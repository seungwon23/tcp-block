#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"

Mac my_mac;

typedef struct _pesudoHeader {
    uint32_t srcAddr;
    uint32_t dstAdrr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcpLen;
} pesudoHeader;

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void get_my_mac(const std::string& dev, Mac* mac) {
    std::ifstream mac_file("/sys/class/net/" + dev + "/address");
    std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());
    if (!str.empty()) {
        *mac = Mac(str.c_str());
    }
}

uint16_t checksum(uint16_t* ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

void send_packet(pcap_t* pcap, const char* packet, int len) {
    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), len)) {
        fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(pcap));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 0;
    }

    std::string dev(argv[1]);
    std::string pattern(argv[2]);

    get_my_mac(dev, &my_mac);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev.c_str(), errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while (1) {
        res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        PEthHdr ethernet_hdr = (PEthHdr)packet;
        if (ethernet_hdr->type() != EthHdr::Ip4) continue;

        PIpHdr ip_hdr = (PIpHdr)(packet + sizeof(EthHdr));
        uint32_t iphdr_len = ip_hdr->ip_len * 4;
        uint32_t ippkt_len = ntohs(ip_hdr->total_len);
        if (ip_hdr->proto != 6) continue;

        PTcpHdr tcp_hdr = (PTcpHdr)((uint8_t*)ip_hdr + iphdr_len);
        uint32_t tcphdr_len = tcp_hdr->th_off * 4;
        uint32_t tcpdata_len = ippkt_len - iphdr_len - tcphdr_len;
        if (tcpdata_len == 0) continue;

        std::string tcp_data((char*)((uint8_t*)tcp_hdr + tcphdr_len), tcpdata_len);
        if (tcp_data.find(pattern) != std::string::npos && tcp_data.compare(0, 3, "GET") == 0) {
            // backward packet (FIN) -> client
            int rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            int value = 1;
            setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

            struct sockaddr_in rawaddr;
            rawaddr.sin_family = AF_INET;
            rawaddr.sin_port = tcp_hdr->sport;
            rawaddr.sin_addr.s_addr = ip_hdr->sip_;

            const char* warn_tcpdata = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
            uint16_t warn_iphdr_len = sizeof(IpHdr);
            uint16_t warn_tcphdr_len = sizeof(TcpHdr);
            uint16_t warn_tcpdata_len = strlen(warn_tcpdata);
            uint16_t warn_total_len = warn_iphdr_len + warn_tcphdr_len + warn_tcpdata_len;

            char* warn_packet = (char*)malloc(warn_total_len);
            memset(warn_packet, 0, warn_total_len);

            PIpHdr warn_iphdr = (PIpHdr)warn_packet;
            PTcpHdr warn_tcphdr = (PTcpHdr)(warn_packet + warn_iphdr_len);
            memcpy(warn_packet + warn_iphdr_len + warn_tcphdr_len, warn_tcpdata, warn_tcpdata_len);

            warn_tcphdr->sport = tcp_hdr->dport;
            warn_tcphdr->dport = tcp_hdr->sport;
            warn_tcphdr->seqnum = tcp_hdr->acknum;
            warn_tcphdr->acknum = htonl(ntohl(tcp_hdr->seqnum) + tcpdata_len);
            warn_tcphdr->th_off = warn_tcphdr_len / 4;
            warn_tcphdr->flags = 0b00010001;
            warn_tcphdr->win = htons(60000);

            warn_iphdr->ip_len = warn_iphdr_len / 4;
            warn_iphdr->ip_v = 4;
            warn_iphdr->total_len = htons(warn_total_len);
            warn_iphdr->ttl = 128;
            warn_iphdr->proto = 6;
            warn_iphdr->sip_ = ip_hdr->dip_;
            warn_iphdr->dip_ = ip_hdr->sip_;

            pesudoHeader psdheader;
            memset(&psdheader, 0, sizeof(pesudoHeader));
            psdheader.srcAddr = ip_hdr->dip_;
            psdheader.dstAdrr = ip_hdr->sip_;
            psdheader.protocol = IPPROTO_TCP;
            psdheader.tcpLen = htons(warn_tcphdr_len + warn_tcpdata_len);

            uint32_t tcp_checksum = checksum((uint16_t*)warn_tcphdr, warn_tcphdr_len + warn_tcpdata_len) + checksum((uint16_t*)&psdheader, sizeof(pesudoHeader));
            warn_tcphdr->check = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
            warn_iphdr->check = checksum((uint16_t*)warn_iphdr, warn_iphdr_len);

            if (sendto(rawsock, warn_packet, warn_total_len, 0, (struct sockaddr*)&rawaddr, sizeof(rawaddr)) < 0) {
                perror("Failed!\n");
                return -1;
            }
            else printf("Blocked!\n");
            free(warn_packet);
            close(rawsock);

            // forward packet (RST) -> server
            uint32_t newpkt_len = sizeof(EthHdr) + iphdr_len + sizeof(TcpHdr);
            char* newpkt = (char*)malloc(newpkt_len);
            memset(newpkt, 0, newpkt_len);
            memcpy(newpkt, packet, newpkt_len);

            ethernet_hdr = (PEthHdr)newpkt;
            ip_hdr = (PIpHdr)(newpkt + sizeof(EthHdr));
            tcp_hdr = (PTcpHdr)((char*)ip_hdr + iphdr_len);

            ethernet_hdr->smac_ = my_mac;
            ip_hdr->total_len = htons(iphdr_len + sizeof(TcpHdr));
            ip_hdr->check = 0;
            tcp_hdr->th_off = sizeof(TcpHdr) / 4;
            tcp_hdr->seqnum = htonl(ntohl(tcp_hdr->seqnum) + tcpdata_len);
            tcp_hdr->flags = 0b00010100;
            tcp_hdr->check = 0;

            memset(&psdheader, 0, sizeof(pesudoHeader));
            psdheader.srcAddr = ip_hdr->sip_;
            psdheader.dstAdrr = ip_hdr->dip_;
            psdheader.protocol = IPPROTO_TCP;
            psdheader.tcpLen = htons(sizeof(TcpHdr));

            tcp_checksum = checksum((uint16_t*)tcp_hdr, sizeof(TcpHdr)) + checksum((uint16_t*)&psdheader, sizeof(pesudoHeader));
            tcp_hdr->check = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
            ip_hdr->check = checksum((uint16_t*)ip_hdr, iphdr_len);

            send_packet(pcap, newpkt, newpkt_len);
            free(newpkt);
        }
    }

    pcap_close(pcap);
    return 0;
}

