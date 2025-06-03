#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t sport; // Source port
	uint16_t dport; // Destination port
	uint32_t seqnum;  // Sequence Number
	uint32_t acknum;  // Acknowledgement number
	uint8_t reserved:4; // Reserved 	
	uint8_t th_off:4; // Header length
	uint8_t flags;  // packet flags
	uint16_t win;   // Window Size
	uint16_t check;   // Header Checksum
	uint16_t urgptr; // Urgent pointer
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
