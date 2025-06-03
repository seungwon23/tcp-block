LDLIBS=-lpcap

all: tcp-block


main.o: mac.h ip.h ethhdr.h tcphdr.h main.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

iphdr.o : ip.h iphdr.h iphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

tcp-block : main.o tcphdr.o ethhdr.o ip.o mac.o iphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
