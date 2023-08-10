LDLIBS=-lpcap

all: send-arp-test


main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

utils.o: utils.h utils.cpp

protocoltype.o: protocoltype.h protocoltype.cpp

init.o: ethhdr.h arphdr.h init.h init.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o protocoltype.o utils.o init.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
