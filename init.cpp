#include <pcap.h>
#include "arphdr.h"
#include "ethhdr.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define MAC_SIZE 6

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

unsigned char* getMyMac(const char* dev) {
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return NULL;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return NULL;
    }

    close(sockfd);

    unsigned char* mac_address = (unsigned char*)malloc(MAC_SIZE);
    if (mac_address == NULL) {
        printf("Failed to allocate memory for MAC address\n");
        return NULL;
    }

    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
    return mac_address;
}

std::string getSenderMac(std::string sdr,const char* dev,unsigned char *mymac) {
    
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* sender = sdr.c_str();
    pcap_t* handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return "error";
    }
    EthArpPacket myPacket;
    myPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 1 : broadcast 2 : sender mac
	// myPacket.eth_.smac_ = Mac(); -> config after getMyMac()
	myPacket.eth_.type_ = htons(EthHdr::Arp);

	myPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	myPacket.arp_.pro_ = htons(EthHdr::Ip4);
	myPacket.arp_.hln_ = Mac::SIZE;
	myPacket.arp_.pln_ = Ip::SIZE;
	myPacket.arp_.op_ = htons(ArpHdr::Request);  
	// myPacket.arp_.smac_ = Mac("00:00:00:00:00:00"); -> after getMyMac() 
	// myPacket.arp_.sip_ = htonl(Ip("0.0.0.0"));  -> after getMyIp()
	myPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
	myPacket.arp_.tip_ = htonl(Ip(sender));
    
    memcpy(&myPacket.eth_.smac_,mymac,MAC_SIZE);
    memcpy(&myPacket.arp_.smac_,mymac,MAC_SIZE);

    int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&myPacket), sizeof(EthArpPacket) );
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    while (true) {
        
        struct pcap_pkthdr* header;
        const u_char* responsePacket;
        int res = pcap_next_ex(handle, &header, &responsePacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return "error";
        }
        
        // detection for eth-arp packet(sender'sip)
        EthArpPacket* recvPacket = (EthArpPacket*)responsePacket;

        if (ntohs(recvPacket->eth_.type_) != EthHdr::Arp) {
            continue;
        }
        if(ntohs(recvPacket->arp_.op_) != ArpHdr::Reply) {
            continue;
        }
        if(recvPacket->arp_.sip_ != myPacket.arp_.tip_) {
            continue;
        }          

        std::string sdr_mac=static_cast<std::string>(recvPacket->arp_.smac_);
        return sdr_mac;
    }
}

//TODO : SendArp, Relay