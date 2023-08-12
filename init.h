#pragma once
#include <string>
#include <map>
std::string checkSend(const u_char* pac);
std::string checkTarget(const u_char* pac);
std::string getMyIp(const char* dev);
std::string getSenderMac(std::string sdr,const char* dev,std::string mymac);
std::string getMyMac(const char* dev);
bool sendArpSpoof(std::string sI,std::string tI,const char* dev,std::string sM,std::string mM);
bool isBroadcast(const u_char *packet);
bool isUnicast(const u_char *packet,std::string sender, std::string attackerIp, std::map<std::string,std::string> ip_to_mac);
std::vector<uint8_t> macAddressStringToBytes(const std::string& mac);
std::string bytesToMacString(const u_char* addr);
std::string checksMac(const u_char* pac);
std::string checkdMac(const u_char* pac);
void relayPacket(const u_char* pac,int packetsize, const char* dev,std::string mM,std::string tm);