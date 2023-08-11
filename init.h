#pragma once
#include <string>

std::string checkSend(const u_char* pac);
std::string getMyIp(const char* dev);
std::string getSenderMac(std::string sdr,const char* dev,std::string mymac);
std::string getMyMac(const char* dev);
bool sendArpSpoof(std::string sI,std::string tI,const char* dev,std::string sM,std::string mM);
bool isBroadcast(const u_char *packet);
void relay_thread(const u_char* pac,const char* dev,std::string tm);