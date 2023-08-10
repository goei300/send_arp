#pragma once
#include <string>

unsigned char* getMyMac(const char* dev);
std::string getSenderMac(std::string sdr,const char* dev,unsigned char *mymac);