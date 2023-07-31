#pragma once

#include <arpa/inet.h>
#include "Ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t ihl_:4, version_:4;
	uint8_t tos_;
	uint16_t tot_len_;
	uint16_t id_;
	uint16_t frag_off_;
	uint8_t ttl_;
	uint8_t protocol_;
	uint16_t check_;
	Ip saddr_;
	Ip daddr_;

	uint8_t ihl() { return ihl_; }
	uint8_t version() { return version_; }
	uint8_t tos() { return tos_; }
	uint16_t tot_len() { return ntohs(tot_len_); }
	uint16_t id() { return ntohs(id_); }
	uint16_t frag_off() { return ntohs(frag_off_); }
	uint8_t ttl() { return ttl_; }
	uint8_t protocol() { return protocol_; }
	uint16_t check() { return ntohs(check_); }
	Ip saddr() { return saddr_; }
	Ip daddr() { return daddr_; }

	// Protocol(protocol_)
	enum: uint8_t {
		ICMP = 1,
		TCP = 6,
		UDP = 17
	};
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)