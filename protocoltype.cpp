#include <libnet.h>
#include "protocoltype.h"
int checkType(const u_char* pac){
    struct libnet_ethernet_hdr *eth_hdr=(struct libnet_ethernet_hdr *)pac;

    if(ntohs(eth_hdr->ether_type)== ETHERTYPE_ARP){
        return 1;
    }
    else if(ntohs(eth_hdr->ether_type)== ETHERTYPE_IP){
        return 2;
    }
    else{
        return 3;
    }
}