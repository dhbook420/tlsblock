#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "mac.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <algorithm>
#include <pcap.h>

bool pkt_parse(const uint8_t* pkt, string &host, pcap_t* pcap, string iface, host_info& host);
void send_packet(const string& iface,pcap_t* handle, const EthHdr* eth,const IpHdr* ip,
                 const TcpHdr* tcp,const char* payload,int recv_len,bool  is_forward);
