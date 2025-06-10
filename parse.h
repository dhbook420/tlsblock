#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tlshdr.h"
#include "mac.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <algorithm>
#include <pcap.h>

using namespace std;
struct Packet{
    EthHdr eth;
    IpHdr ip;
    TcpHdr tcp;
};

struct Host_info{
    Mac mac;
    Ip ip;
};

bool pkt_parse(const uint8_t* pktbuf, string &target_server, pcap_t* pcap, string iface, Host_info& host);
void send_packet(pcap_t* handle, Packet* pkt, Host_info& host);
