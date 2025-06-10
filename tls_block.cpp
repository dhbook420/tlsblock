#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "mac.h"
#include "ip.h"
#include "tcphdr.h"
#include "parse.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <algorithm>
#include <pcap.h>

using namespace std;

void usage() {
    cout << "syntax : ./tls-block <interface> <server name>\nsample : tls-block wlan0 naver.com\n";
}

struct Packet{
    EthHdr eth;
    IpHdr ip;
    TcpHdr tcp;
};

struct Host_info{
    Mac mac;
    Ip ip;
};

bool getMacIpAddr(string &iface_name, Mac& mac_addr, Ip& ip_addr);



int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    string iface(argv[1]);
    string server(argv[2]);
    Mac mac;
    Ip ip;

    //나의 인터페이스 정보 저장
    Host_info host;
    host.mac = mac;
    host.ip = ip;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (!getMacIpAddr(iface, mac, ip))
        return EXIT_FAILURE;


    pcap_t* pcap = pcap_open_live(iface.c_str(), 65536, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", iface.c_str(), errbuf);
        return EXIT_FAILURE;
    }

    cout << server << endl;

    while (true){
        struct pcap_pkthdr *header;
        const uint8_t* pkt;
        int res = pcap_next_ex(pcap, &header, &pkt);
        if (res == 0){
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            break;
        }

        pkt_parse(pkt, server, pcap, iface, host);

    }
    pcap_close(pcap);
    return 0;

}

bool getMacIpAddr(string &iface_name, Mac& mac_addr, Ip& ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }
    struct ifreq ifr {};
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(failed to get mac addr)");
        close(fd);
        return false;
    }
    Mac mac(reinterpret_cast< uint8_t*>(ifr.ifr_hwaddr.sa_data));
    mac_addr = mac;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl(failed to get ip addr)");
        close(fd);
        return false;
    }
    Ip ip_tmp(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));
    ip_addr = ip_tmp;

    close(fd);
    return true;
}

