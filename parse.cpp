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

void send_packet(const string& iface,
                 pcap_t*     handle,
                 const EthHdr* eth,
                 const IpHdr*  ip,
                 const TcpHdr* tcp,
                 const char*   payload,
                 int           recv_len,
                 bool          is_forward)
{

}

bool pkt_parse(const uint8_t* pktbuf, string &server, pcap_t* pcap, string iface, Host_info& host)
{
    //client hello = ip4,
    //ip hdrlen 20
    //tcp flag psh, ack

    const EthHdr* eth = reinterpret_cast<const EthHdr*>(pktbuf);
    uint16_t eth_type = eth->type();

    if (eth_type != EthHdr::Ip4) {
        return false;
    }

    const uint8_t* ip_start = pktbuf + sizeof(EthHdr);
    const IpHdr* ip = reinterpret_cast<const IpHdr*>(ip_start);

    uint8_t ihl = (ip->version_and_ihl & 0x0F);
    size_t ip_header_len = static_cast<size_t>(ihl) * 4;

    if ((ip_header_len < 20) || (ip->protocol != IpHdr::TCP) ) {
        return false;
    }

    const uint8_t* tcp_start = ip_start + ip_header_len;
    const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(tcp_start);

    uint8_t data_offset = (tcp->th_off) & 0x0F;
    size_t tcp_header_len = static_cast<size_t>(data_offset) * 4;

    if (tcp_header_len < 20) {
        return false;
    }

    const uint8_t* payload = tcp_start + tcp_header_len;
    uint16_t ip_total_len = ntohs(ip->total_length);
    size_t payload_len = 0;

    if (ip_total_len > ip_header_len + tcp_header_len) {
        payload_len = static_cast<size_t>(ip_total_len) - ip_header_len - tcp_header_len;
    } else {
        payload_len = 0;
    }

    if (payload_len == 0) {
        return false;
    }

    const tls* tls_pkt = reinterpret_cast<const tls*>(payload);
    uint8_t session_id_len = (tls_pkt->session_id_length);

    payload = payload + 44 + session_id_len;

    uint16_t cipher_suites_len = ntohs(*(uint16_t*)(payload));

    payload = payload + 2 + cipher_suites_len;

    uint8_t comp_len = *((uint8_t*)(payload));

    payload = payload + 1 + comp_len;

    uint16_t exten_len = ntohs(*(uint16_t*)(payload));

    payload = payload + 2 + exten_len;

    uint16_t extension_type = -1;
    uint16_t extension_len = 0;

    while (extension_type == 0x0000){
      extension_type = ntohs(*(uint16_t*)(payload));
      extension_len = ntohs(*(uint16_t*)(payload + 2));
      payload = payload + 2 + extension_len;
    }

    string tls_server(reinterpret_cast<const char*>(payload), extension_len);



    return false;
}

