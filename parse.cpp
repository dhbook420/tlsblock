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
#include "tlshdr.h"
#include "parse.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <algorithm>
#include <pcap.h>

using namespace std;

void send_packet(pcap_t* handle, Packet* pkt, Host_info& host)
{
    // 포트폴리오 미사용 변수 경고 방지
    (void)host.ip;

    const int eth_len = sizeof(EthHdr);
    const int ip_len  = sizeof(IpHdr);
    const int tcp_len = sizeof(TcpHdr);
    const int packet_len = eth_len + ip_len + tcp_len;

    // IP 체크섬 계산용 람다
    auto ip_checksum = [](const IpHdr* iph)->uint16_t {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(iph);
        uint32_t sum = 0;
        for (int i = 0; i < sizeof(IpHdr)/2; ++i) {
            sum += ntohs(ptr[i]);
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        return htons(static_cast<uint16_t>(~sum & 0xFFFF));
    };

    // TCP 체크섬 계산용 람다
    auto tcp_checksum = [](const uint8_t* buf, int len)->uint16_t {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buf);
        uint32_t sum = 0;
        for (int i = 0; i < len/2; ++i) {
            sum += ntohs(ptr[i]);
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        if (len & 1) {
            sum += (buf[len-1] << 8) & 0xFF00;
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        return htons(static_cast<uint16_t>(~sum & 0xFFFF));
    };

    // 의사 헤더 (pseudo header) 구조체
    struct PseudoHdr {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len;
    };

    // --- 1) Forward: client -> server (RST|ACK) ---
    EthHdr  fe = pkt->eth;
    fe.smac_ = host.mac;
    // fe.dmac_ == pkt->eth.dmac_ (서버 MAC)

    IpHdr   fi = pkt->ip;
    fi.total_length = htons(static_cast<uint16_t>(ip_len + tcp_len));
    fi.checksum = 0;
    fi.checksum = ip_checksum(&fi);

    TcpHdr  ft = pkt->tcp;
    ft.th_flags = static_cast<uint8_t>(TcpHdr::RST) | static_cast<uint8_t>(TcpHdr::ACK);
    ft.th_off   = tcp_len / 4;
    ft.th_sum   = 0;

    // forward TCP 체크섬 계산
    PseudoHdr psh {
        fi.sip_, fi.dip_, 0, IpHdr::TCP, htons(static_cast<uint16_t>(tcp_len))
    };
    int buf_len = sizeof(psh) + tcp_len;
    uint8_t* buf = static_cast<uint8_t*>(malloc(buf_len));
    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), &ft, tcp_len);
    ft.th_sum = tcp_checksum(buf, buf_len);
    free(buf);

    {
        uint8_t* frame = static_cast<uint8_t*>(malloc(packet_len));
        memcpy(frame, &fe, eth_len);
        memcpy(frame + eth_len, &fi, ip_len);
        memcpy(frame + eth_len + ip_len, &ft, tcp_len);
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(frame), packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket (forward) failed: %s\n", pcap_geterr(handle));
        }
        free(frame);
    }

    // --- 2) Backward: server -> client (RST|ACK) ---
    EthHdr  be = pkt->eth;
    be.dmac_ = pkt->eth.smac_;  // 원래 client MAC
    be.smac_ = host.mac;        // 우리 MAC

    IpHdr   bi = pkt->ip;
    bi.sip_ = pkt->ip.dip_;     // 서버 IP
    bi.dip_ = pkt->ip.sip_;     // 클라이언트 IP
    bi.ttl  = 128;
    bi.total_length = htons(static_cast<uint16_t>(ip_len + tcp_len));
    bi.checksum = 0;
    bi.checksum = ip_checksum(&bi);

    TcpHdr  bt = pkt->tcp;
    bt.th_sport = pkt->tcp.th_dport;
    bt.th_dport = pkt->tcp.th_sport;
    bt.th_flags = static_cast<uint8_t>(TcpHdr::RST) | static_cast<uint8_t>(TcpHdr::ACK);
    bt.th_off   = tcp_len / 4;
    bt.th_sum   = 0;

    // backward TCP 체크섬 계산
    psh = PseudoHdr{ bi.sip_, bi.dip_, 0, IpHdr::TCP, htons(static_cast<uint16_t>(tcp_len)) };
    buf_len = sizeof(psh) + tcp_len;
    buf = static_cast<uint8_t*>(malloc(buf_len));
    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), &bt, tcp_len);
    bt.th_sum = tcp_checksum(buf, buf_len);
    free(buf);

    {
        uint8_t* frame = static_cast<uint8_t*>(malloc(packet_len));
        memcpy(frame, &be, eth_len);
        memcpy(frame + eth_len, &bi, ip_len);
        memcpy(frame + eth_len + ip_len, &bt, tcp_len);
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(frame), packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket (backward) failed: %s\n", pcap_geterr(handle));
        }
        free(frame);
    }
}

bool pkt_parse(const uint8_t* pktbuf, string &target_server, pcap_t* pcap, string iface, Host_info& host)
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

    Packet pkt_hdrs;
    pkt_hdrs.eth = *eth;
    pkt_hdrs.ip = *ip;
    pkt_hdrs.tcp = *tcp;

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

    const Tls* tls_pkt = reinterpret_cast<const Tls*>(payload);


    uint8_t content_type = (tls_pkt->tls_content);
    if (content_type != 22) { //0x16, handshake
        return false;
    }
    uint8_t hs_type = ((tls_pkt->handshake_type));
    if (hs_type != 1) { //0x1, client hello
        return false;
    }

    cout << "found client hello" <<endl;
    uint8_t session_id_len = (tls_pkt->session_id_length);

    const uint8_t* payload2 = reinterpret_cast<const uint8_t*>(payload) + 44 + session_id_len;


    uint16_t cipher_suites_len = ntohs(*(uint16_t*)(payload2));

    payload2 = payload2 + 2 + cipher_suites_len;

    uint8_t comp_len = *((uint8_t*)(payload2));

    payload2 = payload2 + 1 + comp_len;

    uint16_t exten_len = ntohs(*(uint16_t*)(payload2));
    cout << exten_len <<endl;

    payload2 = payload2 + 2 ;

    uint16_t extension_type = 0xffff;
    uint16_t extension_len = 0;

    while (extension_type != 0x0000){
      extension_type = ntohs(*(uint16_t*)(payload2));
      extension_len = ntohs(*(uint16_t*)(payload2 + 2));
      if (extension_type == 0x0000)
        break;
      payload2 = payload2 + 4 + extension_len;
    }



    payload2 += 4;
    uint16_t list_len = ntohs(*(uint16_t*)(payload2));

    payload2 += 2;
    const uint8_t* list_end = payload2 + list_len;

    while (payload2 + 3 <= list_end) {
        uint8_t name_type = *payload2;

        payload2 += 1;

        uint16_t name_len = ntohs(*(uint16_t*)(payload2));
        payload2 += 2;

        string tls_server(reinterpret_cast<const char*>(payload2), name_len);
        if (tls_server.find(target_server) != string::npos) {
            send_packet(pcap, &pkt_hdrs, host);
            break;
        }

        payload2 += name_len;
    }
    return false;
}

