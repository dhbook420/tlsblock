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
    const int eth_len  = sizeof(EthHdr);
    const int ip_len   = sizeof(IpHdr);
    const int tcp_len  = sizeof(TcpHdr);
    const int packet_len = eth_len + ip_len + tcp_len;

    int total_len   = ntohs(pkt->ip.total_length);
    int payload_len = total_len - pkt->ip_header_len - pkt->tcp_header_len;
    uint32_t orig_seq = ntohl(pkt->tcp.th_seq);
    uint32_t orig_ack = ntohl(pkt->tcp.th_ack);

    auto ip_checksum = [](const IpHdr* iph)->uint16_t {
        const uint16_t* ptr = (const uint16_t*)iph;
        uint32_t sum = 0;
        for (int i = 0; i < sizeof(IpHdr)/2; ++i) {
            sum += ntohs(ptr[i]);
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        return htons(~sum & 0xFFFF);
    };

    auto tcp_checksum = [&](const IpHdr& iph, const TcpHdr& th)->uint16_t {
        struct Pseudo {
            uint32_t src, dst;
            uint8_t  zero, proto;
            uint16_t len;
        } psh;
        psh.src   = iph.sip_;
        psh.dst   = iph.dip_;
        psh.zero  = 0;
        psh.proto = IpHdr::TCP;
        psh.len   = htons(tcp_len);
        int buflen = sizeof(psh) + tcp_len;
        uint8_t* buf = (uint8_t*)malloc(buflen);
        memcpy(buf, &psh, sizeof(psh));
        memcpy(buf + sizeof(psh), &th, tcp_len);
        uint32_t sum = 0;
        uint16_t* w = (uint16_t*)buf;
        for (int i = 0; i < buflen/2; ++i) {
            sum += ntohs(w[i]);
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        if (buflen & 1) {
            sum += (buf[buflen-1] << 8) & 0xFF00;
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        free(buf);
        return htons(~sum & 0xFFFF);
    };

    {
        EthHdr fe = pkt->eth;
        fe.smac_ = host.mac;

        IpHdr fi = pkt->ip;
        fi.total_length = htons(ip_len + tcp_len);
        fi.checksum = 0;
        fi.checksum = ip_checksum(&fi);

        TcpHdr th = pkt->tcp;
        th.th_flags = TcpHdr::RST | TcpHdr::ACK;
        th.th_off   = tcp_len / 4;
        th.th_seq   = htonl(orig_seq + payload_len); // next seq
        th.th_ack   = pkt->tcp.th_ack;               // 그대로 유지
        th.th_sum   = 0;
        th.th_sum   = tcp_checksum(fi, th);

        uint8_t* frame = (uint8_t*)malloc(packet_len);
        memcpy(frame,                   &fe, eth_len);
        memcpy(frame + eth_len,        &fi, ip_len);
        memcpy(frame + eth_len + ip_len, &th, tcp_len);

        if (pcap_sendpacket(handle, frame, packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        }

        free(frame);
    }

    {
        IpHdr fi = pkt->ip;
        std::swap(fi.sip_, fi.dip_);
        fi.total_length = htons(ip_len + tcp_len);
        fi.checksum = 0;
        fi.checksum = ip_checksum(&fi);

        TcpHdr th = pkt->tcp;
        std::swap(th.th_sport, th.th_dport);
        th.th_flags = TcpHdr::RST | TcpHdr::ACK;
        th.th_off   = tcp_len / 4;
        th.th_seq   = htonl(orig_ack);                     // 서버 seq = 클라이언트가 준 ack
        th.th_ack   = htonl(orig_seq + payload_len);       // 서버 ack = 클라 seq + len
        th.th_sum   = 0;
        th.th_sum   = tcp_checksum(fi, th);

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            perror("socket() failed");
            return;
        }

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        struct sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = th.th_dport;
        dst.sin_addr.s_addr = fi.dip_;

        uint8_t* ip_tcp = (uint8_t*)malloc(ip_len + tcp_len);
        memcpy(ip_tcp, &fi, ip_len);
        memcpy(ip_tcp + ip_len, &th, tcp_len);

        if (sendto(sock, ip_tcp, ip_len + tcp_len, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
            perror("sendto() failed");
        }

        close(sock);
        free(ip_tcp);
    }
}

//2개로 나뉘어 보내진 경우 첫 segment의 정보들
static uint8_t segment_payload[65536] = {0,};
static size_t segment_len = 0;
static Packet segment_hdrs;
static uint16_t expected_tls_total = 0;

bool pkt_parse(const uint8_t* pktbuf, string &target_server, pcap_t* pcap, string iface, Host_info& host)
{
    //client hello = ip4
    //ip hdrlen 20
    //tcp flag psh, ack

    const EthHdr* eth = reinterpret_cast<const EthHdr*>(pktbuf);
    uint16_t eth_type = eth->type();

    if (eth_type != EthHdr::Ip4) {
        segment_len = 0;
        expected_tls_total = 0;
        return false;
    }

    const uint8_t* ip_start = pktbuf + sizeof(EthHdr);
    const IpHdr* ip = reinterpret_cast<const IpHdr*>(ip_start);

    uint8_t ihl = (ip->version_and_ihl & 0x0F);
    size_t ip_header_len = static_cast<size_t>(ihl) * 4;

    if ((ip_header_len < 20) || (ip->protocol != IpHdr::TCP) ) {
        segment_len = 0;
        expected_tls_total = 0;
        return false;
    }

    const uint8_t* tcp_start = ip_start + ip_header_len;
    const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(tcp_start);

    uint8_t data_offset = (tcp->th_off) & 0x0F;
    size_t tcp_header_len = static_cast<size_t>(data_offset) * 4;

    if (tcp_header_len < 20) {
        segment_len = 0;
        expected_tls_total = 0;
        return false;
    }

    Packet pkt_hdrs;
    pkt_hdrs.eth = *eth;
    pkt_hdrs.ip = *ip;
    pkt_hdrs.tcp = *tcp;
    pkt_hdrs.ip_header_len  = ihl * 4;
    pkt_hdrs.tcp_header_len = data_offset * 4;

    const uint8_t* payload = tcp_start + tcp_header_len;
    uint16_t ip_total_len = ntohs(ip->total_length);
    size_t payload_len = 0;

    if (ip_total_len > ip_header_len + tcp_header_len) {
        payload_len = static_cast<size_t>(ip_total_len) - ip_header_len - tcp_header_len;
    } else {
        payload_len = 0;
    }

    if (payload_len == 0) {
        segment_len = 0;
        expected_tls_total = 0;
        return false;
    }

    if (!segment_len) {
        const Tls* tls_pkt = reinterpret_cast<const Tls*>(payload);

        uint8_t content_type = (tls_pkt->tls_content);
        if (content_type != 22) { //0x16, handshake
            segment_len = 0;
            expected_tls_total = 0;
            return false;
        }
        uint8_t hs_type = ((tls_pkt->handshake_type));
        if (hs_type != 1) { //0x1, client hello
            segment_len = 0;
            expected_tls_total = 0;
            return false;
        }

        uint16_t tls_len = ntohs((tls_pkt->tls_length));
        expected_tls_total = tls_len + 5;

        if (expected_tls_total > payload_len) {
            memcpy(segment_payload, payload, payload_len);
            segment_len = payload_len;
            segment_hdrs = pkt_hdrs;
            return false;
        }
        //false return 안되면 segmet
        segment_len = 0;
        expected_tls_total = 0;
    }
    else {

        if (segment_len + payload_len >= sizeof(segment_payload)) {
            cerr << "segment overflow" << endl;
            segment_len = 0;
            expected_tls_total = 0;
            return false;
        }

        memcpy(segment_payload + segment_len, payload, payload_len);
        segment_len += payload_len;

        if (segment_len < expected_tls_total) {
            return false;
        }

        // 이제 완성 → segment_payload로 파싱
        payload = segment_payload;
        payload_len = segment_len;
        pkt_hdrs = segment_hdrs;

        // 버퍼 초기화 (한 번만 처리)
        segment_len = 0;
        expected_tls_total = 0;

    }

    const Tls* tls_pkt = reinterpret_cast<const Tls*>(payload);



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
            cout << "found in " << tls_server <<endl;
            send_packet(pcap, &pkt_hdrs, host);
            segment_len = 0;
            break;
        }

        payload2 += name_len;
    }
    return false;
}

