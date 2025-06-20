#pragma once

#include <netinet/in.h>

#pragma pack(push, 1)

struct Tls final
{
    uint8_t tls_content;
    uint16_t tls_version;
    uint16_t tls_length;
    //5

    uint8_t handshake_type;
    uint8_t handshake_length[3];
    //9
    uint16_t protocol_version;
    //11
    uint8_t random[32];
    //43
    uint8_t session_id_length;
};

#pragma pack(pop)