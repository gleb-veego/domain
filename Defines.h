#pragma once

#include "DetectionConfiguration.h"

#include <vector>
#include <string>

#define SIZE_NORMALIZTION (1500UL)
#define TIME_NORMALIZATON (1000000000UL)
#define TCP_LEN_PACKET_SIZE_FIX (52UL)
#define UDP_LEN_PACKET_SIZE_FIX (28UL)
enum class ProtocolType {
    UDP = 0,
    TCP = 1,
};

enum class MultiConnectionType {
    small = 1,
    unclassified,
    gaming,
    streaming_tcp,
    streaming_udp,
    streaming_video,
    browsing,
    live_streaming_udp,
    upload_tcp,
    upload_udp,
    untrusted,
    undefined,
};

enum class MultiConnectionSubtype {
    undefined = 0,
    gaming_menu,
    gaming_ingame,
    gaming_difficult,
    lag
};

enum class ServiceQuality {
    undefined = 0,
    perfect,
    good,
    ok,
    bad
};

extern std::vector <std::string> MultiConnectionTypeString;
extern std::vector <std::string> MultiConnectionTypeSybtypeString;
extern std::vector <std::string> ServiceQualityString;
