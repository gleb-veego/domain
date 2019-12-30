#pragma once

#include <chrono>


const uint16_t LONG_MODEL_SIZE = 1000;
const uint16_t SHORT_MODEL_SIZE = 30;
const std::chrono::milliseconds LEGAL_DIFFERENCE_THRESHOLD(300);
const uint16_t GAMING_MENU_TRESHOLD = 300;
const uint16_t INGAME_RETURN_TRESHOLD = 100;
const uint16_t LEGAL_MISS_THRESHOLD = 5;
const double MEAN_CHANGE_COEEFICENT_THRESHOLD = 1.3;
const double STD_CHANGE_COEEFICENT_THRESHOLD = 5.0;
const double LAG_SENSIVITY = 3.0;
const double AVERAGE_STATIC_MISS_BASE = 40.0;
const double AVERAGE_STATIC_MISS_FIX = 300.0;
const double CHAIN_QUALITY_PERFECT = 10.0;
const double CHAIN_QUALITY_GOOD = 1.0;
const double CHAIN_QUALITY_OK = 0.1;

// BITRATE
const unsigned int BITRATE_WINDOW = 10; // seconds

// WEB DETECTION
//#define PRINT_WEB_DEBUG
const double WEB_INBOUND_PERCENT_THRESHOLD = 0.5;
const unsigned int WEB_CONSECUTIVE_PORTS = 5;
const double WEB_ERROR_SCORE = 60;
const double WEB_WARNING_SCORE = 80;
const std::chrono::seconds MAX_WEB_SESSION_LENGTH(60);
const std::chrono::seconds WEB_TIME_SINCE_LAST_PACKET_THRESHOLD(5);

// Remove old multiconnections
const std::chrono::seconds ERASE_UNCLASSIFIED(10);
const std::chrono::seconds ERASE_CLASSIFIED(40);
