#pragma once

#include <Arduino.h>

#include "AppConfig.h"

struct RssiReport {
    uint8_t  node_id;
    uint32_t mac_hash;
    int8_t   rssi;
};

uint32_t hashMac(const uint8_t* mac);
bool isAllowedDevice(uint32_t hash);
