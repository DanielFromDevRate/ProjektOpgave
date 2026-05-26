#ifndef SHARED_H
#define SHARED_H

#include <Arduino.h>
#include "AppConfig.h"

struct RssiReport {
    uint8_t NodeId;
    uint32_t MacHash;
    int8_t Rssi;
};

uint32_t HashMac(const uint8_t* mac);
bool IsAllowedDevice(uint32_t hash);

#endif
