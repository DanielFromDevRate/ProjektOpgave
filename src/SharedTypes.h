#pragma once

#include <Arduino.h>
#include "Config.h"

struct RssiReport {
    uint8_t node_id;
    uint32_t mac_hash;
    int8_t rssi;
    uint8_t mac_flags;
};

struct RecentDeviceRecord {
    uint32_t hash;
    uint32_t lastSeenMs;
};

struct TrackedDevice {
    uint32_t hash;
    int8_t rssi[NUMBER_OF_NODES];
    uint8_t macFlags[NUMBER_OF_NODES];
    bool seenByNode[NUMBER_OF_NODES];
    uint32_t nodeReceivedMs[NUMBER_OF_NODES];
    uint32_t lastSeenMs;
    uint32_t reportCount;
};

struct PositionResult {
    float x;
    float y;
    float distanceFromNode[NUMBER_OF_NODES];
    float fitError;
};
