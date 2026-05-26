#include "Shared.h"

uint32_t hashMac(const uint8_t* mac) {
    uint32_t hash = 2166136261u;

    for (int i = 0; i < 6; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }

    return hash;
}

bool isAllowedDevice(uint32_t hash) {
    if (ALLOW_ALL_DEVICES) {
        return true;
    }

    for (size_t i = 0; i < NUM_ALLOWED_DEVICES; i++) {
        if (ALLOWED_DEVICE_HASHES[i] == 0) {
            continue;
        }

        if (ALLOWED_DEVICE_HASHES[i] == hash) {
            return true;
        }
    }

    return false;
}
