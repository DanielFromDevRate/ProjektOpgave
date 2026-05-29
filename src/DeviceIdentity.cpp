#include "DeviceIdentity.h"

#include <string.h>
#include "Config.h"

// The raw MAC address is personal data. This FNV-1a hash gives us a stable
// pseudonymous id without transmitting the original MAC between boards or to MQTT.
uint32_t hashMacAddress(const uint8_t* macAddress) {
    uint32_t hash = 2166136261u;
    for (int i = 0; i < 6; i++) {
        hash ^= macAddress[i];
        hash *= 16777619u;
    }
    return hash;
}

bool isRandomizedMacAddress(const uint8_t* macAddress) {
    return (macAddress[0] & 0x02) != 0;
}

static bool isMulticastMacAddress(const uint8_t* macAddress) {
    return (macAddress[0] & 0x01) != 0;
}

uint8_t macAddressFlags(const uint8_t* macAddress) {
    uint8_t flags = 0;
    if (isRandomizedMacAddress(macAddress)) {
        flags |= MAC_FLAG_RANDOMIZED;
    }
    if (isMulticastMacAddress(macAddress)) {
        flags |= MAC_FLAG_MULTICAST;
    }
    return flags;
}

const char* macTypeFromFlags(uint8_t flags) {
    if (flags & MAC_FLAG_MULTICAST) {
        return "multicast";
    }
    if (flags & MAC_FLAG_RANDOMIZED) {
        return "randomized";
    }
    return "vendor";
}

bool isAllowedDevice(uint32_t deviceHash) {
    if (ALLOW_ALL_DEVICES) {
        return true;
    }

    for (size_t i = 0; i < NUMBER_OF_ALLOWED_DEVICE_HASHES; i++) {
        if (ALLOWED_DEVICE_HASHES[i] == 0) {
            continue;
        }
        if (ALLOWED_DEVICE_HASHES[i] == deviceHash) {
            return true;
        }
    }
    return false;
}

const char* deviceLabel(uint32_t deviceHash) {
    for (size_t i = 0; i < NUMBER_OF_KNOWN_DEVICES; i++) {
        if (KNOWN_DEVICES[i].hash == deviceHash) {
            return KNOWN_DEVICES[i].label;
        }
    }
    return "unknown";
}

bool isKnownDevice(uint32_t deviceHash) {
    return strcmp(deviceLabel(deviceHash), "unknown") != 0;
}
