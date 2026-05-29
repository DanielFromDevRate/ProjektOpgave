#include "ProbeParsing.h"

#include "DeviceIdentity.h"

// Keeps repeated probe requests from the same device from flooding ESP-NOW,
// Serial, and MQTT. Unknown devices use an empty slot or replace the oldest slot.
bool shouldKeepProbeReport(
    RecentDeviceRecord* recentDevices,
    int recentDeviceCount,
    uint32_t deviceHash,
    int8_t rssi
) {
    if (rssi < MIN_REPORT_RSSI) {
        return false;
    }

    const uint32_t now = millis();
    int emptySlot = -1;
    int oldestSlot = 0;

    for (int i = 0; i < recentDeviceCount; i++) {
        if (recentDevices[i].hash == deviceHash) {
            if (now - recentDevices[i].lastSeenMs < SAME_DEVICE_REPORT_INTERVAL_MS) {
                return false;
            }
            recentDevices[i].lastSeenMs = now;
            return true;
        }

        if (recentDevices[i].hash == 0 && emptySlot < 0) {
            emptySlot = i;
        }
        if (recentDevices[i].lastSeenMs < recentDevices[oldestSlot].lastSeenMs) {
            oldestSlot = i;
        }
    }

    const int slot = (emptySlot >= 0) ? emptySlot : oldestSlot;
    recentDevices[slot].hash = deviceHash;
    recentDevices[slot].lastSeenMs = now;
    return true;
}

// WiFi management frame byte 0 contains type/subtype. 0x40 is a probe request.
bool isProbeRequestFrame(const wifi_promiscuous_pkt_t* packet) {
    return packet->rx_ctrl.sig_len >= 24 && packet->payload[0] == 0x40;
}

// In 802.11 management frames the source MAC address starts at byte offset 10.
const uint8_t* sourceMacAddressFromPacket(const wifi_promiscuous_pkt_t* packet) {
    return packet->payload + 10;
}

RssiReport buildRssiReportFromProbe(const wifi_promiscuous_pkt_t* packet) {
    const uint8_t* macAddress = sourceMacAddressFromPacket(packet);
    RssiReport report = {
        NODE_ID,
        hashMacAddress(macAddress),
        static_cast<int8_t>(packet->rx_ctrl.rssi),
        macAddressFlags(macAddress),
    };
    return report;
}
