#pragma once

#include <esp_wifi.h>
#include "SharedTypes.h"

bool shouldKeepProbeReport(
    RecentDeviceRecord* recentDevices,
    int recentDeviceCount,
    uint32_t deviceHash,
    int8_t rssi
);

bool isProbeRequestFrame(const wifi_promiscuous_pkt_t* packet);
const uint8_t* sourceMacAddressFromPacket(const wifi_promiscuous_pkt_t* packet);
RssiReport buildRssiReportFromProbe(const wifi_promiscuous_pkt_t* packet);
