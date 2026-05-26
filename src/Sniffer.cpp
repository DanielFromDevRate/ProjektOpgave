#ifdef ROLE_SNIFFER

#include "Sniffer.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

#include "Shared.h"

namespace {

constexpr uint8_t RECENT_DEVICE_COUNT = 24;
constexpr uint8_t SNIFF_DEBUG_QUEUE_SIZE = 16;
constexpr uint8_t SNIFF_DEBUG_DEVICE_COUNT = 32;
constexpr uint32_t ACTIVE_DEBUG_DEVICE_MS = 30000;

struct RecentDevice {
    uint32_t hash;
    uint32_t last_ms;
};

struct SniffDebugReport {
    RssiReport report;
    uint8_t mac[6];
};

struct SniffDebugDevice {
    uint32_t hash;
    uint8_t mac[6];
    uint32_t count;
    uint32_t last_ms;
    int8_t last_rssi;
    bool allowed;
    bool randomized_mac;
    const char* mac_type;
};

esp_now_peer_info_t peer;
uint32_t probeCount = 0;
uint32_t reportCount = 0;

RecentDevice recentDevices[RECENT_DEVICE_COUNT];
SniffDebugDevice sniffDebugDevices[SNIFF_DEBUG_DEVICE_COUNT];
SniffDebugReport sniffDebugQueue[SNIFF_DEBUG_QUEUE_SIZE];

volatile uint8_t sniffDebugHead = 0;
volatile uint8_t sniffDebugTail = 0;
portMUX_TYPE sniffDebugMux = portMUX_INITIALIZER_UNLOCKED;

bool isRandomizedMac(const uint8_t* mac) {
    return (mac[0] & 0x02) != 0;
}

bool isMulticastMac(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

const char* macType(const uint8_t* mac) {
    if (isMulticastMac(mac)) {
        return "multicast";
    }

    if (isRandomizedMac(mac)) {
        return "randomized";
    }

    return "vendor";
}

bool shouldReportDevice(uint32_t hash, int8_t rssi) {
    if (rssi < MIN_REPORT_RSSI) {
        return false;
    }

    uint32_t now = millis();
    int empty = -1;
    int oldest = 0;

    for (int i = 0; i < RECENT_DEVICE_COUNT; i++) {
        if (recentDevices[i].hash == hash) {
            if (now - recentDevices[i].last_ms < SAME_DEVICE_REPORT_INTERVAL_MS) {
                return false;
            }

            recentDevices[i].last_ms = now;
            return true;
        }

        if (recentDevices[i].hash == 0 && empty < 0) {
            empty = i;
        }

        if (recentDevices[i].last_ms < recentDevices[oldest].last_ms) {
            oldest = i;
        }
    }

    int slot = (empty >= 0) ? empty : oldest;
    recentDevices[slot].hash = hash;
    recentDevices[slot].last_ms = now;
    return true;
}

void queueSniffDebug(const RssiReport& report, const uint8_t* mac) {
    portENTER_CRITICAL_ISR(&sniffDebugMux);
    uint8_t next = (sniffDebugHead + 1) % SNIFF_DEBUG_QUEUE_SIZE;

    if (next != sniffDebugTail) {
        sniffDebugQueue[sniffDebugHead].report = report;
        memcpy(sniffDebugQueue[sniffDebugHead].mac, mac, 6);
        sniffDebugHead = next;
    }

    portEXIT_CRITICAL_ISR(&sniffDebugMux);
}

bool popSniffDebug(SniffDebugReport& report) {
    portENTER_CRITICAL(&sniffDebugMux);

    if (sniffDebugTail == sniffDebugHead) {
        portEXIT_CRITICAL(&sniffDebugMux);
        return false;
    }

    report = sniffDebugQueue[sniffDebugTail];
    sniffDebugTail = (sniffDebugTail + 1) % SNIFF_DEBUG_QUEUE_SIZE;
    portEXIT_CRITICAL(&sniffDebugMux);
    return true;
}

SniffDebugDevice* getSniffDebugDevice(uint32_t hash) {
    int empty = -1;
    int oldest = 0;

    for (int i = 0; i < SNIFF_DEBUG_DEVICE_COUNT; i++) {
        if (sniffDebugDevices[i].hash == hash) {
            return &sniffDebugDevices[i];
        }

        if (sniffDebugDevices[i].hash == 0 && empty < 0) {
            empty = i;
        }

        if (sniffDebugDevices[i].last_ms < sniffDebugDevices[oldest].last_ms) {
            oldest = i;
        }
    }

    int slot = (empty >= 0) ? empty : oldest;
    memset(&sniffDebugDevices[slot], 0, sizeof(sniffDebugDevices[slot]));
    sniffDebugDevices[slot].hash = hash;
    return &sniffDebugDevices[slot];
}

void rememberSniffDebug(const SniffDebugReport& report) {
    SniffDebugDevice* device = getSniffDebugDevice(report.report.mac_hash);

    memcpy(device->mac, report.mac, 6);
    device->count++;
    device->last_ms = millis();
    device->last_rssi = report.report.rssi;
    device->allowed = isAllowedDevice(report.report.mac_hash);
    device->randomized_mac = isRandomizedMac(device->mac);
    device->mac_type = macType(device->mac);
}

void printSniffDebugDevice(const SniffDebugDevice& device) {
    Serial.printf(
        "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"hash\":\"%08lX\",\"count\":%lu,\"last_seen_ms\":%lu,\"last_rssi\":%d,\"allowed\":%s,\"randomized_mac\":%s,\"mac_type\":\"%s\"}",
        device.mac[0],
        device.mac[1],
        device.mac[2],
        device.mac[3],
        device.mac[4],
        device.mac[5],
        (unsigned long)device.hash,
        (unsigned long)device.count,
        (unsigned long)device.last_ms,
        device.last_rssi,
        device.allowed ? "true" : "false",
        device.randomized_mac ? "true" : "false",
        device.mac_type);
}

void printSniffDebugReport() {
    uint32_t now = millis();
    bool first = true;

    Serial.println("{\"type\":\"sniffer_debug\",\"devices\":[");

    for (int i = 0; i < SNIFF_DEBUG_DEVICE_COUNT; i++) {
        SniffDebugDevice& device = sniffDebugDevices[i];

        if (device.hash == 0 || now - device.last_ms > ACTIVE_DEBUG_DEVICE_MS) {
            continue;
        }

        if (!first) {
            Serial.println(",");
        }

        first = false;
        printSniffDebugDevice(device);
    }

    Serial.println("]}");
    Serial.printf(
        "Probe requests seen: %lu, reported after filters: %lu\n",
        (unsigned long)probeCount,
        (unsigned long)reportCount);
}

bool isProbeRequest(const wifi_promiscuous_pkt_t* packet) {
    if (packet->rx_ctrl.sig_len < 24) {
        return false;
    }

    return packet->payload[0] == 0x40;
}

void sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) {
        return;
    }

    auto* packet = static_cast<wifi_promiscuous_pkt_t*>(buf);

    if (!isProbeRequest(packet)) {
        return;
    }

    probeCount++;

    // Source MAC starts at byte 10 in the 802.11 management frame header.
    const uint8_t* mac = packet->payload + 10;
    RssiReport report = {
        NODE_ID,
        hashMac(mac),
        static_cast<int8_t>(packet->rx_ctrl.rssi),
    };

    if (!shouldReportDevice(report.mac_hash, report.rssi)) {
        return;
    }

    queueSniffDebug(report, mac);

    if (!isAllowedDevice(report.mac_hash)) {
        return;
    }

    reportCount++;
    esp_now_send(COORD_MAC, reinterpret_cast<uint8_t*>(&report), sizeof(report));
}

void onEspNowSent(const uint8_t*, esp_now_send_status_t status) {
    Serial.printf("ESP-NOW send %s\n", status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAILED");
}

void setupEspNow() {
    esp_now_init();
    esp_now_register_send_cb(onEspNowSent);

    memcpy(peer.peer_addr, COORD_MAC, 6);
    peer.channel = SNIFFER_CHANNEL;
    peer.encrypt = false;
    esp_now_add_peer(&peer);
}

}  // namespace

void setupSniffer() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("Sniffer node %d starting on channel %d\n", NODE_ID, SNIFFER_CHANNEL);

    WiFi.mode(WIFI_STA);
    esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);
    setupEspNow();

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffCb);
    Serial.println("Listening for probe requests...");
}

void loopSniffer() {
    SniffDebugReport report;

    while (popSniffDebug(report)) {
        rememberSniffDebug(report);
    }

    static uint32_t last = 0;
    if (millis() - last > REPORT_INTERVAL_MS) {
        last = millis();
        printSniffDebugReport();
    }
}

#endif
