#include "SnifferRole.h"

#ifdef ROLE_SNIFFER

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

#include "Config.h"
#include "DeviceIdentity.h"
#include "ProbeParsing.h"
#include "SharedTypes.h"

// A sniffer board does not connect to WiFi. It listens for probe requests on the
// configured channel and sends compact RSSI reports to the coordinator by ESP-NOW.

static esp_now_peer_info_t coordinatorPeer;

static uint32_t probeRequestCount = 0;
static uint32_t sentReportCount = 0;

static const uint8_t RECENT_DEVICE_COUNT = 24;
static RecentDeviceRecord recentDevices[RECENT_DEVICE_COUNT];

static const uint8_t SNIFF_DEBUG_QUEUE_SIZE = 16;

struct SniffDebugReport {
    RssiReport report;
    uint8_t macAddress[6];
};

static SniffDebugReport sniffDebugQueue[SNIFF_DEBUG_QUEUE_SIZE];
static volatile uint8_t sniffDebugHead = 0;
static volatile uint8_t sniffDebugTail = 0;
static portMUX_TYPE sniffDebugMux = portMUX_INITIALIZER_UNLOCKED;

// The WiFi callback runs in a low-level context. It only queues data; Serial
// printing and table updates happen later in loopSnifferRole().
static void queueSniffDebugReport(const RssiReport& report, const uint8_t* macAddress) {
    portENTER_CRITICAL_ISR(&sniffDebugMux);
    const uint8_t nextHead = (sniffDebugHead + 1) % SNIFF_DEBUG_QUEUE_SIZE;
    if (nextHead != sniffDebugTail) {
        sniffDebugQueue[sniffDebugHead].report = report;
        memcpy(sniffDebugQueue[sniffDebugHead].macAddress, macAddress, 6);
        sniffDebugHead = nextHead;
    }
    portEXIT_CRITICAL_ISR(&sniffDebugMux);
}

static bool popSniffDebugReport(SniffDebugReport& report) {
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

static const uint8_t SNIFF_DEBUG_DEVICE_COUNT = 32;

struct SniffDebugDevice {
    uint32_t hash;
    uint8_t macAddress[6];
    uint32_t count;
    uint32_t lastSeenMs;
    int8_t lastRssi;
    bool allowed;
    bool randomizedMac;
    const char* macType;
};

static SniffDebugDevice sniffDebugDevices[SNIFF_DEBUG_DEVICE_COUNT];

static SniffDebugDevice* findOrCreateSniffDebugDevice(uint32_t deviceHash) {
    int emptySlot = -1;
    int oldestSlot = 0;

    for (int i = 0; i < SNIFF_DEBUG_DEVICE_COUNT; i++) {
        if (sniffDebugDevices[i].hash == deviceHash) {
            return &sniffDebugDevices[i];
        }
        if (sniffDebugDevices[i].hash == 0 && emptySlot < 0) {
            emptySlot = i;
        }
        if (sniffDebugDevices[i].lastSeenMs < sniffDebugDevices[oldestSlot].lastSeenMs) {
            oldestSlot = i;
        }
    }

    const int slot = (emptySlot >= 0) ? emptySlot : oldestSlot;
    memset(&sniffDebugDevices[slot], 0, sizeof(sniffDebugDevices[slot]));
    sniffDebugDevices[slot].hash = deviceHash;
    return &sniffDebugDevices[slot];
}

static void rememberSniffDebugReport(const SniffDebugReport& report) {
    SniffDebugDevice* device = findOrCreateSniffDebugDevice(report.report.mac_hash);
    memcpy(device->macAddress, report.macAddress, 6);
    device->count++;
    device->lastSeenMs = millis();
    device->lastRssi = report.report.rssi;
    device->allowed = isAllowedDevice(report.report.mac_hash);
    device->randomizedMac = isRandomizedMacAddress(device->macAddress);
    device->macType = macTypeFromFlags(macAddressFlags(device->macAddress));
}

static void printSniffDebugReport() {
    const uint32_t now = millis();
    Serial.println("{\"type\":\"sniffer_debug\",\"devices\":[");

    bool firstDevice = true;
    for (int i = 0; i < SNIFF_DEBUG_DEVICE_COUNT; i++) {
        SniffDebugDevice& device = sniffDebugDevices[i];
        if (device.hash == 0 || now - device.lastSeenMs > 30000) {
            continue;
        }

        if (!firstDevice) {
            Serial.println(",");
        }
        firstDevice = false;

        Serial.printf(
            "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"hash\":\"%08lX\",\"count\":%lu,\"last_seen_ms\":%lu,\"last_rssi\":%d,\"allowed\":%s,\"randomized_mac\":%s,\"mac_type\":\"%s\"}",
            device.macAddress[0],
            device.macAddress[1],
            device.macAddress[2],
            device.macAddress[3],
            device.macAddress[4],
            device.macAddress[5],
            (unsigned long)device.hash,
            (unsigned long)device.count,
            (unsigned long)device.lastSeenMs,
            device.lastRssi,
            device.allowed ? "true" : "false",
            device.randomizedMac ? "true" : "false",
            device.macType
        );
    }

    Serial.println("]}");
    Serial.printf(
        "Probe requests seen: %lu, reported after filters: %lu\n",
        (unsigned long)probeRequestCount,
        (unsigned long)sentReportCount
    );
}

static void handleSniffedPacket(void* buffer, wifi_promiscuous_pkt_type_t packetType) {
    if (packetType != WIFI_PKT_MGMT) {
        return;
    }

    auto* packet = static_cast<wifi_promiscuous_pkt_t*>(buffer);
    if (!isProbeRequestFrame(packet)) {
        return;
    }

    probeRequestCount++;
    const uint8_t* macAddress = sourceMacAddressFromPacket(packet);
    const RssiReport report = buildRssiReportFromProbe(packet);

    if (!shouldKeepProbeReport(recentDevices, RECENT_DEVICE_COUNT, report.mac_hash, report.rssi)) {
        return;
    }

    queueSniffDebugReport(report, macAddress);
    if (!isAllowedDevice(report.mac_hash)) {
        return;
    }

    sentReportCount++;
    esp_now_send(COORDINATOR_MAC_ADDRESS, reinterpret_cast<const uint8_t*>(&report), sizeof(report));
}

static void onEspNowSent(const uint8_t*, esp_now_send_status_t status) {
    Serial.printf("ESP-NOW send %s\n", status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAILED");
}

void setupSnifferRole() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("Sniffer node %d starting on channel %d\n", NODE_ID, SNIFFER_CHANNEL);

    WiFi.mode(WIFI_STA);
    esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);

    esp_now_init();
    esp_now_register_send_cb(onEspNowSent);

    memcpy(coordinatorPeer.peer_addr, COORDINATOR_MAC_ADDRESS, 6);
    coordinatorPeer.channel = SNIFFER_CHANNEL;
    coordinatorPeer.encrypt = false;
    esp_now_add_peer(&coordinatorPeer);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(handleSniffedPacket);
    Serial.println("Listening for probe requests...");
}

void loopSnifferRole() {
    SniffDebugReport report;
    while (popSniffDebugReport(report)) {
        rememberSniffDebugReport(report);
    }

    static uint32_t lastDebugPrintMs = 0;
    if (millis() - lastDebugPrintMs > REPORT_INTERVAL_MS) {
        lastDebugPrintMs = millis();
        printSniffDebugReport();
    }
}

#endif
