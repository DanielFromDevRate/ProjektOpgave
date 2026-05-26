#include "SnifferNode.h"

#if defined(ROLE_SNIFFER)

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "Shared.h"

namespace {
    const int SourceMacOffset = 10;
    const int ProbeRequestFrameType = 0x40;
    const int RecentDeviceCount = 24;
    const int SniffDebugQueueSize = 16;
    const int SniffDebugDeviceCount = 32;
    const uint32_t ActiveDebugWindowMs = 30000;

    esp_now_peer_info_t coordinatorPeer;
    uint32_t probeCount = 0;
    uint32_t reportCount = 0;

    struct RecentDevice {
        uint32_t Hash;
        uint32_t LastSeenMs;
    };

    struct SniffDebugReport {
        RssiReport Report;
        uint8_t Mac[6];
    };

    struct SniffDebugDevice {
        uint32_t Hash;
        uint8_t Mac[6];
        uint32_t Count;
        uint32_t LastSeenMs;
        int8_t LastRssi;
        bool Allowed;
        bool RandomizedMac;
        const char* MacType;
    };

    RecentDevice recentDevices[RecentDeviceCount];
    SniffDebugReport sniffDebugQueue[SniffDebugQueueSize];
    SniffDebugDevice sniffDebugDevices[SniffDebugDeviceCount];

    volatile uint8_t sniffDebugHead = 0;
    volatile uint8_t sniffDebugTail = 0;
    portMUX_TYPE sniffDebugMux = portMUX_INITIALIZER_UNLOCKED;

    bool IsRandomizedMac(const uint8_t* mac) {
        return (mac[0] & 0x02) != 0;
    }

    bool IsMulticastMac(const uint8_t* mac) {
        return (mac[0] & 0x01) != 0;
    }

    const char* GetMacType(const uint8_t* mac) {
        if (IsMulticastMac(mac)) {
            return "multicast";
        }

        if (IsRandomizedMac(mac)) {
            return "randomized";
        }

        return "vendor";
    }

    bool IsProbeRequest(const wifi_promiscuous_pkt_t* packet, wifi_promiscuous_pkt_type_t type) {
        if (type != WIFI_PKT_MGMT) {
            return false;
        }

        if (packet->rx_ctrl.sig_len < 24) {
            return false;
        }

        return packet->payload[0] == ProbeRequestFrameType;
    }

    bool ShouldReportDevice(uint32_t hash, int8_t rssi) {
        if (rssi < MIN_REPORT_RSSI) {
            return false;
        }

        uint32_t now = millis();
        int emptySlot = -1;
        int oldestSlot = 0;

        for (int i = 0; i < RecentDeviceCount; i++) {
            if (recentDevices[i].Hash == hash) {
                if (now - recentDevices[i].LastSeenMs < SAME_DEVICE_REPORT_INTERVAL_MS) {
                    return false;
                }

                recentDevices[i].LastSeenMs = now;
                return true;
            }

            if (recentDevices[i].Hash == 0 && emptySlot < 0) {
                emptySlot = i;
            }

            if (recentDevices[i].LastSeenMs < recentDevices[oldestSlot].LastSeenMs) {
                oldestSlot = i;
            }
        }

        int targetSlot = (emptySlot >= 0) ? emptySlot : oldestSlot;
        recentDevices[targetSlot].Hash = hash;
        recentDevices[targetSlot].LastSeenMs = now;
        return true;
    }

    void QueueSniffDebug(const RssiReport& report, const uint8_t* mac) {
        portENTER_CRITICAL_ISR(&sniffDebugMux);
        uint8_t nextHead = (sniffDebugHead + 1) % SniffDebugQueueSize;

        if (nextHead != sniffDebugTail) {
            sniffDebugQueue[sniffDebugHead].Report = report;
            memcpy(sniffDebugQueue[sniffDebugHead].Mac, mac, 6);
            sniffDebugHead = nextHead;
        }

        portEXIT_CRITICAL_ISR(&sniffDebugMux);
    }

    bool TryPopSniffDebug(SniffDebugReport& report) {
        portENTER_CRITICAL(&sniffDebugMux);

        if (sniffDebugTail == sniffDebugHead) {
            portEXIT_CRITICAL(&sniffDebugMux);
            return false;
        }

        report = sniffDebugQueue[sniffDebugTail];
        sniffDebugTail = (sniffDebugTail + 1) % SniffDebugQueueSize;
        portEXIT_CRITICAL(&sniffDebugMux);
        return true;
    }

    SniffDebugDevice* GetSniffDebugDevice(uint32_t hash) {
        int emptySlot = -1;
        int oldestSlot = 0;

        for (int i = 0; i < SniffDebugDeviceCount; i++) {
            if (sniffDebugDevices[i].Hash == hash) {
                return &sniffDebugDevices[i];
            }

            if (sniffDebugDevices[i].Hash == 0 && emptySlot < 0) {
                emptySlot = i;
            }

            if (sniffDebugDevices[i].LastSeenMs < sniffDebugDevices[oldestSlot].LastSeenMs) {
                oldestSlot = i;
            }
        }

        int targetSlot = (emptySlot >= 0) ? emptySlot : oldestSlot;
        memset(&sniffDebugDevices[targetSlot], 0, sizeof(sniffDebugDevices[targetSlot]));
        sniffDebugDevices[targetSlot].Hash = hash;
        return &sniffDebugDevices[targetSlot];
    }

    void RememberSniffDebug(const SniffDebugReport& report) {
        SniffDebugDevice* device = GetSniffDebugDevice(report.Report.MacHash);

        memcpy(device->Mac, report.Mac, 6);
        device->Count++;
        device->LastSeenMs = millis();
        device->LastRssi = report.Report.Rssi;
        device->Allowed = IsAllowedDevice(report.Report.MacHash);
        device->RandomizedMac = IsRandomizedMac(device->Mac);
        device->MacType = GetMacType(device->Mac);
    }

    void PrintDebugDevice(const SniffDebugDevice& device) {
        Serial.printf(
            "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"hash\":\"%08lX\",\"count\":%lu,\"last_seen_ms\":%lu,\"last_rssi\":%d,\"allowed\":%s,\"randomized_mac\":%s,\"mac_type\":\"%s\"}",
            device.Mac[0], device.Mac[1], device.Mac[2], device.Mac[3], device.Mac[4], device.Mac[5],
            (unsigned long)device.Hash,
            (unsigned long)device.Count,
            (unsigned long)device.LastSeenMs,
            device.LastRssi,
            device.Allowed ? "true" : "false",
            device.RandomizedMac ? "true" : "false",
            device.MacType);
    }

    void PrintSniffDebugReport() {
        uint32_t now = millis();
        bool first = true;

        Serial.println("{\"type\":\"sniffer_debug\",\"devices\":[");

        for (int i = 0; i < SniffDebugDeviceCount; i++) {
            SniffDebugDevice& device = sniffDebugDevices[i];

            if (device.Hash == 0 || now - device.LastSeenMs > ActiveDebugWindowMs) {
                continue;
            }

            if (!first) {
                Serial.println(",");
            }

            first = false;
            PrintDebugDevice(device);
        }

        Serial.println("]}");
        Serial.printf("Probe requests seen: %lu, reported after filters: %lu\n",
                      (unsigned long)probeCount,
                      (unsigned long)reportCount);
    }

    void SendReportToCoordinator(const RssiReport& report) {
        if (!IsAllowedDevice(report.MacHash)) {
            return;
        }

        reportCount++;
        esp_now_send(COORDINATOR_MAC, (uint8_t*)&report, sizeof(report));
    }

    void IRAM_ATTR OnWifiPacketReceived(void* buffer, wifi_promiscuous_pkt_type_t type) {
        wifi_promiscuous_pkt_t* packet = (wifi_promiscuous_pkt_t*)buffer;

        if (!IsProbeRequest(packet, type)) {
            return;
        }

        probeCount++;
        const uint8_t* sourceMac = packet->payload + SourceMacOffset;
        RssiReport report = {NODE_ID, HashMac(sourceMac), (int8_t)packet->rx_ctrl.rssi};

        if (!ShouldReportDevice(report.MacHash, report.Rssi)) {
            return;
        }

        QueueSniffDebug(report, sourceMac);
        SendReportToCoordinator(report);
    }

    void OnEspNowSent(const uint8_t*, esp_now_send_status_t status) {
        Serial.printf("ESP-NOW send %s\n", status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAILED");
    }

    void ConfigureWifi() {
        WiFi.mode(WIFI_STA);
        esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);
    }

    void ConfigureEspNow() {
        esp_now_init();
        esp_now_register_send_cb(OnEspNowSent);

        memcpy(coordinatorPeer.peer_addr, COORDINATOR_MAC, 6);
        coordinatorPeer.channel = SNIFFER_CHANNEL;
        coordinatorPeer.encrypt = false;
        esp_now_add_peer(&coordinatorPeer);
    }

    void ConfigureSnifferCallback() {
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(OnWifiPacketReceived);
    }
}

namespace SnifferNode {
    void Setup() {
        Serial.begin(115200);
        delay(500);
        Serial.printf("Sniffer node %d starting on channel %d\n", NODE_ID, SNIFFER_CHANNEL);

        ConfigureWifi();
        ConfigureEspNow();
        ConfigureSnifferCallback();

        Serial.println("Listening for probe requests...");
    }

    void Loop() {
        SniffDebugReport report;

        while (TryPopSniffDebug(report)) {
            RememberSniffDebug(report);
        }

        static uint32_t lastReportMs = 0;
        if (millis() - lastReportMs > REPORT_INTERVAL_MS) {
            lastReportMs = millis();
            PrintSniffDebugReport();
        }
    }
}

#endif
