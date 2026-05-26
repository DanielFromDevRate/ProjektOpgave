#include "CoordinatorNode.h"

#if defined(ROLE_COORDINATOR)

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <esp_now.h>
#include <math.h>
#include <time.h>
#include "Shared.h"

namespace {
    const int RssiReportQueueSize = 24;
    const int MaxTrackedDevices = 20;
    const uint32_t DeviceStaleAfterMs = 30000;
    const uint32_t WifiRetryAfterMs = 15000;
    const uint32_t NtpTimeoutMs = 20000;
    const uint32_t MqttRetryAfterMs = 500;

    enum NetworkState {
        WifiConnecting,
        NtpSyncing,
        MqttConnecting,
        NetworkReady
    };

    struct QueuedRssiReport {
        RssiReport Report;
        uint32_t ReceivedMs;
    };

    struct TrackedDevice {
        uint32_t Hash;
        int8_t Rssi[NUM_NODES];
        bool Seen[NUM_NODES];
        uint32_t LastSeenMs;
        uint32_t Count;
    };

    WiFiClientSecure wifiClient;
    PubSubClient mqtt(wifiClient);

    NetworkState networkState = WifiConnecting;
    uint32_t networkStateStartedMs = 0;

    QueuedRssiReport reportQueue[RssiReportQueueSize];
    volatile uint8_t reportQueueHead = 0;
    volatile uint8_t reportQueueTail = 0;
    portMUX_TYPE reportQueueMux = portMUX_INITIALIZER_UNLOCKED;

    TrackedDevice trackedDevices[MaxTrackedDevices];
    int trackedDeviceCount = 0;

    bool TryGetTimestamp(char* buffer, size_t length, uint32_t timeoutMs = 100) {
        struct tm timeInfo;

        if (getLocalTime(&timeInfo, timeoutMs)) {
            strftime(buffer, length, "%Y-%m-%dT%H:%M:%S%z", &timeInfo);
            return true;
        }

        snprintf(buffer, length, "uptime:%lu", (unsigned long)millis());
        return false;
    }

    void StartNtpSync() {
        Serial.printf("\n[WiFi] OK IP=%s MAC=%s Channel=%d GW=%s DNS=%s\n",
                      WiFi.localIP().toString().c_str(),
                      WiFi.macAddress().c_str(),
                      WiFi.channel(),
                      WiFi.gatewayIP().toString().c_str(),
                      WiFi.dnsIP().toString().c_str());

        configTime(0, 0, "0.dk.pool.ntp.org", "pool.ntp.org", "time.google.com");
        setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
        tzset();

        Serial.println("[NTP] Syncing...");
        networkState = NtpSyncing;
        networkStateStartedMs = millis();
    }

    void StartMqttConnection() {
        wifiClient.setInsecure();
        mqtt.setServer(MQTT_HOST, MQTT_PORT);

        Serial.printf("[MQTT] Connecting to %s:%d...\n", MQTT_HOST, MQTT_PORT);
        networkState = MqttConnecting;
        networkStateStartedMs = millis();
    }

    bool IsMqttReady() {
        return networkState == NetworkReady && mqtt.connected();
    }

    bool PublishMqtt(const char* topic, const char* payload) {
        if (!IsMqttReady()) {
            Serial.printf("[MQTT] Not ready %s\n", topic);
            return false;
        }

        bool published = mqtt.publish(topic, payload);
        Serial.printf("[MQTT] Publish %s %s %s\n", published ? "OK" : "FAILED", topic, payload);
        return published;
    }

    bool TryQueueRssiReport(const RssiReport& report) {
        portENTER_CRITICAL(&reportQueueMux);
        uint8_t nextHead = (reportQueueHead + 1) % RssiReportQueueSize;

        if (nextHead == reportQueueTail) {
            portEXIT_CRITICAL(&reportQueueMux);
            return false;
        }

        reportQueue[reportQueueHead].Report = report;
        reportQueue[reportQueueHead].ReceivedMs = millis();
        reportQueueHead = nextHead;
        portEXIT_CRITICAL(&reportQueueMux);
        return true;
    }

    bool TryPeekRssiReport(QueuedRssiReport& queuedReport) {
        portENTER_CRITICAL(&reportQueueMux);

        if (reportQueueTail == reportQueueHead) {
            portEXIT_CRITICAL(&reportQueueMux);
            return false;
        }

        queuedReport = reportQueue[reportQueueTail];
        portEXIT_CRITICAL(&reportQueueMux);
        return true;
    }

    void DropQueuedRssiReport() {
        portENTER_CRITICAL(&reportQueueMux);

        if (reportQueueTail != reportQueueHead) {
            reportQueueTail = (reportQueueTail + 1) % RssiReportQueueSize;
        }

        portEXIT_CRITICAL(&reportQueueMux);
    }

    TrackedDevice* GetTrackedDevice(uint32_t hash) {
        for (int i = 0; i < trackedDeviceCount; i++) {
            if (trackedDevices[i].Hash == hash) {
                return &trackedDevices[i];
            }
        }

        TrackedDevice* device = (trackedDeviceCount < MaxTrackedDevices)
            ? &trackedDevices[trackedDeviceCount++]
            : &trackedDevices[0];

        memset(device, 0, sizeof(*device));
        device->Hash = hash;
        return device;
    }

    bool IsValidReport(const RssiReport& report) {
        if (report.NodeId < 1 || report.NodeId > NUM_NODES) {
            Serial.println("  bad node_id");
            return false;
        }

        if (!IsAllowedDevice(report.MacHash)) {
            Serial.println("  blocked device");
            return false;
        }

        return true;
    }

    void RememberDeviceReport(const RssiReport& report) {
        TrackedDevice* device = GetTrackedDevice(report.MacHash);
        int nodeIndex = report.NodeId - 1;

        device->Rssi[nodeIndex] = report.Rssi;
        device->Seen[nodeIndex] = true;
        device->LastSeenMs = millis();
        device->Count++;
    }

    void OnEspNowReceived(const uint8_t*, const uint8_t* data, int length) {
        Serial.printf("ESP-NOW recv: %d bytes\n", length);

        if (length != sizeof(RssiReport)) {
            Serial.printf("  bad len (expected %d)\n", sizeof(RssiReport));
            return;
        }

        RssiReport report;
        memcpy(&report, data, sizeof(report));

        Serial.printf("  node=%d hash=%08lX rssi=%d\n",
                      report.NodeId,
                      (unsigned long)report.MacHash,
                      report.Rssi);

        if (!IsValidReport(report)) {
            return;
        }

        if (!TryQueueRssiReport(report)) {
            Serial.println("  report queue full");
        }

        RememberDeviceReport(report);
    }

    float CalculateDistanceFromRssi(int8_t rssi) {
        return powf(10.0f, (TX_POWER - rssi) / (10.0f * PATH_LOSS_EXPONENT));
    }

    bool TryCalculatePosition(const TrackedDevice& device, float& x, float& y) {
        float totalWeight = 0.0f;
        float weightedX = 0.0f;
        float weightedY = 0.0f;
        int seenNodeCount = 0;

        for (int i = 0; i < NUM_NODES; i++) {
            if (!device.Seen[i]) {
                continue;
            }

            float distance = CalculateDistanceFromRssi(device.Rssi[i]);
            float weight = 1.0f / (distance * distance + 1e-4f);

            weightedX += weight * NODE_POSITIONS[i][0];
            weightedY += weight * NODE_POSITIONS[i][1];
            totalWeight += weight;
            seenNodeCount++;
        }

        if (seenNodeCount < 1 || totalWeight == 0.0f) {
            return false;
        }

        x = weightedX / totalWeight;
        y = weightedY / totalWeight;
        return true;
    }

    int CountSeenNodes(const TrackedDevice& device) {
        int count = 0;

        for (int i = 0; i < NUM_NODES; i++) {
            if (device.Seen[i]) {
                count++;
            }
        }

        return count;
    }

    void UpdateNetwork() {
        uint32_t now = millis();

        switch (networkState) {
            case WifiConnecting:
                if (WiFi.status() == WL_CONNECTED) {
                    StartNtpSync();
                } else if (now - networkStateStartedMs > WifiRetryAfterMs) {
                    Serial.println("[WiFi] Timeout - retrying...");
                    WiFi.reconnect();
                    networkStateStartedMs = now;
                }
                break;

            case NtpSyncing: {
                struct tm timeInfo;

                if (getLocalTime(&timeInfo)) {
                    char timestamp[32];
                    TryGetTimestamp(timestamp, sizeof(timestamp));
                    Serial.printf("[NTP] OK %s\n", timestamp);
                    StartMqttConnection();
                } else if (now - networkStateStartedMs > NtpTimeoutMs) {
                    Serial.println("[NTP] FAILED - continuing without time sync");
                    StartMqttConnection();
                }
                break;
            }

            case MqttConnecting:
                if (mqtt.connected()) {
                    Serial.println("[MQTT] OK");
                    networkState = NetworkReady;
                } else if (now - networkStateStartedMs > MqttRetryAfterMs) {
                    mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS);
                    networkStateStartedMs = now;

                    if (!mqtt.connected()) {
                        Serial.printf("[MQTT] state=%d retrying...\n", mqtt.state());
                    }
                }
                break;

            case NetworkReady:
                mqtt.loop();

                if (!mqtt.connected() && WiFi.status() == WL_CONNECTED) {
                    Serial.println("[MQTT] Lost connection - reconnecting...");
                    networkState = MqttConnecting;
                    networkStateStartedMs = now;
                }
                break;
        }
    }

    void PublishQueuedSnifferReports(const char* timestamp, bool timeSynced) {
        char payload[256];
        QueuedRssiReport queuedReport;

        while (TryPeekRssiReport(queuedReport)) {
            snprintf(payload, sizeof(payload),
                     "{\"type\":\"sniffer_result\",\"id\":\"%08lX\",\"node_id\":%u,\"rssi\":%d,\"timestamp\":\"%s\",\"time_synced\":%s,\"received_ms\":%lu}",
                     (unsigned long)queuedReport.Report.MacHash,
                     queuedReport.Report.NodeId,
                     queuedReport.Report.Rssi,
                     timestamp,
                     timeSynced ? "true" : "false",
                     (unsigned long)queuedReport.ReceivedMs);

            if (!PublishMqtt(MQTT_SNIFFER_TOPIC, payload)) {
                break;
            }

            DropQueuedRssiReport();
        }
    }

    void PublishTrackedPositions(const char* timestamp, bool timeSynced) {
        char payload[256];
        uint32_t now = millis();

        for (int i = 0; i < trackedDeviceCount; i++) {
            TrackedDevice& device = trackedDevices[i];

            if (now - device.LastSeenMs > DeviceStaleAfterMs) {
                continue;
            }

            if (CountSeenNodes(device) < 2) {
                continue;
            }

            float x;
            float y;
            if (!TryCalculatePosition(device, x, y)) {
                continue;
            }

            snprintf(payload, sizeof(payload),
                     "{\"type\":\"position\",\"id\":\"%08lX\",\"timestamp\":\"%s\",\"time_synced\":%s,\"uptime_ms\":%lu,\"last_seen_ms\":%lu,\"count\":%lu,\"x\":%.1f,\"y\":%.1f}",
                     (unsigned long)device.Hash,
                     timestamp,
                     timeSynced ? "true" : "false",
                     (unsigned long)now,
                     (unsigned long)device.LastSeenMs,
                     (unsigned long)device.Count,
                     x,
                     y);

            PublishMqtt(MQTT_POSITION_TOPIC, payload);
        }
    }

    void ConfigureWifi() {
        Serial.printf("[WiFi] Connecting to %s...\n", WIFI_SSID);
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_SSID, WIFI_PASS);
        networkState = WifiConnecting;
        networkStateStartedMs = millis();
    }

    void WaitForWifiConnection() {
        while (WiFi.status() != WL_CONNECTED) {
            UpdateNetwork();
            delay(50);
        }
    }

    void ConfigureEspNow() {
        esp_now_init();
        esp_now_register_recv_cb(OnEspNowReceived);
        Serial.println("ESP-NOW OK");
    }
}

namespace CoordinatorNode {
    void Setup() {
        Serial.begin(115200);
        delay(500);

        ConfigureWifi();
        WaitForWifiConnection();
        ConfigureEspNow();
    }

    void Loop() {
        UpdateNetwork();

        char timestamp[32];
        bool timeSynced = TryGetTimestamp(timestamp, sizeof(timestamp));

        if (IsMqttReady()) {
            PublishQueuedSnifferReports(timestamp, timeSynced);
        }

        static uint32_t lastPositionReportMs = 0;
        if (millis() - lastPositionReportMs < REPORT_INTERVAL_MS) {
            return;
        }

        lastPositionReportMs = millis();

        if (IsMqttReady()) {
            PublishTrackedPositions(timestamp, timeSynced);
        }
    }
}

#endif
