#include "CoordinatorRole.h"

#ifdef ROLE_COORDINATOR

#include <Arduino.h>
#include <PubSubClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <time.h>

#include "Config.h"
#include "DeviceIdentity.h"
#include "Positioning.h"
#include "ProbeParsing.h"
#include "SharedTypes.h"

// The coordinator joins WiFi, receives ESP-NOW reports from sniffer nodes, adds
// its own local sniffing as NODE_ID, estimates positions, and publishes MQTT.

static WiFiClientSecure secureWifiClient;
static PubSubClient mqttClient(secureWifiClient);

enum NetworkState {
    WIFI_CONNECTING,
    NTP_SYNCING,
    MQTT_CONNECTING,
    NETWORK_READY,
};

static NetworkState networkState = WIFI_CONNECTING;
static uint32_t networkStateStartedMs = 0;

static const uint8_t MAX_TRACKED_DEVICES = 20;
static TrackedDevice trackedDevices[MAX_TRACKED_DEVICES];
static int trackedDeviceCount = 0;

static const uint8_t COORDINATOR_RECENT_DEVICE_COUNT = 24;
static RecentDeviceRecord coordinatorRecentDevices[COORDINATOR_RECENT_DEVICE_COUNT];
static uint32_t coordinatorProbeRequestCount = 0;
static uint32_t coordinatorKeptReportCount = 0;

static bool getTimestamp(char* buffer, size_t bufferLength, uint32_t timeoutMs = 100) {
    struct tm timeInfo;
    if (getLocalTime(&timeInfo, timeoutMs)) {
        strftime(buffer, bufferLength, "%Y-%m-%dT%H:%M:%S%z", &timeInfo);
        return true;
    }

    snprintf(buffer, bufferLength, "uptime:%lu", (unsigned long)millis());
    return false;
}

static void startNtpSync() {
    Serial.printf(
        "\n[WiFi] OK IP=%s MAC=%s Channel=%d GW=%s DNS=%s\n",
        WiFi.localIP().toString().c_str(),
        WiFi.macAddress().c_str(),
        WiFi.channel(),
        WiFi.gatewayIP().toString().c_str(),
        WiFi.dnsIP().toString().c_str()
    );

    configTime(0, 0, "0.dk.pool.ntp.org", "pool.ntp.org", "time.google.com");
    setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
    tzset();

    Serial.println("[NTP] Syncing...");
    networkState = NTP_SYNCING;
    networkStateStartedMs = millis();
}

static void startMqttConnection() {
    secureWifiClient.setInsecure();
    mqttClient.setBufferSize(MQTT_PACKET_BUFFER_SIZE);
    mqttClient.setServer(MQTT_HOST, MQTT_PORT);

    Serial.printf("[MQTT] Connecting to %s:%d...\n", MQTT_HOST, MQTT_PORT);
    networkState = MQTT_CONNECTING;
    networkStateStartedMs = millis();
}

static bool mqttReady() {
    return networkState == NETWORK_READY && mqttClient.connected();
}

static bool publishMqtt(const char* topic, const char* payload) {
    if (!mqttReady()) {
        Serial.printf("[MQTT] Not ready %s\n", topic);
        return false;
    }

    const bool published = mqttClient.publish(topic, payload);
    Serial.printf("[MQTT] Publish %s %s %s\n", published ? "OK" : "FAILED", topic, payload);
    return published;
}

static TrackedDevice* findOrCreateTrackedDevice(uint32_t deviceHash) {
    for (int i = 0; i < trackedDeviceCount; i++) {
        if (trackedDevices[i].hash == deviceHash) {
            return &trackedDevices[i];
        }
    }

    // If the table is full, reuse slot 0. The next reports will rebuild that entry.
    TrackedDevice* device = (trackedDeviceCount < MAX_TRACKED_DEVICES)
        ? &trackedDevices[trackedDeviceCount++]
        : &trackedDevices[0];
    memset(device, 0, sizeof(*device));
    device->hash = deviceHash;
    return device;
}

static void rememberRssiReport(const RssiReport& report) {
    TrackedDevice* device = findOrCreateTrackedDevice(report.mac_hash);
    const uint8_t nodeIndex = report.node_id - 1;

    device->rssi[nodeIndex] = report.rssi;
    device->macFlags[nodeIndex] = report.mac_flags;
    device->seenByNode[nodeIndex] = true;
    device->nodeReceivedMs[nodeIndex] = millis();
    device->lastSeenMs = millis();
    device->reportCount++;
}

static void onEspNowReceived(const uint8_t*, const uint8_t* data, int length) {
    Serial.printf("ESP-NOW recv: %d bytes\n", length);
    if (length != sizeof(RssiReport)) {
        Serial.printf("  bad len (expected %d)\n", sizeof(RssiReport));
        return;
    }

    RssiReport report;
    memcpy(&report, data, sizeof(report));
    Serial.printf("  node=%d hash=%08lX rssi=%d\n", report.node_id, (unsigned long)report.mac_hash, report.rssi);

    if (report.node_id < 1 || report.node_id > NUMBER_OF_NODES) {
        Serial.printf("  bad node_id\n");
        return;
    }
    if (!isAllowedDevice(report.mac_hash)) {
        Serial.printf("  blocked device\n");
        return;
    }

    rememberRssiReport(report);
}

static void handleCoordinatorSniffedPacket(void* buffer, wifi_promiscuous_pkt_type_t packetType) {
    if (packetType != WIFI_PKT_MGMT) {
        return;
    }

    auto* packet = static_cast<wifi_promiscuous_pkt_t*>(buffer);
    if (!isProbeRequestFrame(packet)) {
        return;
    }

    coordinatorProbeRequestCount++;
    const RssiReport report = buildRssiReportFromProbe(packet);

    if (!shouldKeepProbeReport(
            coordinatorRecentDevices,
            COORDINATOR_RECENT_DEVICE_COUNT,
            report.mac_hash,
            report.rssi
        )) {
        return;
    }
    if (!isAllowedDevice(report.mac_hash)) {
        return;
    }

    coordinatorKeptReportCount++;
    rememberRssiReport(report);
}

// Returns indexes into trackedDevices, sorted by strongest recent RSSI.
static int selectPublishCandidates(uint8_t* candidateIndexes, uint32_t now) {
    int candidateCount = 0;

    for (int i = 0; i < trackedDeviceCount; i++) {
        TrackedDevice* device = &trackedDevices[i];

        if (now - device->lastSeenMs > DEVICE_STALE_AFTER_MS) {
            continue;
        }
        if (SHOW_ONLY_KNOWN_DEVICES && !isKnownDevice(device->hash)) {
            continue;
        }
        if (recentNodeCount(device, now) < MIN_POSITION_NODES) {
            continue;
        }

        const int candidateRssi = bestRecentRssi(device, now);
        if (candidateRssi < MIN_REPORT_RSSI) {
            continue;
        }

        int insertAt = candidateCount;
        for (int j = 0; j < candidateCount; j++) {
            if (candidateRssi > bestRecentRssi(&trackedDevices[candidateIndexes[j]], now)) {
                insertAt = j;
                break;
            }
        }

        if (insertAt < MAX_PUBLISHED_DEVICES) {
            const int lastShiftIndex = (candidateCount < MAX_PUBLISHED_DEVICES)
                ? candidateCount
                : MAX_PUBLISHED_DEVICES - 1;
            for (int j = lastShiftIndex; j > insertAt; j--) {
                candidateIndexes[j] = candidateIndexes[j - 1];
            }
            candidateIndexes[insertAt] = i;
            if (candidateCount < MAX_PUBLISHED_DEVICES) {
                candidateCount++;
            }
        }
    }

    return candidateCount;
}

static bool appendJsonText(char* buffer, size_t bufferSize, size_t& used, const char* text) {
    const size_t textLength = strlen(text);
    if (used + textLength >= bufferSize) {
        return false;
    }

    memcpy(buffer + used, text, textLength + 1);
    used += textLength;
    return true;
}

static void publishSnifferBatch(
    const uint8_t* candidateIndexes,
    int candidateCount,
    const char* timestamp,
    bool timeSynced,
    uint32_t now
) {
    char results[720];
    size_t used = 0;
    int resultCount = 0;
    results[0] = '\0';

    for (int c = 0; c < candidateCount; c++) {
        TrackedDevice* device = &trackedDevices[candidateIndexes[c]];

        for (int node = 0; node < NUMBER_OF_NODES; node++) {
            if (!nodeReportIsRecent(device, node, now)) {
                continue;
            }

            const uint8_t flags = device->macFlags[node];
            char item[220];
            snprintf(
                item,
                sizeof(item),
                "{\"id\":\"%08lX\",\"label\":\"%s\",\"node_id\":%d,\"rssi\":%d,\"received_ms\":%lu,\"mac_type\":\"%s\",\"randomized_mac\":%s}",
                (unsigned long)device->hash,
                deviceLabel(device->hash),
                node + 1,
                device->rssi[node],
                (unsigned long)device->nodeReceivedMs[node],
                macTypeFromFlags(flags),
                (flags & MAC_FLAG_RANDOMIZED) ? "true" : "false"
            );

            if (used + strlen(item) + (resultCount > 0 ? 1 : 0) >= sizeof(results)) {
                break;
            }
            if (resultCount > 0) {
                appendJsonText(results, sizeof(results), used, ",");
            }
            appendJsonText(results, sizeof(results), used, item);
            resultCount++;
        }
    }

    char payload[MQTT_PACKET_BUFFER_SIZE];
    snprintf(
        payload,
        sizeof(payload),
        "{\"type\":\"sniffer_results\",\"timestamp\":\"%s\",\"time_synced\":%s,\"count\":%d,\"results\":[%s]}",
        timestamp,
        timeSynced ? "true" : "false",
        resultCount,
        results
    );

    publishMqtt(MQTT_SNIFFER_TOPIC, payload);
}

static void publishPositionBatch(
    const uint8_t* candidateIndexes,
    int candidateCount,
    const char* timestamp,
    bool timeSynced,
    uint32_t now
) {
    char positions[720];
    size_t used = 0;
    int positionCount = 0;
    positions[0] = '\0';

    for (int c = 0; c < candidateCount; c++) {
        TrackedDevice* device = &trackedDevices[candidateIndexes[c]];
        PositionResult position;

        if (!calculateTrilateration(device, position, now)) {
            continue;
        }

        const uint8_t flags = bestRecentMacFlags(device, now);
        char item[320];
        snprintf(
            item,
            sizeof(item),
            "{\"id\":\"%08lX\",\"label\":\"%s\",\"mac_type\":\"%s\",\"randomized_mac\":%s,\"x\":%.1f,\"y\":%.1f,\"seen_nodes\":%d,\"best_rssi\":%d,\"count\":%lu,\"distances\":[%.1f,%.1f,%.1f],\"fit_error\":%.1f}",
            (unsigned long)device->hash,
            deviceLabel(device->hash),
            macTypeFromFlags(flags),
            (flags & MAC_FLAG_RANDOMIZED) ? "true" : "false",
            position.x,
            position.y,
            recentNodeCount(device, now),
            bestRecentRssi(device, now),
            (unsigned long)device->reportCount,
            position.distanceFromNode[0],
            position.distanceFromNode[1],
            position.distanceFromNode[2],
            position.fitError
        );

        if (used + strlen(item) + (positionCount > 0 ? 1 : 0) >= sizeof(positions)) {
            break;
        }
        if (positionCount > 0) {
            appendJsonText(positions, sizeof(positions), used, ",");
        }
        appendJsonText(positions, sizeof(positions), used, item);
        positionCount++;
    }

    char payload[MQTT_PACKET_BUFFER_SIZE];
    snprintf(
        payload,
        sizeof(payload),
        "{\"type\":\"positions\",\"timestamp\":\"%s\",\"time_synced\":%s,\"count\":%d,\"positions\":[%s]}",
        timestamp,
        timeSynced ? "true" : "false",
        positionCount,
        positions
    );

    publishMqtt(MQTT_POSITION_TOPIC, payload);
}

static void updateNetwork() {
    const uint32_t now = millis();

    switch (networkState) {
        case WIFI_CONNECTING:
            if (WiFi.status() == WL_CONNECTED) {
                startNtpSync();
            } else if (now - networkStateStartedMs > 15000) {
                Serial.println("[WiFi] Timeout - retrying...");
                WiFi.reconnect();
                networkStateStartedMs = now;
            }
            break;

        case NTP_SYNCING: {
            struct tm timeInfo;
            if (getLocalTime(&timeInfo)) {
                char timestamp[32];
                getTimestamp(timestamp, sizeof(timestamp));
                Serial.printf("[NTP] OK %s\n", timestamp);
                startMqttConnection();
            } else if (now - networkStateStartedMs > 20000) {
                Serial.println("[NTP] FAILED - continuing without time sync");
                startMqttConnection();
            }
            break;
        }

        case MQTT_CONNECTING:
            if (mqttClient.connected()) {
                Serial.println("[MQTT] OK");
                networkState = NETWORK_READY;
            } else if (now - networkStateStartedMs > 500) {
                mqttClient.connect(DEVICE_ID, MQTT_USER, MQTT_PASS);
                networkStateStartedMs = now;
                if (!mqttClient.connected()) {
                    Serial.printf("[MQTT] state=%d retrying...\n", mqttClient.state());
                }
            }
            break;

        case NETWORK_READY:
            mqttClient.loop();
            if (!mqttClient.connected() && WiFi.status() == WL_CONNECTED) {
                Serial.println("[MQTT] Lost connection - reconnecting...");
                networkState = MQTT_CONNECTING;
                networkStateStartedMs = now;
            }
            break;
    }
}

void setupCoordinatorRole() {
    Serial.begin(115200);
    delay(500);

    Serial.printf("[WiFi] Connecting to %s...\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    networkState = WIFI_CONNECTING;
    networkStateStartedMs = millis();
    while (WiFi.status() != WL_CONNECTED) {
        updateNetwork();
        delay(50);
    }

    esp_now_init();
    esp_now_register_recv_cb(onEspNowReceived);
    Serial.println("ESP-NOW OK");

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(handleCoordinatorSniffedPacket);
    Serial.printf("Coordinator also sniffing as node %d on WiFi channel %d\n", NODE_ID, WiFi.channel());
}

void loopCoordinatorRole() {
    updateNetwork();

    static uint32_t lastPublishMs = 0;
    if (millis() - lastPublishMs < PUBLISH_BATCH_INTERVAL_MS) {
        return;
    }
    lastPublishMs = millis();

    if (!mqttReady()) {
        return;
    }

    const uint32_t now = millis();
    char timestamp[32];
    const bool timeSynced = getTimestamp(timestamp, sizeof(timestamp));

    uint8_t candidateIndexes[MAX_PUBLISHED_DEVICES];
    const int candidateCount = selectPublishCandidates(candidateIndexes, now);

    publishSnifferBatch(candidateIndexes, candidateCount, timestamp, timeSynced, now);
    publishPositionBatch(candidateIndexes, candidateCount, timestamp, timeSynced, now);
    Serial.printf(
        "Coordinator probe requests seen: %lu, kept after filters: %lu\n",
        (unsigned long)coordinatorProbeRequestCount,
        (unsigned long)coordinatorKeptReportCount
    );
}

#endif
