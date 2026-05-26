#ifdef ROLE_COORDINATOR

#include "Coordinator.h"

#include <Arduino.h>
#include <PubSubClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_now.h>
#include <math.h>
#include <time.h>

#include "Shared.h"

namespace {

constexpr uint8_t RSSI_REPORT_QUEUE_SIZE = 24;
constexpr uint8_t MAX_DEV = 20;
constexpr uint32_t STALE_DEVICE_MS = 30000;

enum NetState {
    WIFI_CONNECTING,
    NTP_SYNCING,
    MQTT_CONNECTING,
    NET_READY,
};

struct QueuedRssiReport {
    RssiReport report;
    uint32_t received_ms;
};

struct Device {
    uint32_t hash;
    int8_t rssi[NUM_NODES];
    bool seen[NUM_NODES];
    uint32_t ts;
    uint32_t count;
};

WiFiClientSecure wifiClient;
PubSubClient mqtt(wifiClient);

NetState netState = WIFI_CONNECTING;
uint32_t netStateStart = 0;

QueuedRssiReport rssiReportQueue[RSSI_REPORT_QUEUE_SIZE];
volatile uint8_t rssiReportHead = 0;
volatile uint8_t rssiReportTail = 0;
portMUX_TYPE rssiReportMux = portMUX_INITIALIZER_UNLOCKED;

Device devices[MAX_DEV];
int deviceCount = 0;

bool getTimestamp(char* buffer, size_t len, uint32_t timeoutMs = 100) {
    struct tm timeinfo;

    if (getLocalTime(&timeinfo, timeoutMs)) {
        strftime(buffer, len, "%Y-%m-%dT%H:%M:%S%z", &timeinfo);
        return true;
    }

    snprintf(buffer, len, "uptime:%lu", (unsigned long)millis());
    return false;
}

void startNTP() {
    Serial.printf(
        "\n[WiFi] OK IP=%s MAC=%s Channel=%d GW=%s DNS=%s\n",
        WiFi.localIP().toString().c_str(),
        WiFi.macAddress().c_str(),
        WiFi.channel(),
        WiFi.gatewayIP().toString().c_str(),
        WiFi.dnsIP().toString().c_str());

    configTime(0, 0, "0.dk.pool.ntp.org", "pool.ntp.org", "time.google.com");
    setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
    tzset();

    Serial.println("[NTP] Syncing...");
    netState = NTP_SYNCING;
    netStateStart = millis();
}

void startMQTT() {
    wifiClient.setInsecure();
    mqtt.setServer(MQTT_HOST, MQTT_PORT);

    Serial.printf("[MQTT] Connecting to %s:%d...\n", MQTT_HOST, MQTT_PORT);
    netState = MQTT_CONNECTING;
    netStateStart = millis();
}

bool mqttReady() {
    return netState == NET_READY && mqtt.connected();
}

bool publishMqtt(const char* topic, const char* payload) {
    if (!mqttReady()) {
        Serial.printf("[MQTT] Not ready %s\n", topic);
        return false;
    }

    bool ok = mqtt.publish(topic, payload);
    Serial.printf("[MQTT] Publish %s %s %s\n", ok ? "OK" : "FAILED", topic, payload);
    return ok;
}

bool queueRssiReport(const RssiReport& report) {
    portENTER_CRITICAL(&rssiReportMux);
    uint8_t next = (rssiReportHead + 1) % RSSI_REPORT_QUEUE_SIZE;

    if (next == rssiReportTail) {
        portEXIT_CRITICAL(&rssiReportMux);
        return false;
    }

    rssiReportQueue[rssiReportHead].report = report;
    rssiReportQueue[rssiReportHead].received_ms = millis();
    rssiReportHead = next;
    portEXIT_CRITICAL(&rssiReportMux);
    return true;
}

bool peekRssiReport(QueuedRssiReport& queued) {
    portENTER_CRITICAL(&rssiReportMux);

    if (rssiReportTail == rssiReportHead) {
        portEXIT_CRITICAL(&rssiReportMux);
        return false;
    }

    queued = rssiReportQueue[rssiReportTail];
    portEXIT_CRITICAL(&rssiReportMux);
    return true;
}

void dropQueuedRssiReport() {
    portENTER_CRITICAL(&rssiReportMux);

    if (rssiReportTail != rssiReportHead) {
        rssiReportTail = (rssiReportTail + 1) % RSSI_REPORT_QUEUE_SIZE;
    }

    portEXIT_CRITICAL(&rssiReportMux);
}

Device* getDevice(uint32_t hash) {
    for (int i = 0; i < deviceCount; i++) {
        if (devices[i].hash == hash) {
            return &devices[i];
        }
    }

    Device* device = (deviceCount < MAX_DEV) ? &devices[deviceCount++] : &devices[0];
    memset(device, 0, sizeof(*device));
    device->hash = hash;
    return device;
}

bool readRssiReport(const uint8_t* data, int len, RssiReport& report) {
    Serial.printf("ESP-NOW recv: %d bytes\n", len);

    if (len != sizeof(RssiReport)) {
        Serial.printf("  bad len (expected %d)\n", sizeof(RssiReport));
        return false;
    }

    memcpy(&report, data, sizeof(report));
    Serial.printf(
        "  node=%d hash=%08lX rssi=%d\n",
        report.node_id,
        (unsigned long)report.mac_hash,
        report.rssi);

    if (report.node_id < 1 || report.node_id > NUM_NODES) {
        Serial.printf("  bad node_id\n");
        return false;
    }

    if (!isAllowedDevice(report.mac_hash)) {
        Serial.printf("  blocked device\n");
        return false;
    }

    return true;
}

void rememberDeviceReading(const RssiReport& report) {
    Device* device = getDevice(report.mac_hash);
    int nodeIndex = report.node_id - 1;

    device->rssi[nodeIndex] = report.rssi;
    device->seen[nodeIndex] = true;
    device->ts = millis();
    device->count++;
}

void onRecv(const uint8_t*, const uint8_t* data, int len) {
    RssiReport report;

    if (!readRssiReport(data, len, report)) {
        return;
    }

    if (!queueRssiReport(report)) {
        Serial.println("  report queue full");
    }

    rememberDeviceReading(report);
}

bool calcPos(Device* device, float& x, float& y) {
    float sw = 0;
    float sx = 0;
    float sy = 0;
    int n = 0;

    for (int i = 0; i < NUM_NODES; i++) {
        if (!device->seen[i]) {
            continue;
        }

        float dist = powf(10.0f, (TX_POWER - device->rssi[i]) / (10.0f * PATH_N));
        float weight = 1.0f / (dist * dist + 1e-4f);

        sx += weight * NODE_POS[i][0];
        sy += weight * NODE_POS[i][1];
        sw += weight;
        n++;
    }

    if (n < 1 || sw == 0.0f) {
        return false;
    }

    x = sx / sw;
    y = sy / sw;
    return true;
}

int seenNodeCount(Device* device) {
    int count = 0;

    for (int i = 0; i < NUM_NODES; i++) {
        if (device->seen[i]) {
            count++;
        }
    }

    return count;
}

void updateNetwork() {
    uint32_t now = millis();

    switch (netState) {
        case WIFI_CONNECTING:
            if (WiFi.status() == WL_CONNECTED) {
                startNTP();
            } else if (now - netStateStart > 15000) {
                Serial.println("[WiFi] Timeout - retrying...");
                WiFi.reconnect();
                netStateStart = now;
            }
            break;

        case NTP_SYNCING: {
            struct tm timeinfo;

            if (getLocalTime(&timeinfo)) {
                char timestamp[32];
                getTimestamp(timestamp, sizeof(timestamp));
                Serial.printf("[NTP] OK %s\n", timestamp);
                startMQTT();
            } else if (now - netStateStart > 20000) {
                Serial.println("[NTP] FAILED - continuing without time sync");
                startMQTT();
            }

            break;
        }

        case MQTT_CONNECTING:
            if (mqtt.connected()) {
                Serial.println("[MQTT] OK");
                netState = NET_READY;
            } else if (now - netStateStart > 500) {
                mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS);
                netStateStart = now;

                if (!mqtt.connected()) {
                    Serial.printf("[MQTT] state=%d retrying...\n", mqtt.state());
                }
            }
            break;

        case NET_READY:
            mqtt.loop();

            if (!mqtt.connected() && WiFi.status() == WL_CONNECTED) {
                Serial.println("[MQTT] Lost connection - reconnecting...");
                netState = MQTT_CONNECTING;
                netStateStart = now;
            }
            break;
    }
}

void publishQueuedRssiReports(char* buffer, size_t bufferSize, const char* timestamp, bool timeSynced) {
    if (!mqttReady()) {
        return;
    }

    QueuedRssiReport queued;

    while (peekRssiReport(queued)) {
        snprintf(
            buffer,
            bufferSize,
            "{\"type\":\"sniffer_result\",\"id\":\"%08lX\",\"node_id\":%u,\"rssi\":%d,\"timestamp\":\"%s\",\"time_synced\":%s,\"received_ms\":%lu}",
            (unsigned long)queued.report.mac_hash,
            queued.report.node_id,
            queued.report.rssi,
            timestamp,
            timeSynced ? "true" : "false",
            (unsigned long)queued.received_ms);

        if (!publishMqtt(MQTT_SNIFFER_TOPIC, buffer)) {
            break;
        }

        dropQueuedRssiReport();
    }
}

void publishDevicePosition(
    Device& device,
    char* buffer,
    size_t bufferSize,
    const char* timestamp,
    bool timeSynced,
    uint32_t now) {
    float x;
    float y;

    if (now - device.ts > STALE_DEVICE_MS) {
        return;
    }

    if (seenNodeCount(&device) < 2) {
        return;
    }

    if (!calcPos(&device, x, y)) {
        return;
    }

    snprintf(
        buffer,
        bufferSize,
        "{\"type\":\"position\",\"id\":\"%08lX\",\"timestamp\":\"%s\",\"time_synced\":%s,\"uptime_ms\":%lu,\"last_seen_ms\":%lu,\"count\":%lu,\"x\":%.1f,\"y\":%.1f}",
        (unsigned long)device.hash,
        timestamp,
        timeSynced ? "true" : "false",
        (unsigned long)now,
        (unsigned long)device.ts,
        (unsigned long)device.count,
        x,
        y);

    publishMqtt(MQTT_POSITION_TOPIC, buffer);
}

void publishPositions(char* buffer, size_t bufferSize, const char* timestamp, bool timeSynced) {
    if (!mqttReady()) {
        return;
    }

    uint32_t now = millis();

    for (int i = 0; i < deviceCount; i++) {
        publishDevicePosition(devices[i], buffer, bufferSize, timestamp, timeSynced, now);
    }
}

}  // namespace

void setupCoordinator() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("[WiFi] Connecting to %s...\n", WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    netState = WIFI_CONNECTING;
    netStateStart = millis();

    while (WiFi.status() != WL_CONNECTED) {
        updateNetwork();
        delay(50);
    }

    esp_now_init();
    esp_now_register_recv_cb(onRecv);
    Serial.println("ESP-NOW OK");
}

void loopCoordinator() {
    updateNetwork();

    static uint32_t last = 0;
    char buffer[256];
    char timestamp[32];
    bool timeSynced = getTimestamp(timestamp, sizeof(timestamp));

    publishQueuedRssiReports(buffer, sizeof(buffer), timestamp, timeSynced);

    if (millis() - last < REPORT_INTERVAL_MS) {
        return;
    }

    last = millis();
    publishPositions(buffer, sizeof(buffer), timestamp, timeSynced);
}

#endif
