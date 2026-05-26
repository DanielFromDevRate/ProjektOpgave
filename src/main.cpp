#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

// ─── CONFIG (edit before flashing) ───────────────────────────────────────────

// Coordinator MAC – flash coordinator first, read MAC from Serial, paste here
static const uint8_t COORD_MAC[6] = {0xEC, 0x64, 0xC9, 0x85, 0xF5, 0x8C};

// Sniffer channel must match the WiFi AP channel the coordinator connects to
#define SNIFFER_CHANNEL 2

// Each sniffer gets a unique NODE_ID (1..NUM_NODES); coordinator uses 0
#define NODE_ID 3

static const float NODE_POS[][2] = {
    {  0,  0 },
    {100,  0 },
    { 50, 87 },
};
#define NUM_NODES 3

// Coordinator WiFi / MQTT
#define WIFI_SSID   "IoT_H3/4"
#define WIFI_PASS   "98806829"
#define MQTT_HOST   "wilsons.local"
#define MQTT_PORT   8883
#define DEVICE_ID   "device07"
#define MQTT_USER   "device07"
#define MQTT_PASS   "madTdHrb"
#define MQTT_BASE_TOPIC       "/devices/device07"
#define MQTT_SNIFFER_TOPIC    MQTT_BASE_TOPIC "/sniffer_result"
#define MQTT_POSITION_TOPIC   MQTT_BASE_TOPIC "/position"

// Keep true while discovering devices. Set false after filling ALLOWED_DEVICE_HASHES.
#define ALLOW_ALL_DEVICES true

// Add allowed device hashes here after discovering them from the sniffer Serial output.
static const uint32_t ALLOWED_DEVICE_HASHES[] = {
    0,
    //0x782C50E5,
    //0x5851599B,
};
#define NUM_ALLOWED_DEVICES (sizeof(ALLOWED_DEVICE_HASHES) / sizeof(ALLOWED_DEVICE_HASHES[0]))

// Sniffer noise filtering. Raise MIN_REPORT_RSSI to only keep closer devices.
#define MIN_REPORT_RSSI -75
#define SAME_DEVICE_REPORT_INTERVAL_MS 2000
#define REPORT_INTERVAL_MS 10000

// RSSI → distance model:  d = 10 ^ ((TX_POWER - rssi) / (10 * PATH_N))
#define TX_POWER  -59.0f   // measured RSSI at 1 m
#define PATH_N     2.0f    // path-loss exponent (free space ≈ 2)

// ─── SHARED ──────────────────────────────────────────────────────────────────

struct RssiReport {
    uint8_t  node_id;
    uint32_t mac_hash;  // one-way FNV-1a hash – raw MAC is never transmitted
    int8_t   rssi;
};

// FNV-1a: irreversible pseudonym; satisfies GDPR data-minimisation requirement
static uint32_t hashMac(const uint8_t* m) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= m[i]; h *= 16777619u; }
    return h;
}

static bool isAllowedDevice(uint32_t hash) {
    if (ALLOW_ALL_DEVICES) return true;
    for (size_t i = 0; i < NUM_ALLOWED_DEVICES; i++) {
        if (ALLOWED_DEVICE_HASHES[i] == 0) continue;
        if (ALLOWED_DEVICE_HASHES[i] == hash) return true;
    }
    return false;
}

// ═══════════════════════════ SNIFFER ═════════════════════════════════════════
#ifdef ROLE_SNIFFER

static esp_now_peer_info_t peer;

static uint32_t probeCount = 0;
static uint32_t reportCount = 0;

#define RECENT_DEVICE_COUNT 24
struct RecentDevice {
    uint32_t hash;
    uint32_t last_ms;
};

static RecentDevice recentDevices[RECENT_DEVICE_COUNT];

static bool shouldReportDevice(uint32_t hash, int8_t rssi) {
    if (rssi < MIN_REPORT_RSSI) return false;

    uint32_t now = millis();
    int empty = -1;
    int oldest = 0;

    for (int i = 0; i < RECENT_DEVICE_COUNT; i++) {
        if (recentDevices[i].hash == hash) {
            if (now - recentDevices[i].last_ms < SAME_DEVICE_REPORT_INTERVAL_MS) return false;
            recentDevices[i].last_ms = now;
            return true;
        }
        if (recentDevices[i].hash == 0 && empty < 0) empty = i;
        if (recentDevices[i].last_ms < recentDevices[oldest].last_ms) oldest = i;
    }

    int slot = (empty >= 0) ? empty : oldest;
    recentDevices[slot].hash = hash;
    recentDevices[slot].last_ms = now;
    return true;
}

#define SNIFF_DEBUG_QUEUE_SIZE 16
struct SniffDebugReport {
    RssiReport report;
    uint8_t mac[6];
};

static SniffDebugReport sniffDebugQueue[SNIFF_DEBUG_QUEUE_SIZE];
static volatile uint8_t sniffDebugHead = 0;
static volatile uint8_t sniffDebugTail = 0;
static portMUX_TYPE sniffDebugMux = portMUX_INITIALIZER_UNLOCKED;

static void queueSniffDebug(const RssiReport& r, const uint8_t* mac) {
    portENTER_CRITICAL_ISR(&sniffDebugMux);
    uint8_t next = (sniffDebugHead + 1) % SNIFF_DEBUG_QUEUE_SIZE;
    if (next != sniffDebugTail) {
        sniffDebugQueue[sniffDebugHead].report = r;
        memcpy(sniffDebugQueue[sniffDebugHead].mac, mac, 6);
        sniffDebugHead = next;
    }
    portEXIT_CRITICAL_ISR(&sniffDebugMux);
}

static bool popSniffDebug(SniffDebugReport& r) {
    portENTER_CRITICAL(&sniffDebugMux);
    if (sniffDebugTail == sniffDebugHead) {
        portEXIT_CRITICAL(&sniffDebugMux);
        return false;
    }
    r = sniffDebugQueue[sniffDebugTail];
    sniffDebugTail = (sniffDebugTail + 1) % SNIFF_DEBUG_QUEUE_SIZE;
    portEXIT_CRITICAL(&sniffDebugMux);
    return true;
}

static bool isRandomizedMac(const uint8_t* mac) {
    return (mac[0] & 0x02) != 0;
}

static bool isMulticastMac(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

static const char* macType(const uint8_t* mac) {
    if (isMulticastMac(mac)) return "multicast";
    if (isRandomizedMac(mac)) return "randomized";
    return "vendor";
}

#define SNIFF_DEBUG_DEVICE_COUNT 32
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

static SniffDebugDevice sniffDebugDevices[SNIFF_DEBUG_DEVICE_COUNT];

static SniffDebugDevice* getSniffDebugDevice(uint32_t hash) {
    int empty = -1;
    int oldest = 0;

    for (int i = 0; i < SNIFF_DEBUG_DEVICE_COUNT; i++) {
        if (sniffDebugDevices[i].hash == hash) return &sniffDebugDevices[i];
        if (sniffDebugDevices[i].hash == 0 && empty < 0) empty = i;
        if (sniffDebugDevices[i].last_ms < sniffDebugDevices[oldest].last_ms) oldest = i;
    }

    int slot = (empty >= 0) ? empty : oldest;
    memset(&sniffDebugDevices[slot], 0, sizeof(sniffDebugDevices[slot]));
    sniffDebugDevices[slot].hash = hash;
    return &sniffDebugDevices[slot];
}

static void rememberSniffDebug(const SniffDebugReport& r) {
    SniffDebugDevice* d = getSniffDebugDevice(r.report.mac_hash);
    memcpy(d->mac, r.mac, 6);
    d->count++;
    d->last_ms = millis();
    d->last_rssi = r.report.rssi;
    d->allowed = isAllowedDevice(r.report.mac_hash);
    d->randomized_mac = isRandomizedMac(d->mac);
    d->mac_type = macType(d->mac);
}

static void printSniffDebugReport() {
    uint32_t now = millis();
    Serial.println("{\"type\":\"sniffer_debug\",\"devices\":[");
    bool first = true;
    for (int i = 0; i < SNIFF_DEBUG_DEVICE_COUNT; i++) {
        SniffDebugDevice& d = sniffDebugDevices[i];
        if (d.hash == 0 || now - d.last_ms > 30000) continue;
        if (!first) Serial.println(",");
        first = false;
        Serial.printf(
            "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"hash\":\"%08lX\",\"count\":%lu,\"last_seen_ms\":%lu,\"last_rssi\":%d,\"allowed\":%s,\"randomized_mac\":%s,\"mac_type\":\"%s\"}",
            d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5],
            (unsigned long)d.hash,
            (unsigned long)d.count,
            (unsigned long)d.last_ms,
            d.last_rssi,
            d.allowed ? "true" : "false",
            d.randomized_mac ? "true" : "false",
            d.mac_type);
    }
    Serial.println("]}");
    Serial.printf("Probe requests seen: %lu, reported after filters: %lu\n",
                  (unsigned long)probeCount, (unsigned long)reportCount);
}

static void sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 24) return;
    if (pkt->payload[0] != 0x40) return;  // probe requests only (subtype 0100)

    probeCount++;
    // Source MAC is at byte offset 10 in the 802.11 management frame header
    const uint8_t* mac = pkt->payload + 10;
    RssiReport r = { NODE_ID, hashMac(mac), (int8_t)pkt->rx_ctrl.rssi };
    if (!shouldReportDevice(r.mac_hash, r.rssi)) return;
    queueSniffDebug(r, mac);
    if (!isAllowedDevice(r.mac_hash)) return;
    reportCount++;
    esp_now_send(COORD_MAC, (uint8_t*)&r, sizeof(r));
}

static void onEspNowSent(const uint8_t*, esp_now_send_status_t status) {
    Serial.printf("ESP-NOW send %s\n", status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAILED");
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("Sniffer node %d starting on channel %d\n", NODE_ID, SNIFFER_CHANNEL);

    WiFi.mode(WIFI_STA);  // STA mode but do not connect – channel is ours to set
    esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);

    esp_now_init();
    esp_now_register_send_cb(onEspNowSent);
    memcpy(peer.peer_addr, COORD_MAC, 6);
    peer.channel = SNIFFER_CHANNEL;
    peer.encrypt = false;
    esp_now_add_peer(&peer);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffCb);
    Serial.println("Listening for probe requests...");
}

void loop() {
    SniffDebugReport r;
    while (popSniffDebug(r)) {
        rememberSniffDebug(r);
    }

    static uint32_t last = 0;
    if (millis() - last > REPORT_INTERVAL_MS) {
        last = millis();
        printSniffDebugReport();
    }
}

// ══════════════════════════ COORDINATOR ══════════════════════════════════════
#elif defined(ROLE_COORDINATOR)

#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <math.h>
#include <time.h>

static WiFiClientSecure wc;
static PubSubClient     mqtt(wc);

enum NetState { WIFI_CONNECTING, NTP_SYNCING, MQTT_CONNECTING, NET_READY };
static NetState netState = WIFI_CONNECTING;
static uint32_t netStateStart = 0;

struct QueuedRssiReport {
    RssiReport report;
    uint32_t received_ms;
};

#define RSSI_REPORT_QUEUE_SIZE 24
static QueuedRssiReport rssiReportQueue[RSSI_REPORT_QUEUE_SIZE];
static volatile uint8_t rssiReportHead = 0;
static volatile uint8_t rssiReportTail = 0;
static portMUX_TYPE rssiReportMux = portMUX_INITIALIZER_UNLOCKED;

static bool getTimestamp(char* buf, size_t len, uint32_t timeoutMs = 100) {
    struct tm timeinfo;
    if (getLocalTime(&timeinfo, timeoutMs)) {
        strftime(buf, len, "%Y-%m-%dT%H:%M:%S%z", &timeinfo);
        return true;
    }
    snprintf(buf, len, "uptime:%lu", (unsigned long)millis());
    return false;
}

struct Device {
    uint32_t hash;
    int8_t   rssi[NUM_NODES];
    bool     seen[NUM_NODES];
    uint32_t ts;
    uint32_t count;
};

#define MAX_DEV 20
static Device devs[MAX_DEV];
static int    ndev = 0;

static void startNTP() {
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
    netState = NTP_SYNCING;
    netStateStart = millis();
}

static void startMQTT() {
    wc.setInsecure();  // TLS without certificate verification
    mqtt.setServer(MQTT_HOST, MQTT_PORT);
    Serial.printf("[MQTT] Connecting to %s:%d...\n", MQTT_HOST, MQTT_PORT);
    netState = MQTT_CONNECTING;
    netStateStart = millis();
}

static bool mqttReady() {
    return netState == NET_READY && mqtt.connected();
}

static bool publishMqtt(const char* topic, const char* payload) {
    if (!mqttReady()) {
        Serial.printf("[MQTT] Not ready %s\n", topic);
        return false;
    }
    bool ok = mqtt.publish(topic, payload);
    Serial.printf("[MQTT] Publish %s %s %s\n", ok ? "OK" : "FAILED", topic, payload);
    return ok;
}

static bool queueRssiReport(const RssiReport& report) {
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

static bool peekRssiReport(QueuedRssiReport& queued) {
    portENTER_CRITICAL(&rssiReportMux);
    if (rssiReportTail == rssiReportHead) {
        portEXIT_CRITICAL(&rssiReportMux);
        return false;
    }
    queued = rssiReportQueue[rssiReportTail];
    portEXIT_CRITICAL(&rssiReportMux);
    return true;
}

static void dropQueuedRssiReport() {
    portENTER_CRITICAL(&rssiReportMux);
    if (rssiReportTail != rssiReportHead) {
        rssiReportTail = (rssiReportTail + 1) % RSSI_REPORT_QUEUE_SIZE;
    }
    portEXIT_CRITICAL(&rssiReportMux);
}

static Device* getDevice(uint32_t hash) {
    for (int i = 0; i < ndev; i++)
        if (devs[i].hash == hash) return &devs[i];
    Device* d = (ndev < MAX_DEV) ? &devs[ndev++] : &devs[0];  // evict first on overflow
    memset(d, 0, sizeof(*d));
    d->hash = hash;
    return d;
}

static void onRecv(const uint8_t*, const uint8_t* data, int len) {
    Serial.printf("ESP-NOW recv: %d bytes\n", len);
    if (len != sizeof(RssiReport)) { Serial.printf("  bad len (expected %d)\n", sizeof(RssiReport)); return; }
    RssiReport r;
    memcpy(&r, data, sizeof(r));
    Serial.printf("  node=%d hash=%08lX rssi=%d\n", r.node_id, (unsigned long)r.mac_hash, r.rssi);
    if (r.node_id < 1 || r.node_id > NUM_NODES) { Serial.printf("  bad node_id\n"); return; }
    if (!isAllowedDevice(r.mac_hash)) { Serial.printf("  blocked device\n"); return; }
    if (!queueRssiReport(r)) Serial.println("  report queue full");
    Device* d = getDevice(r.mac_hash);
    d->rssi[r.node_id - 1] = r.rssi;
    d->seen[r.node_id - 1] = true;
    d->ts = millis();
    d->count++;
}

// Weighted centroid: weight = 1/d² where d = RSSI-derived distance
static bool calcPos(Device* d, float& x, float& y) {
    float sw = 0, sx = 0, sy = 0;
    int n = 0;
    for (int i = 0; i < NUM_NODES; i++) {
        if (!d->seen[i]) continue;
        float dist = powf(10.0f, (TX_POWER - d->rssi[i]) / (10.0f * PATH_N));
        float w = 1.0f / (dist * dist + 1e-4f);
        sx += w * NODE_POS[i][0];
        sy += w * NODE_POS[i][1];
        sw += w;
        n++;
    }
    if (n < 1 || sw == 0.0f) return false;
    x = sx / sw;
    y = sy / sw;
    return true;
}

static int seenNodeCount(Device* d) {
    int n = 0;
    for (int i = 0; i < NUM_NODES; i++) {
        if (d->seen[i]) n++;
    }
    return n;
}

static void updateNetwork() {
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
                if (!mqtt.connected()) Serial.printf("[MQTT] state=%d retrying...\n", mqtt.state());
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

void setup() {
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

void loop() {
    updateNetwork();

    static uint32_t last = 0;
    char buf[256];
    char timestamp[32];
    bool timeSynced = getTimestamp(timestamp, sizeof(timestamp));
    if (mqttReady()) {
        QueuedRssiReport queued;
        while (peekRssiReport(queued)) {
            snprintf(buf, sizeof(buf),
                "{\"type\":\"sniffer_result\",\"id\":\"%08lX\",\"node_id\":%u,\"rssi\":%d,\"timestamp\":\"%s\",\"time_synced\":%s,\"received_ms\":%lu}",
                (unsigned long)queued.report.mac_hash,
                queued.report.node_id,
                queued.report.rssi,
                timestamp,
                timeSynced ? "true" : "false",
                (unsigned long)queued.received_ms);
            bool ok = publishMqtt(MQTT_SNIFFER_TOPIC, buf);
            if (!ok) break;
            dropQueuedRssiReport();
        }
    }

    if (millis() - last < REPORT_INTERVAL_MS) return;
    last = millis();
    if (!mqttReady()) return;

    uint32_t now = millis();
    for (int i = 0; i < ndev; i++) {
        if (now - devs[i].ts > 30000) continue;  // discard stale entries (>30 s)
        if (seenNodeCount(&devs[i]) < 2) continue;
        float x, y;
        if (!calcPos(&devs[i], x, y)) continue;
        snprintf(buf, sizeof(buf),
            "{\"type\":\"position\",\"id\":\"%08lX\",\"timestamp\":\"%s\",\"time_synced\":%s,\"uptime_ms\":%lu,\"last_seen_ms\":%lu,\"count\":%lu,\"x\":%.1f,\"y\":%.1f}",
            (unsigned long)devs[i].hash,
            timestamp,
            timeSynced ? "true" : "false",
            (unsigned long)now,
            (unsigned long)devs[i].ts,
            (unsigned long)devs[i].count,
            x, y);
        publishMqtt(MQTT_POSITION_TOPIC, buf);
    }
}

#endif
