#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

// ─── CONFIG (edit before flashing) ───────────────────────────────────────────

// Coordinator MAC – flash coordinator first, read MAC from Serial, paste here
static const uint8_t COORD_MAC[6] = {0xEC, 0x64, 0xC9, 0x85, 0xF5, 0x8C};

// Sniffer channel must match the WiFi AP channel the coordinator connects to
#define SNIFFER_CHANNEL 2

// Each measuring ESP32 gets a unique NODE_ID (1..NUM_NODES).
// With three boards total, the coordinator also sniffs as node 3.
#ifndef NODE_ID
#define NODE_ID 3
#endif

static const float NODE_POS[][2] = {
    {  64.0f,   0.0f },
    { -32.0f,  55.4f },
    { -32.0f, -55.4f },
};
#define NUM_NODES 3

#if NODE_ID < 1 || NODE_ID > NUM_NODES
#error "NODE_ID must be between 1 and NUM_NODES"
#endif

// Coordinator WiFi / MQTT
#define WIFI_SSID   "IoT_H3/4"
#define WIFI_PASS   "98806829"
#define MQTT_HOST   "wilsons.local"
#define MQTT_PORT   8883
#define DEVICE_ID   "device07"
#define MQTT_USER   "device07"
#define MQTT_PASS   "madTdHrb"
#define MQTT_BASE_TOPIC       "/devices/device07"
#define MQTT_SNIFFER_TOPIC    MQTT_BASE_TOPIC "/sniffer_results"
#define MQTT_POSITION_TOPIC   MQTT_BASE_TOPIC "/positions"

// Keep true for iPhone/demo proximity mode. iPhones randomize probe MACs, so a
// static hash allow-list only works reliably for devices with stable MACs.
#define ALLOW_ALL_DEVICES true

// Add allowed device hashes here after discovering them from the sniffer Serial output.
static const uint32_t ALLOWED_DEVICE_HASHES[] = {
    0x80465F21,
    //0x782C50E5,
    //0x5851599B,
};
#define NUM_ALLOWED_DEVICES (sizeof(ALLOWED_DEVICE_HASHES) / sizeof(ALLOWED_DEVICE_HASHES[0]))

// Add known hashes here to make MQTT output readable. Set SHOW_ONLY_KNOWN_DEVICES
// true after adding your PC hash if you only want your own devices in MQTT.
#define SHOW_ONLY_KNOWN_DEVICES false

struct KnownDevice {
    uint32_t hash;
    const char* label;
};

static const KnownDevice KNOWN_DEVICES[] = {
    {0x80465F21, "test_device"},
    {0x1A2F4832, "daniel_pc"},
    {0xBE463ED8, "daniel_phone"},
};
#define NUM_KNOWN_DEVICES (sizeof(KNOWN_DEVICES) / sizeof(KNOWN_DEVICES[0]))

// Proximity filtering. Raise MIN_REPORT_RSSI to only keep closer devices.
#define MAX_PUBLISHED_DEVICES 4
#define MIN_REPORT_RSSI -65
#define SAME_DEVICE_REPORT_INTERVAL_MS 2000
#define REPORT_INTERVAL_MS 10000
#define PUBLISH_BATCH_INTERVAL_MS 10000
#define DEVICE_STALE_AFTER_MS 30000
#define MIN_POSITION_NODES 3
#define MQTT_PACKET_BUFFER_SIZE 1024

// RSSI → distance model:  d = 10 ^ ((TX_POWER - rssi) / (10 * PATH_N))
// Tune TX_POWER and PATH_N by measuring RSSI at known distances in the actual room.
#define TX_POWER  -59.0f   // measured RSSI at 1 m
#define RSSI_DISTANCE_TO_COORD_SCALE 100.0f  // RSSI model returns meters; NODE_POS is in cm
#define PATH_N     2.0f    // path-loss exponent (free space ≈ 2)

// ─── SHARED ──────────────────────────────────────────────────────────────────

struct RssiReport {
    uint8_t  node_id;
    uint32_t mac_hash;  // one-way FNV-1a hash – raw MAC is never transmitted
    int8_t   rssi;
    uint8_t  mac_flags;
};

// FNV-1a: irreversible pseudonym; satisfies GDPR data-minimisation requirement
static uint32_t hashMac(const uint8_t* m) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= m[i]; h *= 16777619u; }
    return h;
}

#define MAC_FLAG_RANDOMIZED 0x01
#define MAC_FLAG_MULTICAST  0x02

static bool isRandomizedMac(const uint8_t* mac) {
    return (mac[0] & 0x02) != 0;
}

static bool isMulticastMac(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

static uint8_t macFlags(const uint8_t* mac) {
    uint8_t flags = 0;
    if (isRandomizedMac(mac)) flags |= MAC_FLAG_RANDOMIZED;
    if (isMulticastMac(mac)) flags |= MAC_FLAG_MULTICAST;
    return flags;
}

static const char* macTypeFromFlags(uint8_t flags) {
    if (flags & MAC_FLAG_MULTICAST) return "multicast";
    if (flags & MAC_FLAG_RANDOMIZED) return "randomized";
    return "vendor";
}

static bool isAllowedDevice(uint32_t hash) {
    if (ALLOW_ALL_DEVICES) return true;
    for (size_t i = 0; i < NUM_ALLOWED_DEVICES; i++) {
        if (ALLOWED_DEVICE_HASHES[i] == 0) continue;
        if (ALLOWED_DEVICE_HASHES[i] == hash) return true;
    }
    return false;
}

static const char* deviceLabel(uint32_t hash) {
    for (size_t i = 0; i < NUM_KNOWN_DEVICES; i++) {
        if (KNOWN_DEVICES[i].hash == hash) return KNOWN_DEVICES[i].label;
    }
    return "unknown";
}

static bool isKnownDevice(uint32_t hash) {
    return strcmp(deviceLabel(hash), "unknown") != 0;
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

static const char* macType(const uint8_t* mac) {
    return macTypeFromFlags(macFlags(mac));
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
    RssiReport r = { NODE_ID, hashMac(mac), (int8_t)pkt->rx_ctrl.rssi, macFlags(mac) };
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
    uint8_t  mac_flags[NUM_NODES];
    bool     seen[NUM_NODES];
    uint32_t node_ts[NUM_NODES];
    uint32_t ts;
    uint32_t count;
};

#define MAX_DEV 20
static Device devs[MAX_DEV];
static int    ndev = 0;

#define COORD_RECENT_DEVICE_COUNT 24
struct CoordRecentDevice {
    uint32_t hash;
    uint32_t last_ms;
};

static CoordRecentDevice coordRecentDevices[COORD_RECENT_DEVICE_COUNT];
static uint32_t coordProbeCount = 0;
static uint32_t coordReportCount = 0;

static bool shouldKeepCoordinatorProbe(uint32_t hash, int8_t rssi) {
    if (rssi < MIN_REPORT_RSSI) return false;

    uint32_t now = millis();
    int empty = -1;
    int oldest = 0;

    for (int i = 0; i < COORD_RECENT_DEVICE_COUNT; i++) {
        if (coordRecentDevices[i].hash == hash) {
            if (now - coordRecentDevices[i].last_ms < SAME_DEVICE_REPORT_INTERVAL_MS) return false;
            coordRecentDevices[i].last_ms = now;
            return true;
        }
        if (coordRecentDevices[i].hash == 0 && empty < 0) empty = i;
        if (coordRecentDevices[i].last_ms < coordRecentDevices[oldest].last_ms) oldest = i;
    }

    int slot = (empty >= 0) ? empty : oldest;
    coordRecentDevices[slot].hash = hash;
    coordRecentDevices[slot].last_ms = now;
    return true;
}

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
    mqtt.setBufferSize(MQTT_PACKET_BUFFER_SIZE);
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

static Device* getDevice(uint32_t hash) {
    for (int i = 0; i < ndev; i++)
        if (devs[i].hash == hash) return &devs[i];
    Device* d = (ndev < MAX_DEV) ? &devs[ndev++] : &devs[0];  // evict first on overflow
    memset(d, 0, sizeof(*d));
    d->hash = hash;
    return d;
}

static void rememberReport(const RssiReport& r) {
    Device* d = getDevice(r.mac_hash);
    d->rssi[r.node_id - 1] = r.rssi;
    d->mac_flags[r.node_id - 1] = r.mac_flags;
    d->seen[r.node_id - 1] = true;
    d->node_ts[r.node_id - 1] = millis();
    d->ts = millis();
    d->count++;
}

static void onRecv(const uint8_t*, const uint8_t* data, int len) {
    Serial.printf("ESP-NOW recv: %d bytes\n", len);
    if (len != sizeof(RssiReport)) { Serial.printf("  bad len (expected %d)\n", sizeof(RssiReport)); return; }
    RssiReport r;
    memcpy(&r, data, sizeof(r));
    Serial.printf("  node=%d hash=%08lX rssi=%d\n", r.node_id, (unsigned long)r.mac_hash, r.rssi);
    if (r.node_id < 1 || r.node_id > NUM_NODES) { Serial.printf("  bad node_id\n"); return; }
    if (!isAllowedDevice(r.mac_hash)) { Serial.printf("  blocked device\n"); return; }
    rememberReport(r);
}

static void coordSniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 24) return;
    if (pkt->payload[0] != 0x40) return;

    coordProbeCount++;
    const uint8_t* mac = pkt->payload + 10;
    RssiReport r = { NODE_ID, hashMac(mac), (int8_t)pkt->rx_ctrl.rssi, macFlags(mac) };
    if (!shouldKeepCoordinatorProbe(r.mac_hash, r.rssi)) return;
    if (!isAllowedDevice(r.mac_hash)) return;

    coordReportCount++;
    rememberReport(r);
}

// Trilateration uses three RSSI-derived distances in the same unit as NODE_POS.
static bool isRecentNode(Device* d, int nodeIndex, uint32_t now) {
    return d->seen[nodeIndex] && now - d->node_ts[nodeIndex] <= DEVICE_STALE_AFTER_MS;
}

struct PositionResult {
    float x;
    float y;
    float dist[NUM_NODES];
    float fit_error;
};

static float rssiToDistance(int8_t rssi) {
    return powf(10.0f, (TX_POWER - rssi) / (10.0f * PATH_N)) * RSSI_DISTANCE_TO_COORD_SCALE;
}

static bool calcTrilateration(Device* d, PositionResult& result, uint32_t now) {
    for (int i = 0; i < NUM_NODES; i++) {
        if (!isRecentNode(d, i, now)) return false;
        result.dist[i] = rssiToDistance(d->rssi[i]);
    }

    const float x1 = NODE_POS[0][0], y1 = NODE_POS[0][1], d1 = result.dist[0];
    const float x2 = NODE_POS[1][0], y2 = NODE_POS[1][1], d2 = result.dist[1];
    const float x3 = NODE_POS[2][0], y3 = NODE_POS[2][1], d3 = result.dist[2];

    const float a = 2.0f * (x2 - x1);
    const float b = 2.0f * (y2 - y1);
    const float c = (d1 * d1) - (d2 * d2) - (x1 * x1) + (x2 * x2) - (y1 * y1) + (y2 * y2);
    const float e = 2.0f * (x3 - x1);
    const float f = 2.0f * (y3 - y1);
    const float g = (d1 * d1) - (d3 * d3) - (x1 * x1) + (x3 * x3) - (y1 * y1) + (y3 * y3);

    const float det = (a * f) - (b * e);
    if (fabsf(det) < 1e-3f) return false;

    result.x = ((c * f) - (b * g)) / det;
    result.y = ((a * g) - (c * e)) / det;

    float totalError = 0.0f;
    for (int i = 0; i < NUM_NODES; i++) {
        const float dx = result.x - NODE_POS[i][0];
        const float dy = result.y - NODE_POS[i][1];
        const float solvedDistance = sqrtf((dx * dx) + (dy * dy));
        totalError += fabsf(solvedDistance - result.dist[i]);
    }
    result.fit_error = totalError / NUM_NODES;
    return true;
}

static int seenNodeCount(Device* d, uint32_t now) {
    int n = 0;
    for (int i = 0; i < NUM_NODES; i++) {
        if (isRecentNode(d, i, now)) n++;
    }
    return n;
}

static int bestRecentRssi(Device* d, uint32_t now) {
    int best = -128;
    for (int i = 0; i < NUM_NODES; i++) {
        if (isRecentNode(d, i, now) && d->rssi[i] > best) best = d->rssi[i];
    }
    return best;
}

static uint8_t bestRecentMacFlags(Device* d, uint32_t now) {
    int best = -128;
    uint8_t flags = 0;
    for (int i = 0; i < NUM_NODES; i++) {
        if (isRecentNode(d, i, now) && d->rssi[i] > best) {
            best = d->rssi[i];
            flags = d->mac_flags[i];
        }
    }
    return flags;
}

static int selectPublishCandidates(uint8_t* indexes, uint32_t now) {
    int count = 0;

    for (int i = 0; i < ndev; i++) {
        if (now - devs[i].ts > DEVICE_STALE_AFTER_MS) continue;
        if (SHOW_ONLY_KNOWN_DEVICES && !isKnownDevice(devs[i].hash)) continue;
        if (seenNodeCount(&devs[i], now) < MIN_POSITION_NODES) continue;
        int candidateRssi = bestRecentRssi(&devs[i], now);
        if (candidateRssi < MIN_REPORT_RSSI) continue;

        int insertAt = count;
        for (int j = 0; j < count; j++) {
            if (candidateRssi > bestRecentRssi(&devs[indexes[j]], now)) {
                insertAt = j;
                break;
            }
        }

        if (insertAt < MAX_PUBLISHED_DEVICES) {
            int limit = (count < MAX_PUBLISHED_DEVICES) ? count : MAX_PUBLISHED_DEVICES - 1;
            for (int j = limit; j > insertAt; j--) {
                indexes[j] = indexes[j - 1];
            }
            indexes[insertAt] = i;
            if (count < MAX_PUBLISHED_DEVICES) count++;
        }
    }

    return count;
}

static bool appendJson(char* buffer, size_t bufferSize, size_t& used, const char* text) {
    size_t len = strlen(text);
    if (used + len >= bufferSize) return false;
    memcpy(buffer + used, text, len + 1);
    used += len;
    return true;
}

static void publishSnifferBatch(const uint8_t* candidates, int candidateCount, const char* timestamp, bool timeSynced, uint32_t now) {
    char results[720];
    size_t used = 0;
    int resultCount = 0;

    results[0] = '\0';

    for (int c = 0; c < candidateCount; c++) {
        Device* d = &devs[candidates[c]];
        for (int node = 0; node < NUM_NODES; node++) {
            if (!isRecentNode(d, node, now)) continue;

            uint8_t flags = d->mac_flags[node];
            char item[220];
            snprintf(
                    item,
                    sizeof(item),
                    "{\"id\":\"%08lX\",\"label\":\"%s\",\"node_id\":%d,\"rssi\":%d,\"received_ms\":%lu,\"mac_type\":\"%s\",\"randomized_mac\":%s}",
                    (unsigned long)d->hash,
                    deviceLabel(d->hash),
                    node + 1,
                    d->rssi[node],
                    (unsigned long)d->node_ts[node],
                    macTypeFromFlags(flags),
                    (flags & MAC_FLAG_RANDOMIZED) ? "true" : "false");

            if (used + strlen(item) + (resultCount > 0 ? 1 : 0) >= sizeof(results)) {
                break;
            }
            if (resultCount > 0) appendJson(results, sizeof(results), used, ",");
            appendJson(results, sizeof(results), used, item);
            resultCount++;
        }
    }

    char payload[MQTT_PACKET_BUFFER_SIZE];
    snprintf(payload, sizeof(payload),
             "{\"type\":\"sniffer_results\",\"timestamp\":\"%s\",\"time_synced\":%s,\"count\":%d,\"results\":[%s]}",
             timestamp,
             timeSynced ? "true" : "false",
             resultCount,
             results);

    publishMqtt(MQTT_SNIFFER_TOPIC, payload);
}

static void publishPositionBatch(const uint8_t* candidates, int candidateCount, const char* timestamp, bool timeSynced, uint32_t now) {
    char positions[720];
    size_t used = 0;
    int positionCount = 0;

    positions[0] = '\0';

    for (int c = 0; c < candidateCount; c++) {
        Device* d = &devs[candidates[c]];
        PositionResult pos;
        if (!calcTrilateration(d, pos, now)) continue;
        uint8_t flags = bestRecentMacFlags(d, now);

        char item[320];
        snprintf(
                item,
                sizeof(item),
                "{\"id\":\"%08lX\",\"label\":\"%s\",\"mac_type\":\"%s\",\"randomized_mac\":%s,\"x\":%.1f,\"y\":%.1f,\"seen_nodes\":%d,\"best_rssi\":%d,\"count\":%lu,\"distances\":[%.1f,%.1f,%.1f],\"fit_error\":%.1f}",
                (unsigned long)d->hash,
                deviceLabel(d->hash),
                macTypeFromFlags(flags),
                (flags & MAC_FLAG_RANDOMIZED) ? "true" : "false",
                pos.x,
                pos.y,
                seenNodeCount(d, now),
                bestRecentRssi(d, now),
                (unsigned long)d->count,
                pos.dist[0],
                pos.dist[1],
                pos.dist[2],
                pos.fit_error);

        if (used + strlen(item) + (positionCount > 0 ? 1 : 0) >= sizeof(positions)) {
            break;
        }
        if (positionCount > 0) appendJson(positions, sizeof(positions), used, ",");
        appendJson(positions, sizeof(positions), used, item);
        positionCount++;
    }

    char payload[MQTT_PACKET_BUFFER_SIZE];
    snprintf(payload, sizeof(payload),
             "{\"type\":\"positions\",\"timestamp\":\"%s\",\"time_synced\":%s,\"count\":%d,\"positions\":[%s]}",
             timestamp,
             timeSynced ? "true" : "false",
             positionCount,
             positions);

    publishMqtt(MQTT_POSITION_TOPIC, payload);
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

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(coordSniffCb);
    Serial.printf("Coordinator also sniffing as node %d on WiFi channel %d\n", NODE_ID, WiFi.channel());
}

void loop() {
    updateNetwork();

    static uint32_t last = 0;
    if (millis() - last < PUBLISH_BATCH_INTERVAL_MS) return;
    last = millis();
    if (!mqttReady()) return;

    uint32_t now = millis();
    char timestamp[32];
    bool timeSynced = getTimestamp(timestamp, sizeof(timestamp));
    uint8_t candidates[MAX_PUBLISHED_DEVICES];
    int candidateCount = selectPublishCandidates(candidates, now);

    publishSnifferBatch(candidates, candidateCount, timestamp, timeSynced, now);
    publishPositionBatch(candidates, candidateCount, timestamp, timeSynced, now);
    Serial.printf("Coordinator probe requests seen: %lu, kept after filters: %lu\n",
                  (unsigned long)coordProbeCount,
                  (unsigned long)coordReportCount);
}

#endif
