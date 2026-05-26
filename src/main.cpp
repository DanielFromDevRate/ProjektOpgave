#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

// ─── CONFIG (edit before flashing) ───────────────────────────────────────────

// Coordinator MAC – flash coordinator first, read MAC from Serial, paste here
static const uint8_t COORD_MAC[6] = {0xCC, 0xDB, 0xA7, 0x1E, 0x07, 0x64};

// Sniffer channel must match the WiFi AP channel the coordinator connects to
#define SNIFFER_CHANNEL 2

// Each sniffer gets a unique NODE_ID (1..NUM_NODES); coordinator uses 0
#define NODE_ID 2

// 2-D positions of sniffer nodes in cm, index = NODE_ID - 1
static const float NODE_POS[][2] = {
    {   0,   0 },  // node 1 — reference corner
    { 100,   0 },  // node 2 — measure distance from node 1 along X axis
};
#define NUM_NODES 2

// Coordinator WiFi / MQTT
#define WIFI_SSID   "IoT_H3/4"
#define WIFI_PASS   "98806829"
#define MQTT_HOST   "wilsons.local"
#define MQTT_PORT   8883
#define DEVICE_ID   "device07"
#define MQTT_USER   "device07"
#define MQTT_PASS   "madTdHrb"
#define MQTT_TOPIC  "devices/device07/position"

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

// ═══════════════════════════ SNIFFER ═════════════════════════════════════════
#ifdef ROLE_SNIFFER

static esp_now_peer_info_t peer;

static uint32_t probeCount = 0;

static void sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 24) return;
    if (pkt->payload[0] != 0x40) return;  // probe requests only (subtype 0100)

    probeCount++;
    // Source MAC is at byte offset 10 in the 802.11 management frame header
    RssiReport r = { NODE_ID, hashMac(pkt->payload + 10), (int8_t)pkt->rx_ctrl.rssi };
    esp_now_send(COORD_MAC, (uint8_t*)&r, sizeof(r));
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("Sniffer node %d starting on channel %d\n", NODE_ID, SNIFFER_CHANNEL);

    WiFi.mode(WIFI_STA);  // STA mode but do not connect – channel is ours to set
    esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);

    esp_now_init();
    memcpy(peer.peer_addr, COORD_MAC, 6);
    peer.channel = SNIFFER_CHANNEL;
    peer.encrypt = false;
    esp_now_add_peer(&peer);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffCb);
    Serial.println("Listening for probe requests...");
}

void loop() {
    static uint32_t last = 0;
    if (millis() - last > 3000) {
        last = millis();
        Serial.printf("Probe requests seen: %lu\n", (unsigned long)probeCount);
    }
}

// ══════════════════════════ COORDINATOR ══════════════════════════════════════
#elif defined(ROLE_COORDINATOR)

#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <math.h>

static WiFiClientSecure wc;
static PubSubClient     mqtt(wc);

struct Device {
    uint32_t hash;
    int8_t   rssi[NUM_NODES];
    bool     seen[NUM_NODES];
    uint32_t ts;
};

#define MAX_DEV 20
static Device devs[MAX_DEV];
static int    ndev = 0;

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
    Device* d = getDevice(r.mac_hash);
    d->rssi[r.node_id - 1] = r.rssi;
    d->seen[r.node_id - 1] = true;
    d->ts = millis();
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

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("Connecting to WiFi...");
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) { Serial.print('.'); delay(500); }
    Serial.printf("\nWiFi OK  IP: %s  MAC: %s  Channel: %d\n",
                  WiFi.localIP().toString().c_str(),
                  WiFi.macAddress().c_str(), WiFi.channel());

    esp_now_init();
    esp_now_register_recv_cb(onRecv);
    Serial.println("ESP-NOW OK");

    wc.setInsecure();  // TLS without certificate verification
    mqtt.setServer(MQTT_HOST, MQTT_PORT);
    Serial.printf("MQTT connecting to %s:%d...\n", MQTT_HOST, MQTT_PORT);
    if (mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS))
        Serial.println("MQTT OK");
    else
        Serial.printf("MQTT FAILED state=%d\n", mqtt.state());
}

void loop() {
    if (!mqtt.connected()) {
        static uint32_t lastRetry = 0;
        if (millis() - lastRetry > 5000) {
            lastRetry = millis();
            Serial.printf("MQTT reconnecting... state=%d\n", mqtt.state());
            mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS);
        }
    }
    mqtt.loop();

    static uint32_t last = 0;
    if (millis() - last < 2000) return;
    last = millis();

    char buf[128];
    uint32_t now = millis();
    for (int i = 0; i < ndev; i++) {
        if (now - devs[i].ts > 10000) continue;  // discard stale entries (>10 s)
        float x, y;
        if (!calcPos(&devs[i], x, y)) continue;
        snprintf(buf, sizeof(buf),
            "{\"id\":\"%08lX\",\"ts\":%lu,\"x\":%.1f,\"y\":%.1f}",
            (unsigned long)devs[i].hash, (unsigned long)now, x, y);
        bool ok = mqtt.publish(MQTT_TOPIC, buf);
        Serial.printf("[MQTT] Publish %s %s %s\n", ok ? "OK" : "FAILED", MQTT_TOPIC, buf);
    }
}

#endif
