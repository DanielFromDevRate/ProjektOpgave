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

#define MQTT_TOPIC  "devices/device07/position"

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
#define TX_POWER  -59.0f
#define PATH_N     2.0f

// ─── SHARED ──────────────────────────────────────────────────────────────────

struct RssiReport {
    uint8_t  node_id;
    uint32_t mac_hash;
    int8_t   rssi;
};

// FNV-1a hash
static uint32_t hashMac(const uint8_t* m) {

    uint32_t h = 2166136261u;

    for (int i = 0; i < 6; i++) {

        h ^= m[i];
        h *= 16777619u;
    }

    return h;
}

static bool isAllowedDevice(uint32_t hash) {

    if (ALLOW_ALL_DEVICES)
        return true;

    for (size_t i = 0; i < NUM_ALLOWED_DEVICES; i++) {

        if (ALLOWED_DEVICE_HASHES[i] == 0)
            continue;

        if (ALLOWED_DEVICE_HASHES[i] == hash)
            return true;
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////
// SNIFFER
///////////////////////////////////////////////////////////////////////////////

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

static bool shouldReportDevice(
    uint32_t hash,
    int8_t rssi
) {

    if (rssi < MIN_REPORT_RSSI)
        return false;

    uint32_t now = millis();

    int empty = -1;
    int oldest = 0;

    for (int i = 0; i < RECENT_DEVICE_COUNT; i++) {

        if (recentDevices[i].hash == hash) {

            if (
                now - recentDevices[i].last_ms <
                SAME_DEVICE_REPORT_INTERVAL_MS
            ) {
                return false;
            }

            recentDevices[i].last_ms = now;

            return true;
        }

        if (
            recentDevices[i].hash == 0 &&
            empty < 0
        ) {
            empty = i;
        }

        if (
            recentDevices[i].last_ms <
            recentDevices[oldest].last_ms
        ) {
            oldest = i;
        }
    }

    int slot =
        (empty >= 0) ? empty : oldest;

    recentDevices[slot].hash = hash;
    recentDevices[slot].last_ms = now;

    return true;
}

static void sniffCb(
    void* buf,
    wifi_promiscuous_pkt_type_t type
) {

    if (type != WIFI_PKT_MGMT)
        return;

    auto* pkt =
        (wifi_promiscuous_pkt_t*)buf;

    if (pkt->rx_ctrl.sig_len < 24)
        return;

    if (pkt->payload[0] != 0x40)
        return;

    probeCount++;

    const uint8_t* mac =
        pkt->payload + 10;

    RssiReport r = {
        NODE_ID,
        hashMac(mac),
        (int8_t)pkt->rx_ctrl.rssi
    };

    if (!shouldReportDevice(r.mac_hash, r.rssi))
        return;

    if (!isAllowedDevice(r.mac_hash))
        return;

    reportCount++;

    esp_now_send(
        COORD_MAC,
        (uint8_t*)&r,
        sizeof(r)
    );

    Serial.printf(
        "HASH=%08lX RSSI=%d\n",
        (unsigned long)r.mac_hash,
        r.rssi
    );
}

void setup() {

    Serial.begin(115200);

    delay(500);

    Serial.printf(
        "Sniffer node %d starting on channel %d\n",
        NODE_ID,
        SNIFFER_CHANNEL
    );

    WiFi.mode(WIFI_STA);

    esp_wifi_set_channel(
        SNIFFER_CHANNEL,
        WIFI_SECOND_CHAN_NONE
    );

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

    if (
        millis() - last >
        REPORT_INTERVAL_MS
    ) {

        last = millis();

        Serial.printf(
            "Probe requests: %lu  Sent: %lu\n",
            (unsigned long)probeCount,
            (unsigned long)reportCount
        );
    }
}

///////////////////////////////////////////////////////////////////////////////
// COORDINATOR
///////////////////////////////////////////////////////////////////////////////

#elif defined(ROLE_COORDINATOR)

#include <WiFiClientSecure.h>
#include <PubSubClient.h>

#include <math.h>
#include <time.h>

static WiFiClientSecure wc;
static PubSubClient mqtt(wc);

static bool getTimestamp(
    char* buf,
    size_t len,
    uint32_t timeoutMs = 100
) {

    struct tm timeinfo;

    if (getLocalTime(&timeinfo, timeoutMs)) {

        strftime(
            buf,
            len,
            "%Y-%m-%dT%H:%M:%S%z",
            &timeinfo
        );

        return true;
    }

    snprintf(
        buf,
        len,
        "uptime:%lu",
        (unsigned long)millis()
    );

    return false;
}

struct Device {

    uint32_t hash;

    int8_t rssi[NUM_NODES];

    bool seen[NUM_NODES];

    uint32_t ts;

    uint32_t count;
};

#define MAX_DEV 20

static Device devs[MAX_DEV];

static int ndev = 0;

static Device* getDevice(uint32_t hash) {

    for (int i = 0; i < ndev; i++) {

        if (devs[i].hash == hash)
            return &devs[i];
    }

    Device* d =
        (ndev < MAX_DEV)
        ? &devs[ndev++]
        : &devs[0];

    memset(d, 0, sizeof(*d));

    d->hash = hash;

    return d;
}

static void onRecv(
    const uint8_t*,
    const uint8_t* data,
    int len
) {

    Serial.printf(
        "ESP-NOW recv: %d bytes\n",
        len
    );

    if (len != sizeof(RssiReport)) {

        Serial.printf(
            "bad len (expected %d)\n",
            sizeof(RssiReport)
        );

        return;
    }

    RssiReport r;

    memcpy(&r, data, sizeof(r));

    Serial.printf(
        "node=%d hash=%08lX rssi=%d\n",
        r.node_id,
        (unsigned long)r.mac_hash,
        r.rssi
    );

    if (
        r.node_id < 1 ||
        r.node_id > NUM_NODES
    ) {
        return;
    }

    if (!isAllowedDevice(r.mac_hash))
        return;

    Device* d =
        getDevice(r.mac_hash);

    d->rssi[r.node_id - 1] =
        r.rssi;

    d->seen[r.node_id - 1] =
        true;

    d->ts = millis();

    d->count++;
}

// Weighted centroid
static bool calcPos(
    Device* d,
    float& x,
    float& y
) {

    float sw = 0;
    float sx = 0;
    float sy = 0;

    int n = 0;

    for (int i = 0; i < NUM_NODES; i++) {

        if (!d->seen[i])
            continue;

        float dist = powf(
            10.0f,
            (TX_POWER - d->rssi[i]) /
            (10.0f * PATH_N)
        );

        float w =
            1.0f /
            (dist * dist + 1e-4f);

        sx += w * NODE_POS[i][0];

        sy += w * NODE_POS[i][1];

        sw += w;

        n++;
    }

    if (n < 1 || sw == 0.0f)
        return false;

    x = sx / sw;
    y = sy / sw;

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// SETUP
///////////////////////////////////////////////////////////////////////////////

void setup() {

    Serial.begin(115200);

    delay(500);

    Serial.println("Connecting to WiFi...");

    WiFi.begin(
        WIFI_SSID,
        WIFI_PASS
    );

    while (WiFi.status() != WL_CONNECTED) {

        Serial.print('.');

        delay(500);
    }

    Serial.printf(
        "\nWiFi OK  IP: %s  MAC: %s  Channel: %d\n",
        WiFi.localIP().toString().c_str(),
        WiFi.macAddress().c_str(),
        WiFi.channel()
    );

    //////////////////////////////////////////////////
    // TIME
    //////////////////////////////////////////////////

    setenv(
        "TZ",
        "CET-1CEST,M3.5.0/2,M10.5.0/3",
        1
    );

    tzset();

    configTime(
        0,
        0,
        "pool.ntp.org",
        "time.nist.gov"
    );

    char timestamp[32];

    getTimestamp(
        timestamp,
        sizeof(timestamp),
        5000
    );

    Serial.printf(
        "Time: %s\n",
        timestamp
    );

    //////////////////////////////////////////////////
    // ESP NOW
    //////////////////////////////////////////////////

    esp_now_init();

    esp_now_register_recv_cb(onRecv);

    Serial.println("ESP-NOW OK");

    //////////////////////////////////////////////////
    // MQTT
    //////////////////////////////////////////////////

    wc.setInsecure();

    mqtt.setServer(
        MQTT_HOST,
        MQTT_PORT
    );

    Serial.printf(
        "MQTT connecting to %s:%d...\n",
        MQTT_HOST,
        MQTT_PORT
    );

    bool mqttConnected =
        mqtt.connect(
            DEVICE_ID,
            MQTT_USER,
            MQTT_PASS
        );

    if (mqttConnected) {

        Serial.println("MQTT OK");

        bool ok =
            mqtt.publish(
                "test/topic",
                "HELLO_FROM_ESP32"
            );

        Serial.print(
            "TEST PUBLISH: "
        );

        Serial.println(ok);
    }
    else {

        Serial.printf(
            "MQTT FAILED state=%d\n",
            mqtt.state()
        );
    }
}

///////////////////////////////////////////////////////////////////////////////
// LOOP
///////////////////////////////////////////////////////////////////////////////

void loop() {

    //////////////////////////////////////////////////
    // MQTT RECONNECT
    //////////////////////////////////////////////////

    if (!mqtt.connected()) {

        static uint32_t lastRetry = 0;

        if (
            millis() - lastRetry >
            5000
        ) {

            lastRetry = millis();

            Serial.printf(
                "MQTT reconnecting... state=%d\n",
                mqtt.state()
            );

            bool ok =
                mqtt.connect(
                    DEVICE_ID,
                    MQTT_USER,
                    MQTT_PASS
                );

            if (ok) {

                Serial.println(
                    "MQTT RECONNECTED"
                );

                mqtt.publish(
                    "test/topic",
                    "RECONNECTED"
                );
            }
            else {

                Serial.printf(
                    "MQTT reconnect failed state=%d\n",
                    mqtt.state()
                );
            }
        }
    }

    mqtt.loop();

    //////////////////////////////////////////////////
    // SEND MQTT DATA
    //////////////////////////////////////////////////

    static uint32_t last = 0;

    if (
        millis() - last <
        REPORT_INTERVAL_MS
    ) {
        return;
    }

    last = millis();

    char buf[256];

    char timestamp[32];

    uint32_t now = millis();

    bool timeSynced =
        getTimestamp(
            timestamp,
            sizeof(timestamp)
        );

    for (int i = 0; i < ndev; i++) {

        if (
            now - devs[i].ts >
            30000
        ) {
            continue;
        }

        float x;
        float y;

        if (!calcPos(&devs[i], x, y))
            continue;

        snprintf(
            buf,
            sizeof(buf),
            "{\"id\":\"%08lX\",\"timestamp\":\"%s\",\"time_synced\":%s,\"uptime_ms\":%lu,\"last_seen_ms\":%lu,\"count\":%lu,\"x\":%.1f,\"y\":%.1f}",
            (unsigned long)devs[i].hash,
            timestamp,
            timeSynced ? "true" : "false",
            (unsigned long)now,
            (unsigned long)devs[i].ts,
            (unsigned long)devs[i].count,
            x,
            y
        );

        bool ok =
            mqtt.publish(
                MQTT_TOPIC,
                buf
            );

        Serial.printf(
            "[MQTT] Publish %s %s %s\n",
            ok ? "OK" : "FAILED",
            MQTT_TOPIC,
            buf
        );
    }
}

#endif