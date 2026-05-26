#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <Arduino.h>

// Coordinator MAC. Flash the coordinator first, read its MAC from Serial, then paste it here.
static const uint8_t COORDINATOR_MAC[6] = {0xEC, 0x64, 0xC9, 0x85, 0xF5, 0x8C};

// The sniffer channel must match the WiFi AP channel used by the coordinator.
#define SNIFFER_CHANNEL 2

// Each sniffer gets a unique NODE_ID from 1..NUM_NODES. The coordinator uses 0.
// PlatformIO environments set this for repeatable flashing of multiple sniffers.
#ifndef NODE_ID
#define NODE_ID 1
#endif

static const float NODE_POSITIONS[][2] = {
    {  0,  0 },
    {100,  0 },
    { 50, 87 },
};
#define NUM_NODES 3

#if defined(ROLE_SNIFFER) && (NODE_ID < 1 || NODE_ID > NUM_NODES)
#error "Sniffer NODE_ID must be between 1 and NUM_NODES"
#endif

// Coordinator WiFi and MQTT settings.
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

static const uint32_t ALLOWED_DEVICE_HASHES[] = {
    0,
    // 0x782C50E5,
    // 0x5851599B,
};
#define NUM_ALLOWED_DEVICES (sizeof(ALLOWED_DEVICE_HASHES) / sizeof(ALLOWED_DEVICE_HASHES[0]))

// Sniffer noise filtering. Raise MIN_REPORT_RSSI to keep only closer devices.
#define MIN_REPORT_RSSI -75
#define SAME_DEVICE_REPORT_INTERVAL_MS 2000
#define REPORT_INTERVAL_MS 10000
#define NODE_OBSERVATION_STALE_AFTER_MS 15000

// RSSI to distance model: d = 10 ^ ((TX_POWER - rssi) / (10 * PATH_LOSS_EXPONENT))
#define TX_POWER  -59.0f
#define PATH_LOSS_EXPONENT 2.0f

#endif
