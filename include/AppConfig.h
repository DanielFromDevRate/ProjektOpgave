#pragma once

#include <Arduino.h>

#include "Secrets.h"

// Coordinator MAC - flash coordinator first, read MAC from Serial, paste here.
static const uint8_t COORD_MAC[6] = {0xEC, 0x64, 0xC9, 0x85, 0xF5, 0x8C};

// Sniffer channel must match the WiFi AP channel the coordinator connects to.
#define SNIFFER_CHANNEL 2

// Each sniffer gets a unique NODE_ID (1..NUM_NODES); coordinator uses 0.
#define NODE_ID 3

static const float NODE_POS[][2] = {
    {  0,  0 },
    {100,  0 },
    { 50, 87 },
};
#define NUM_NODES 3

// Coordinator MQTT topics.
#define MQTT_SNIFFER_TOPIC    MQTT_BASE_TOPIC "/sniffer_result"
#define MQTT_POSITION_TOPIC   MQTT_BASE_TOPIC "/position"

// Keep true while discovering devices. Set false after filling ALLOWED_DEVICE_HASHES.
#define ALLOW_ALL_DEVICES true

// Add allowed device hashes here after discovering them from the sniffer Serial output.
static const uint32_t ALLOWED_DEVICE_HASHES[] = {
    0,
    // 0x782C50E5,
    // 0x5851599B,
};
#define NUM_ALLOWED_DEVICES (sizeof(ALLOWED_DEVICE_HASHES) / sizeof(ALLOWED_DEVICE_HASHES[0]))

// Sniffer noise filtering. Raise MIN_REPORT_RSSI to only keep closer devices.
#define MIN_REPORT_RSSI -75
#define SAME_DEVICE_REPORT_INTERVAL_MS 2000
#define REPORT_INTERVAL_MS 10000

// RSSI to distance model: d = 10 ^ ((TX_POWER - rssi) / (10 * PATH_N)).
#define TX_POWER  -59.0f
#define PATH_N      2.0f
