#pragma once

#include <Arduino.h>

// Project configuration
//
// This firmware has two build roles:
// - ROLE_SNIFFER listens for WiFi probe requests and sends RSSI reports by ESP-NOW.
// - ROLE_COORDINATOR receives reports, also sniffs locally, and publishes MQTT JSON.
//
// MQTT topics and JSON payload field names are part of the dashboard contract.
// Keep them unchanged unless the dashboard is updated at the same time.

// Flash the coordinator first, read its station MAC from Serial, and paste it here.
static const uint8_t COORDINATOR_MAC_ADDRESS[6] = {0xEC, 0x64, 0xC9, 0x85, 0xF5, 0x8C};

// ESP-NOW and promiscuous sniffing must use the same channel as the WiFi AP.
static const uint8_t SNIFFER_CHANNEL = 2;

// Each measuring ESP32 gets a unique node id from 1..NUMBER_OF_NODES.
// With three boards total, the coordinator also sniffs as node 3.
#ifndef NODE_ID
#define NODE_ID 3
#endif

static const float NODE_POSITIONS_CM[][2] = {
    {64.0f, 0.0f},
    {-32.0f, 55.4f},
    {-32.0f, -55.4f},
};
#define NUMBER_OF_NODES 3

#if NODE_ID < 1 || NODE_ID > NUMBER_OF_NODES
#error "NODE_ID must be between 1 and NUMBER_OF_NODES"
#endif

// Coordinator WiFi and MQTT settings.
#define WIFI_SSID "IoT_H3/4"
#define WIFI_PASS "98806829"
#define MQTT_HOST "wilsons.local"
#define MQTT_PORT 8883
#define DEVICE_ID "device07"
#define MQTT_USER "device07"
#define MQTT_PASS "madTdHrb"
#define MQTT_BASE_TOPIC "/devices/device07"
#define MQTT_SNIFFER_TOPIC MQTT_BASE_TOPIC "/sniffer_results"
#define MQTT_POSITION_TOPIC MQTT_BASE_TOPIC "/positions"

// Keep true for iPhone/demo proximity mode. iPhones randomize probe MACs, so a
// static hash allow-list only works reliably for devices with stable MACs.
static const bool ALLOW_ALL_DEVICES = true;

// Proximity and publishing filters. Raising MIN_REPORT_RSSI keeps only closer devices.
static const uint8_t MAX_PUBLISHED_DEVICES = 4;
static const int8_t MIN_REPORT_RSSI = -65;
static const uint32_t SAME_DEVICE_REPORT_INTERVAL_MS = 2000;
static const uint32_t REPORT_INTERVAL_MS = 10000;
static const uint32_t PUBLISH_BATCH_INTERVAL_MS = 10000;
static const uint32_t DEVICE_STALE_AFTER_MS = 30000;
static const uint8_t MIN_POSITION_NODES = 3;
static const size_t MQTT_PACKET_BUFFER_SIZE = 1024;

// RSSI to distance model:
//   distance = 10 ^ ((TX_POWER_AT_ONE_METER - rssi) / (10 * PATH_LOSS_EXPONENT))
//
// The formula returns meters. The coordinate system above is in centimeters, so
// RSSI_DISTANCE_TO_COORDINATE_SCALE converts the estimate before trilateration.
static const float TX_POWER_AT_ONE_METER = -59.0f;
static const float RSSI_DISTANCE_TO_COORDINATE_SCALE = 100.0f;
static const float PATH_LOSS_EXPONENT = 2.0f;

struct KnownDevice {
    uint32_t hash;
    const char* label;
};

// Add allowed device hashes here after discovering them from the sniffer Serial output.
static const uint32_t ALLOWED_DEVICE_HASHES[] = {
    0x80465F21,
    // 0x782C50E5,
    // 0x5851599B,
};
static const size_t NUMBER_OF_ALLOWED_DEVICE_HASHES =
    sizeof(ALLOWED_DEVICE_HASHES) / sizeof(ALLOWED_DEVICE_HASHES[0]);

// Add known hashes here to make MQTT output readable. Set SHOW_ONLY_KNOWN_DEVICES
// true after adding your PC hash if you only want your own devices in MQTT.
static const bool SHOW_ONLY_KNOWN_DEVICES = false;

static const KnownDevice KNOWN_DEVICES[] = {
    {0x80465F21, "test_device"},
    {0x1A2F4832, "daniel_pc"},
    {0xBE463ED8, "daniel_phone"},
};
static const size_t NUMBER_OF_KNOWN_DEVICES = sizeof(KNOWN_DEVICES) / sizeof(KNOWN_DEVICES[0]);
