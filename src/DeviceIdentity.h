#pragma once

#include <Arduino.h>

static const uint8_t MAC_FLAG_RANDOMIZED = 0x01;
static const uint8_t MAC_FLAG_MULTICAST = 0x02;

uint32_t hashMacAddress(const uint8_t* macAddress);
uint8_t macAddressFlags(const uint8_t* macAddress);
const char* macTypeFromFlags(uint8_t flags);
bool isRandomizedMacAddress(const uint8_t* macAddress);
bool isAllowedDevice(uint32_t deviceHash);
bool isKnownDevice(uint32_t deviceHash);
const char* deviceLabel(uint32_t deviceHash);
