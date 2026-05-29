#pragma once

#include "SharedTypes.h"

bool nodeReportIsRecent(TrackedDevice* device, int nodeIndex, uint32_t now);
float rssiToDistanceCentimeters(int8_t rssi);
bool calculateTrilateration(TrackedDevice* device, PositionResult& result, uint32_t now);
int recentNodeCount(TrackedDevice* device, uint32_t now);
int bestRecentRssi(TrackedDevice* device, uint32_t now);
uint8_t bestRecentMacFlags(TrackedDevice* device, uint32_t now);
