#include "Positioning.h"

#include <math.h>

bool nodeReportIsRecent(TrackedDevice* device, int nodeIndex, uint32_t now) {
    return device->seenByNode[nodeIndex] &&
           now - device->nodeReceivedMs[nodeIndex] <= DEVICE_STALE_AFTER_MS;
}

float rssiToDistanceCentimeters(int8_t rssi) {
    return powf(
        10.0f,
        (TX_POWER_AT_ONE_METER - rssi) / (10.0f * PATH_LOSS_EXPONENT)
    ) * RSSI_DISTANCE_TO_COORDINATE_SCALE;
}

// Trilateration solves the intersection point of three RSSI-derived circles.
// RSSI is noisy, so fitError is published to show how well that point matches
// the three measured distances.
bool calculateTrilateration(TrackedDevice* device, PositionResult& result, uint32_t now) {
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
        if (!nodeReportIsRecent(device, i, now)) {
            return false;
        }
        result.distanceFromNode[i] = rssiToDistanceCentimeters(device->rssi[i]);
    }

    const float firstNodeX = NODE_POSITIONS_CM[0][0];
    const float firstNodeY = NODE_POSITIONS_CM[0][1];
    const float distanceToFirstNode = result.distanceFromNode[0];
    const float secondNodeX = NODE_POSITIONS_CM[1][0];
    const float secondNodeY = NODE_POSITIONS_CM[1][1];
    const float distanceToSecondNode = result.distanceFromNode[1];
    const float thirdNodeX = NODE_POSITIONS_CM[2][0];
    const float thirdNodeY = NODE_POSITIONS_CM[2][1];
    const float distanceToThirdNode = result.distanceFromNode[2];

    // Subtracting the first distance circle from the second and third circles
    // turns the three-circle problem into two straight-line equations:
    //   firstLineX * x + firstLineY * y = firstLineRightSide
    //   secondLineX * x + secondLineY * y = secondLineRightSide
    const float firstLineX = 2.0f * (secondNodeX - firstNodeX);
    const float firstLineY = 2.0f * (secondNodeY - firstNodeY);
    const float firstLineRightSide =
        (distanceToFirstNode * distanceToFirstNode) -
        (distanceToSecondNode * distanceToSecondNode) -
        (firstNodeX * firstNodeX) +
        (secondNodeX * secondNodeX) -
        (firstNodeY * firstNodeY) +
        (secondNodeY * secondNodeY);

    const float secondLineX = 2.0f * (thirdNodeX - firstNodeX);
    const float secondLineY = 2.0f * (thirdNodeY - firstNodeY);
    const float secondLineRightSide =
        (distanceToFirstNode * distanceToFirstNode) -
        (distanceToThirdNode * distanceToThirdNode) -
        (firstNodeX * firstNodeX) +
        (thirdNodeX * thirdNodeX) -
        (firstNodeY * firstNodeY) +
        (thirdNodeY * thirdNodeY);

    const float determinant = (firstLineX * secondLineY) - (firstLineY * secondLineX);
    if (fabsf(determinant) < 1e-3f) {
        return false;
    }

    result.x = ((firstLineRightSide * secondLineY) - (firstLineY * secondLineRightSide)) / determinant;
    result.y = ((firstLineX * secondLineRightSide) - (firstLineRightSide * secondLineX)) / determinant;

    float totalFitError = 0.0f;
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
        const float xDelta = result.x - NODE_POSITIONS_CM[i][0];
        const float yDelta = result.y - NODE_POSITIONS_CM[i][1];
        const float solvedDistance = sqrtf((xDelta * xDelta) + (yDelta * yDelta));
        totalFitError += fabsf(solvedDistance - result.distanceFromNode[i]);
    }
    result.fitError = totalFitError / NUMBER_OF_NODES;
    return true;
}

int recentNodeCount(TrackedDevice* device, uint32_t now) {
    int count = 0;
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
        if (nodeReportIsRecent(device, i, now)) {
            count++;
        }
    }
    return count;
}

int bestRecentRssi(TrackedDevice* device, uint32_t now) {
    int bestRssi = -128;
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
        if (nodeReportIsRecent(device, i, now) && device->rssi[i] > bestRssi) {
            bestRssi = device->rssi[i];
        }
    }
    return bestRssi;
}

uint8_t bestRecentMacFlags(TrackedDevice* device, uint32_t now) {
    int bestRssi = -128;
    uint8_t flags = 0;

    for (int i = 0; i < NUMBER_OF_NODES; i++) {
        if (nodeReportIsRecent(device, i, now) && device->rssi[i] > bestRssi) {
            bestRssi = device->rssi[i];
            flags = device->macFlags[i];
        }
    }
    return flags;
}
