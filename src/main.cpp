#include <Arduino.h>

#if defined(ROLE_SNIFFER)
#include "SnifferNode.h"
#elif defined(ROLE_COORDINATOR)
#include "CoordinatorNode.h"
#endif

void setup() {
#if defined(ROLE_SNIFFER)
    SnifferNode::Setup();
#elif defined(ROLE_COORDINATOR)
    CoordinatorNode::Setup();
#endif
}

void loop() {
#if defined(ROLE_SNIFFER)
    SnifferNode::Loop();
#elif defined(ROLE_COORDINATOR)
    CoordinatorNode::Loop();
#endif
}
