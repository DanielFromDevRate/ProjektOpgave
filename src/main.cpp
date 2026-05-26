#include <Arduino.h>

#if defined(ROLE_SNIFFER)
#include "Sniffer.h"
#elif defined(ROLE_COORDINATOR)
#include "Coordinator.h"
#endif

void setup() {
#if defined(ROLE_SNIFFER)
    setupSniffer();
#elif defined(ROLE_COORDINATOR)
    setupCoordinator();
#endif
}

void loop() {
#if defined(ROLE_SNIFFER)
    loopSniffer();
#elif defined(ROLE_COORDINATOR)
    loopCoordinator();
#endif
}
