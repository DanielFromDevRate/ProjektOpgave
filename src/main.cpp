#include <Arduino.h>

#include "CoordinatorRole.h"
#include "SnifferRole.h"

void setup() {
#ifdef ROLE_SNIFFER
    setupSnifferRole();
#elif defined(ROLE_COORDINATOR)
    setupCoordinatorRole();
#else
#error "Build must define ROLE_SNIFFER or ROLE_COORDINATOR"
#endif
}

void loop() {
#ifdef ROLE_SNIFFER
    loopSnifferRole();
#elif defined(ROLE_COORDINATOR)
    loopCoordinatorRole();
#endif
}
