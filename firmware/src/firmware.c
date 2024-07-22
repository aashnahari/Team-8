// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

//Monday July 22 --> editing this to make a "version 3" to test the updater

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <string.h>

#define VERSION_3
#include "mitre_car.h"
#include "uart/uart.h"
#include "usart.h"
#include "util.h"

static const char * FLAG_RESPONSE = "Nice try.";
static const char * VERSION_RESPONSE = "Firmware Version 3";
static const char * TEST_RESPONSE = "I think the firmware is updated???";

void getFlag(char * flag) {
    flag = strcpy(flag, FLAG_RESPONSE);
}

void getVersion(char * version) {
    version = strcpy(version, VERSION_RESPONSE);
}

void getTest(char * test) {
    test = strcpy(test, TEST_RESPONSE);
}

int main(void) __attribute__((section(".text.main")));
int main(void) {
    printBanner();
    for (;;) // Loop forever.
    {
        char buff[256];
        int len = prompt(buff, 256);
        if (buff[0] != '\0' && strncmp(buff, "FLAG", len) == 0) {
            getFlag(buff);
            writeLine(buff);
        }else if (buff[0] != '\0' && strncmp(buff, "TEST", len) == 0){
            getTest(buff);
            writeLine(buff);
        }
    }
}
