// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.
//changes

#include "bootloader.h"
#include "header.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 512
#define FLASH_WRITESIZE 4
#define MESSAGE_SIZE 1024
#define SIGNATURE_SIZE 32
#define IV_SIZE 16

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Frame Buffers
unsigned char encrypted_data[FLASH_PAGESIZE];
unsigned char unencrypted_data[FLASH_PAGESIZE];
unsigned char message[MESSAGE_SIZE];
unsigned char signature[SIGNATURE_SIZE];
unsigned char iv[IV_SIZE];


// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}

// apparently this doesn't even work so may need to update/change this whenever its resolved

void disableDebugging(void){

// Write the unlock value to the flash memory protection registers
HWREG(FLASH_FMPRE0) = 0xFFFFFFFF;
HWREG(FLASH_FMPPE0) = 0xFFFFFFFF;

// Disable the debug interface by writing to the FMD and FMC registers
HWREG(FLASH_FMD) = 0xA4420004;
HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;
}

int main(void) {
    disableDebugging();

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "\nHmmm..we're booting firmware...\n");
            boot_firmware();
        }
    }
}


 /*
 * Load the firmware into flash.
 */



/// ------------------------------------------------------------------- CHANGES
bool verify_hmac(uint8_t *sig, uint8_t *ky, uint8_t *msg){   //function for hmac verifying
    uint8_t hmac_result[WC_MAX_DIGEST_SIZE];
    Hmac hmac;
    wc_HmacInit(&hmac);
    if (wc_HmacSetKey(&hmac, WC_SHA256, ky, 32) != 0){
        perror("wc_HmacSetKey failed");
        return false;
        
    }
    if (wc_HmacUpdate(&hmac, msg, sizeof(msg)) != 0){
        perror("wc_HmacUpdate failed");
        return false;
    }

    if (wc_HmacFinal(&hmac, hmac_result) != 0) {
        perror("wc_HmacFinal failed");
        return false;
    }

    int hmac_len = wc_HmacGetSize(&hmac);
    if (sizeof(sig) != hmac_len || memcmp(hmac_result, sig, hmac_len) != 0) {
        return false;
    }  

    return true;
}
/// ------------------------------------------------------------------- CHANGES





void load_firmware(void) {
    int frame_length = 0;
    int status = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;
/// ------------------------------------------------------------------- CHANGES
//GET HMAC KEY FROM HEADER FILE
    char verify_key[] = "temp_key";

//READING FRAME 0 (VERSION_FRAME)

    // Get version.
    rcv = uart_read(UART0, BLOCKING, &status);
    version = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &status);
    version |= (uint32_t)rcv << 8;

    // Get size (overall of firmware).
    rcv = uart_read(UART0, BLOCKING, &status);
    size = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &status);
    size |= (uint32_t)rcv << 8;

    for (int j = 0; j < MESSAGE_SIZE; ++j) {
        message[j] = uart_read(UART0, BLOCKING, &status);
    }

    for (int k = 0; k < SIGNATURE_SIZE; ++k){
        signature[k] = uart_read(UART0, BLOCKING, &status);
    }
     //Verifying hmac signature for firmware data frames
    if (verify_hmac(signature, verify_key, message) == false){
        SysCtlReset();
    }


    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }
    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }


// WRITE INFO TO FLASH!!!
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);
    //also writing message to flash
    program_flash((uint8_t *)(METADATA_BASE + 4), message, MESSAGE_SIZE);

    uart_write(UART0, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
//NEED TO FIX BASED ON HOW WE ACCESS THE HEADER
    // Opens secret key file
    FILE* key_file_ptr;
    key_file_ptr = fopen('./secret_build_output.txt', 'r');

    // Init AES to use, configure (read key from file)
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    char aes_encrypted_key[256];
    char aes_key[32];
    fgets(aes_encrypted_key, sizeof(aes_key), key_file_ptr);

    // Init RSA to use, configure (read key from file)
    RsaKey rsa_private_key;
    wc_InitRsaKey(&rsaKey, NULL);
    char hmac_key_buf[32];
    char rsa_private_key_buf[256];
    fgets(hmac_key_buf, sizeof(hmac_key_buf), key_file_ptr); // done to move file pointer to RSA
    fgets(rsa_private_key_buf, sizeof(rsa_private_key_buf), key_file_ptr);
    wc_RsaPrivateKeyDecode(rsa_private_key_buf, 0, &rsa_private_key, sizeof(rsa_private_key_buf));


    while (1) {

        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &status);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART0, BLOCKING, &status);
        frame_length += (int)rcv;
    //MOVE THIS TO BE AFTER READING THE SIGNATURE?? OR ADD IN READING SIGNATURE INTO THIS IF
        if (frame_length == 0x0000) {
                //verify signature in here first, then send ok
                if(verify_hmac(chunk_signature, verify_key, data_chunk) == false){
                SysCtlReset();
                }
                uart_write(UART0, OK);
                break;
        }
        
        // Read each part of the frame into their respective buffers
        for (int a = 0;a < frame_length; ++a) {
            encrypted_data[data_index] = uart_read(UART0, BLOCKING, &status);
            data_index += 1;
        } 

        for (int b = 0; b < IV_SIZE; ++b){
    // need to fix this based on how the IV is sent
            iv[b] = uart_read(UART0, BLOCKING, &status);
            rcv = uart_read(UART0, BLOCKING, &read);
            iv = (int)rcv << 8;
            rcv = uart_read(UART0, BLOCKING, &read);
            iv += (int)rcv;
        }
        

        for (int c = 0; c < SIGNATURE_SIZE; ++c){
            signature[c] = uart_read(UART0, BLOCKING, &status);
        } 



        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE) {
            // writing the encrypted data to flash
            if (program_flash((uint8_t *) page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;
        }

    // need to fix based on how we're getting the key
        wc_RsaPrivateDecrypt(aes_encrypted_key, 256, aes_key, 32, &rsa_private_key);

        // init the AES object in WolfSSL with now decrypted key
        wc_AesSetKey(&aes, aes_key, 32, iv, AES_DECRYPTION);

        // decrypt data frame with AES
        wc_AesCbcDecrypt(&aes, unencrypted_data, encrypted_data, 32);

        

        if(verify_hmac(chunk_signature, verify_key, data_chunk) == false){
            SysCtlReset();
        }

        uart_write(UART0, OK); // Acknowledge the frame.
    }
    }

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of bytes to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}


void boot_firmware(void) {
//REVERIFY THE SIGNATURE (SECURE BOOT) ?????? what to verify to do the secure boot
    // Check if firmware loaded --> what even is this code....
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }
//DECRYPT THE FIRMWARE HERE
    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(METADATA_BASE + 4);
    uart_write_str(UART0, (char *)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}
