// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.
//changes

#include "bootloader.h"
#include "../../tools/header.h"

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
void reencrypt_firmware(void);
void reencrypt_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4
#define MESSAGE_SIZE 1024

#define HMAC_SIZE 32
#define HMAC_KEY_SIZE 32   
#define IV_SIZE 16

// Protocol Constants
#define OK ((unsigned char)0x04)
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
unsigned char message[MESSAGE_SIZE];    //version + data size + message
unsigned char signature[HMAC_SIZE];
unsigned char end_signature[HMAC_SIZE];
unsigned char meta[16];
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


int main(void) {

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
            reencrypt_firmware();
        }
    }
}

bool verify_hmac(uint8_t *sig, const uint8_t *ky, uint8_t *msg, int msg_size){   //function for hmac verifying
    uint8_t hmac_result[HMAC_SIZE];
    Hmac hmac;
    wc_HmacInit(&hmac, NULL, 0);
    if (wc_HmacSetKey(&hmac, WC_SHA256, ky, HMAC_KEY_SIZE) != 0){
        //perror("wc_HmacSetKey failed");
        return false;
    }
   
    if (wc_HmacUpdate(&hmac, msg, msg_size) != 0){
        //perror("wc_HmacUpdate failed");
        return false;
    }
    if (wc_HmacFinal(&hmac, hmac_result) != 0) {
        //perror("wc_HmacFinal failed");
        return false;
    }
    if (memcmp(hmac_result, sig, HMAC_SIZE) != 0) {
        return false;
    }  
    return true;
}


 /*
 * Load the firmware into flash.
 */
 


void load_firmware(void) {
    uint32_t frame_length = 0;
    int status = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;
    uint8_t enc_meta[16];

   
// reading FRAME 0
    //first recieving the IV
    for (int b = 0; b < IV_SIZE; ++b) {
        iv[b] = uart_read(UART0, BLOCKING, &status);
    }

    //recieve encrypted metadata
    for(int g = 0; g < 16; ++g){
        enc_meta[g] = uart_read(UART0, BLOCKING, &status);
    }
    
    
    //reading in the firmware message
    for (int j = 0; j < MESSAGE_SIZE; ++j) {
        message[j] = uart_read(UART0, BLOCKING, &status);
    }

    //reading in the signature (of unencrypted metadata)
    for (int k = 0; k < HMAC_SIZE; ++k) {
        signature[k] = uart_read(UART0, BLOCKING, &status);
    }

    //preparing for decryption of metadata
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, AES_KEY, 32, iv, AES_DECRYPTION);

    //decrypt the encrypted metadata
    wc_AesCbcDecrypt(&aes, meta, enc_meta, 16);

    //put the version & size in correct spots
    version = (uint32_t)meta[1];
    version |= (uint32_t)meta[0];
    size = (uint32_t)meta[3];
    size |= (uint32_t)meta[2] << 8;

    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);


    // Verifying HMAC signature for the versioning frame
    if (verify_hmac(signature, HMAC_KEY, meta, 16) == false) {
        SysCtlReset();
    }

    // Compare to old version and abort if older (note special case for version 0)

//figure out how "old version" is stored
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }
    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    } else if (version == old_version){
        version = old_version;
    }else if (version == 0) {
        version = old_version;
    }


    // Write metadata & message to flash
//make an array of the message & metadata
    
    //flash the metadata & the message (put them in an array together)
    program_flash((uint8_t *)METADATA_BASE, (uint8_t *)(&metadata), 4);
    //program_flash((uint8_t *)(METADATA_BASE + 4), message, MESSAGE_SIZE);

   //send ok... start sending firmware frames
    uart_write(UART0, OK);

   

// Loop to handle frames
    while (1) {
        rcv = uart_read(UART0, BLOCKING, &status);
        frame_length = (uint32_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &status);
        frame_length |= (uint32_t)rcv << 8;
   

        //if this is the end frame, then wrap up (verify end sig and then stop)
        //NO MORE TAKING IN SIG FOR END
        if (frame_length == 0) {
            uart_write(UART0, OK);
            break;
        }

        
        //assign each piece of data frame to their respective buffers
        for (int a = 0; a < frame_length; ++a) {
            encrypted_data[data_index] = uart_read(UART0, BLOCKING, &status);
            data_index += 1;
        }

        for (int c = 0; c < HMAC_SIZE; ++c) {
            signature[c] = uart_read(UART0, BLOCKING, &status);
        }
        
        //if we fill page buffer...
  
        if (data_index == FLASH_PAGESIZE) {
            if (program_flash((uint8_t *)page_addr, encrypted_data, data_index)) {
                uart_write(UART0, ERROR);
                SysCtlReset();
            }

            page_addr += FLASH_PAGESIZE;
            data_index = 0;
        }

        if (verify_hmac(signature, HMAC_KEY, encrypted_data, frame_length) == false) {
            SysCtlReset();
        }
    
        uart_write(UART0, OK);
    
     
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
    
    // Check if firmware is loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
            break;
        
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset(); // Reset device
        
        return;
    }

    // Initialize AES context
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);

    // Set AES key for decryption
    wc_AesSetKey(&aes, AES_KEY, 32, iv, AES_DECRYPTION);

    // Buffer to hold decrypted firmware

    uint32_t fw_addr = FW_BASE;
    uint16_t fw_size = *(uint16_t*)fw_size_address;

    // Decrypt the firmware in chunks and write it back to the same location
    while (fw_size > 0) {
        uint32_t chunk_size = (fw_size > FLASH_PAGESIZE) ? FLASH_PAGESIZE : fw_size;

        // Decrypt the chunk
        wc_AesCbcDecrypt(&aes, unencrypted_data, (uint8_t*)fw_addr, chunk_size);

        // Verify HMAC signature for each chunk (if applicable)
        if (!verify_hmac(signature, HMAC_KEY, encrypted_data, chunk_size)) {
            uart_write_str(UART0, "Firmware verification failed.\n");
            SysCtlReset();
            return;
        }

        // Write decrypted chunk back to the same location
        program_flash((uint8_t*)fw_addr, unencrypted_data, chunk_size);
        
        fw_addr += chunk_size;
        fw_size -= chunk_size;
    }

    // Print the release message
    uint8_t* fw_release_message_address = (uint8_t*)(METADATA_BASE + 4);
    uart_write_str(UART0, (char*)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}


void reencrypt_firmware(void) {
    // Initialize AES context
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);


    // Set AES key for encryption
    wc_AesSetKey(&aes, AES_KEY, 32, iv, AES_ENCRYPTION);

    // Buffer to hold encrypted firmware

    uint32_t fw_addr = FW_BASE;
    uint16_t fw_size = *(uint16_t*)fw_size_address;

    // Re-encrypt the firmware in chunks and write it back to the same location
    while (fw_size > 0) {
        uint32_t chunk_size = (fw_size > FLASH_PAGESIZE) ? FLASH_PAGESIZE : fw_size;

        // Read the decrypted chunk from memory
        memcpy(encrypted_data, (uint8_t*)fw_addr, chunk_size);

        // Encrypt the chunk
        wc_AesCbcEncrypt(&aes, encrypted_data, encrypted_data, chunk_size);

        // Write encrypted chunk back to flash
        program_flash((uint8_t*)fw_addr, encrypted_data, chunk_size);

        fw_addr += chunk_size;
        fw_size -= chunk_size;
    }
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
