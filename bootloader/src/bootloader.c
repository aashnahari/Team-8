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
#define METADATA_BASE 0xfc00 // base address of version, size, & msg in Flash
#define FW_BASE 0x20000  // base address of firmware in Flash
#define FW_TEMP 0x10000 //base address of temp firmware

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
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE+ MESSAGE_SIZE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + MESSAGE_SIZE + 2);
uint8_t * fw_release_message_address;

// Frame Buffers
unsigned char encrypted_data[512];
unsigned char unencrypted_data[512];
unsigned char temp_data[FLASH_PAGESIZE];
unsigned char message[MESSAGE_SIZE];    
unsigned char signature[HMAC_SIZE];
unsigned char end_signature[HMAC_SIZE];
unsigned char meta[16];
unsigned char iv[IV_SIZE];
unsigned char for_flash[MESSAGE_SIZE + 20];





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
            boot_firmware();
            uart_write_str(UART0, "Booted.\n");
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
    wc_HmacFree(&hmac);
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
    uint32_t temp_addr = FW_TEMP;
    uint32_t firmware_addr = FW_BASE;
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
    version = (uint32_t)meta[0];
    version = (uint32_t)meta[1] << 8;
    size = (uint32_t)meta[2];
    size |= (uint32_t)meta[3] << 8;

    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);


    // Verifying HMAC signature for the versioning frame
    if (verify_hmac(signature, HMAC_KEY, meta, 16) == false) {
        SysCtlReset();
    }

    // Compare to old version and abort if older (note special case for version 0)

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
 
    for (int h = 0; h < MESSAGE_SIZE; ++h){
        for_flash[h] = (uint8_t)message[h];
    }
    uint8_t counter = 0;
    for (int q = MESSAGE_SIZE; q < MESSAGE_SIZE + 4; ++q){
        for_flash[q] = meta[counter];
        ++counter;
    }
    counter = 0;
    for (int q = MESSAGE_SIZE+4; q < MESSAGE_SIZE + 20; ++q){
        for_flash[q] = iv[counter];
        ++counter;
    }
    
    //flash the metadata & the message (put them in an array together)
    program_flash((uint8_t *)METADATA_BASE, for_flash, MESSAGE_SIZE+20);

    //error handling
    if (program_flash((uint8_t *)METADATA_BASE, for_flash, MESSAGE_SIZE+20)) {
        uart_write_str(UART0, "Programming metadata and message failed.\n");
        SysCtlReset();
    }

    //checking data from flash
    unsigned char verify_data[MESSAGE_SIZE + 20];
    memcpy(verify_data, (uint8_t *)METADATA_BASE, MESSAGE_SIZE + 20);
    
    if (memcmp(for_flash, verify_data, MESSAGE_SIZE + 20) != 0) {
        uart_write_str(UART0, "NFlash verification failed.\n");
        SysCtlReset();
    } else {
        //uart_write_str(UART0, "YFlash verification successful.\n");
    }

    
   //send ok... start sending firmware frames
    uart_write(UART0, OK);

   
    int chunk = 1;
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
            encrypted_data[a] = uart_read(UART0, BLOCKING, &status);

        }

        for (int c = 0; c < HMAC_SIZE; ++c) {
            signature[c] = uart_read(UART0, BLOCKING, &status);
        }
        


        if (verify_hmac(signature, HMAC_KEY, encrypted_data, frame_length) == false) {
            SysCtlReset();
        }

        if (chunk == 1){

            if (program_flash((uint8_t *) temp_addr, encrypted_data, 512)) {
                uart_write(UART0, ERROR);
                SysCtlReset(); 
                return;
            }

            // Update to next page
            chunk++;
        } // if
        else{         //if we fill page buffer...

            memcpy(temp_data, (uint8_t*)temp_addr, 512);
            for (int i = 0; i < 512; ++i){
                temp_data[i+512] = encrypted_data[i];
            }

            if (program_flash((uint8_t *) firmware_addr, temp_data, FLASH_PAGESIZE)) {
                uart_write(UART0, ERROR);
                SysCtlReset(); 
                return;
            }
            chunk = 1;
            firmware_addr+= FLASH_PAGESIZE;
        }

        uart_write(UART0, OK); // Acknowledge the frame.
    } 
  
        /*if (data_index % FLASH_PAGESIZE == 0) {
            int8_t error = program_flash((uint8_t *)page_addr, encrypted_data, data_index);

            if (error) {
                uart_write(UART0, ERROR);
                SysCtlReset();
            }

            page_addr += FLASH_PAGESIZE;
        }
        else{
            int8_t error = program_flash((uint8_t *)page_addr, encrypted_data, data_index);

            if (error) {
                uart_write(UART0, ERROR);
                SysCtlReset();
            }
            page_addr += 0x200
        }


    
        uart_write(UART0, OK);*/
    
     
    }





/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of bytes to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char* data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;
    uint32_t aligned_addr = (uint32_t)page_addr; 

    // Ensure the aligned address is within the valid flash range
    if (aligned_addr < 0x00000000 || aligned_addr > 0x0003FFFF) {
        uart_write_str(UART0, "Address out of valid flash range\n");
        uart_write_hex_bytes(UART0, (uint8_t*)&aligned_addr, sizeof(aligned_addr));
        aligned_addr = (uint32_t)page_addr & ~(FLASH_PAGESIZE - 1);
        if (aligned_addr < 0x00000000 || aligned_addr > 0x0003FFFF){
            uart_write_str(UART0, "Oaligned address is still out of valid flash range\n");
            return -1;
        }
          // Return an error
    }

    // Check for misalignment
    if (aligned_addr % FLASH_PAGESIZE != 0) {
        uart_write_str(UART0, "Xaddress misaligned\n");
        return -1;  // Return an error or reset
    }

    // Erase the flash page at the aligned address
    ret = FlashErase(aligned_addr);
    if (ret != 0) {
        uart_write_str(UART0, "Erase failed at address: ");
        uart_write_hex_bytes(UART0, (uint8_t*)&aligned_addr, sizeof(aligned_addr));
        uart_write_str(UART0, "\n");
        return ret;
    }

    // seperate data into full words & overflow
    int full_words = data_len / FLASH_WRITESIZE;
    int rem_bytes = data_len % FLASH_WRITESIZE;

    // Program full words first
    ret = FlashProgram((unsigned long*)data, aligned_addr, full_words * FLASH_WRITESIZE);
    if (ret != 0) {
        uart_write_str(UART0, "KFlash Program failed on full words.\n");
        return ret;
    }

    // Handle the last word if there's a remainder
    if (rem_bytes > 0) {
        word = 0xFFFFFFFF;  // Fill the word with 0xFF by default
        for (i = 0; i < rem_bytes; i++) {
            word = (word >> 8) | (data[full_words * FLASH_WRITESIZE + i] << 24);
        }

        ret = FlashProgram(&word, aligned_addr + full_words * FLASH_WRITESIZE, FLASH_WRITESIZE);
        if (ret != 0) {
            uart_write_str(UART0, "MFlash Program failed on last word.\n");
            return ret;
        }
    }

    //uart_write_str(UART0, "YFlash Program successful.\n");
    return 0;  // Success
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
        uart_write_str(UART0, "No firmware loaded, press reset.\n");
        //SysCtlReset(); // Reset device
        
        return;
    }

    // Initialize AES context
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    memcpy(iv, (uint8_t*)(METADATA_BASE+MESSAGE_SIZE+4), IV_SIZE);
    // Set AES key for decryption
    wc_AesSetIV(&aes, iv);
    wc_AesSetKey(&aes, AES_KEY, 32, iv, AES_DECRYPTION);

    // Buffer to hold decrypted firmware

    uint32_t fw_addr = (uint16_t *)FW_BASE;
    uint16_t fw_size = *(uint16_t*)fw_size_address;
    unsigned char decrypted_flashable[FLASH_PAGESIZE];
    unsigned char encrypted_flashed[FLASH_PAGESIZE];
    while (fw_addr < (FW_BASE + fw_size)){

        memcpy(encrypted_flashed, (uint8_t*)fw_addr, FLASH_PAGESIZE);
        // Decrypt the firmware in chunks and write it back to the same location
        if (wc_AesCbcDecrypt(&aes, decrypted_flashable, encrypted_flashed, FLASH_PAGESIZE)){
                uart_write_str(UART0, "still not working, press reset.\n");
                SysCtlReset();
            }


        if (program_flash((uint8_t *) fw_addr, decrypted_flashable, FLASH_PAGESIZE)) {
            uart_write(UART0, ERROR);
            SysCtlReset(); 
        }
        uart_write_str(UART0, fw_addr);
        fw_addr+= FLASH_PAGESIZE;
    }
    

    // Print the release message
    uint8_t* fw_release_message_address = (uint8_t*)(METADATA_BASE);
    uart_write_str(UART0, (char*)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x20001\n\t"
          "BX R0\n\t");

    uart_write_str(UART0, 'PAST BOOTLOADER'); 
}


void reencrypt_firmware(void) {
    // Initialize AES context
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    memcpy(iv, (uint8_t*)METADATA_BASE+MESSAGE_SIZE+4, IV_SIZE);

    // Set AES key for encryption
    wc_AesSetKey(&aes, AES_KEY, 32, iv, AES_ENCRYPTION);

    // Buffer to hold encrypted firmware

    uint32_t fw_addr = FW_BASE;
    uint16_t fw_size = *(uint16_t*)fw_size_address;

    // Re-encrypt the firmware in chunks and write it back to the same location


    unsigned char reencrypted_flashable[FLASH_PAGESIZE];
    unsigned char decrypted_flashed[FLASH_PAGESIZE];
    while (fw_addr < (FW_BASE + fw_size)){

        memcpy(decrypted_flashed, (uint8_t*)fw_addr, FLASH_PAGESIZE);
        if (wc_AesCbcEncrypt(&aes, reencrypted_flashable, decrypted_flashed, FLASH_PAGESIZE)){
                uart_write_str(UART0, "still not working, press reset.\n");
        }


        if (program_flash((uint8_t *) fw_addr, reencrypted_flashable, FLASH_PAGESIZE)) {
            uart_write(UART0, ERROR);
            SysCtlReset(); 
            return;
        }

        fw_addr+= FLASH_PAGESIZE;
    }
    

    // while (fw_size > 0) {
    //     uint32_t chunk_size = 512;

    //     // Read the decrypted chunk from memory
    //     memcpy(encrypted_data, (uint8_t*)fw_addr, chunk_size);

    //     // Encrypt the chunk
    //     wc_AesCbcEncrypt(&aes, encrypted_data, encrypted_data, chunk_size);

    //     // Write encrypted chunk back to flash
    //     program_flash((uint8_t*)fw_addr, encrypted_data, chunk_size);

    //     fw_addr += chunk_size;
    //     fw_size -= chunk_size;
    // }


    
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
