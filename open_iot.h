#ifndef __OPEN_IOT_H
#define __OPEN_IOT_H

#include <pb.h>

#define MAX_MESSAGE_SIZE                 256
#define AES_BLOCK_SIZE                   16

// Diffie-Hellman defaults
#ifndef DH_G
#define DH_G                             199
#endif
#ifndef DH_P
#define DH_P                             4001
#endif

// Error codes //
#define OPEN_IOT_RETURN_CODES(m)           \
    /* Error codes */                      \
    m(OPEN_IOT_OK,               0U)       \
    m(OPEN_IOT_HAL_ERROR,        1U)       \
    m(OPEN_IOT_HAL_BUSY,         2U)       \
    m(OPEN_IOT_HAL_TIMEOUT,      3U)       \
    m(OPEN_IOT_PB_ENCODE_FAILED, 101U)     \
    m(OPEN_IOT_PB_DECODE_FAILED, 102U)     \
    m(OPEN_IOT_MESSAGE_TOO_LONG, 103U)     \
    m(OPEN_IOT_MESSAGE_TOO_SHORT,104U)     \
    m(OPEN_IOT_CRC_FAILED,       105U)     \
    m(OPEN_IOT_WRONG_DEVICE_ID,  106U)     \
    m(OPEN_IOT_WRONG_TYPE,       107U)     \
    m(OPEN_IOT_SET_CONFIG_FAILED,108U)     \

#define OPEN_IOT_RETURN_CODES_ENUM(name, code) name = code,
enum {
    OPEN_IOT_RETURN_CODES(OPEN_IOT_RETURN_CODES_ENUM)
};
#undef OPEN_IOT_RETURN_CODES_ENUM

// Configuration //

struct open_iot_config
{
    uint8_t  aes_key[AES_BLOCK_SIZE];
    uint32_t joined;
    uint32_t sequence_receive;
    uint32_t sequence_send;
};
_Static_assert((sizeof(struct open_iot_config) % 4) == 0, "config must be aligned to uint32");

struct open_iot {
    // Buffers for ser/des encrypt/decrypt //
    __ALIGN_BEGIN
    uint8_t buffer1[MAX_MESSAGE_SIZE];
    uint8_t buffer2[MAX_MESSAGE_SIZE];
    __ALIGN_END

    uint8_t                 dh_private_key[AES_BLOCK_SIZE];
    struct open_iot_config *config;
    uint64_t                device_id;
    uint32_t                error;
    uint32_t                encryption;

    const char* name;
    const char* manufacturer;
    const char* product_url;
    const char* default_handler;
    const char* protobuf_name;

    // Functions to work with permanent configuration, usually EEPROM/FLASH
    uint32_t (*set_sequence_receive)(struct open_iot_config*, uint32_t sequence);
    uint32_t (*set_sequence_send)(struct open_iot_config*, uint32_t sequence);
    uint32_t (*set_joined)  (struct open_iot_config*, uint32_t joined);
    uint32_t (*set_aes_key) (struct open_iot_config*, uint8_t* key);
};



void     open_iot_init_eeprom(struct open_iot*, uint32_t eeprom_address);
uint8_t* open_iot_make_key_exchange_request(struct open_iot*, size_t* len);
uint8_t* open_iot_make_join_request(struct open_iot*, size_t *out_len);
uint8_t* open_iot_make_custom_message(struct open_iot*,
                                      const pb_msgdesc_t *pb_fields, const void *pb_struct,
                                      size_t* len);

void     open_iot_process_key_exchange_response(struct open_iot*, uint8_t* payload, size_t len);
void     open_iot_process_join_response(struct open_iot*, uint8_t* payload, size_t len);

uint32_t open_iot_is_joined(struct open_iot*);
void     open_iot_set_joined(struct open_iot*, uint32_t value);

uint64_t open_iot_get_device_id();
const char*
         open_iot_str_error(uint32_t error);

#endif
