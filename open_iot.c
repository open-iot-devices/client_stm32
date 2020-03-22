#include <string.h>
#include <stdlib.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include <openiot/system.pb.h>
#include <aes.h>

#include "main.h"
#include "open_iot.h"

// Forward declarations //
extern CRC_HandleTypeDef hcrc;

// Config functions //
extern uint32_t open_iot_eeprom_set_sequence_receive(struct open_iot_config*, uint32_t);
extern uint32_t open_iot_eeprom_set_sequence_send(struct open_iot_config*, uint32_t);
extern uint32_t open_iot_eeprom_set_joined(struct open_iot_config*, uint32_t);
extern uint32_t open_iot_eeprom_set_aes_key(struct open_iot_config*, uint8_t*);

// Boilerplates //
static uint64_t dh_pow_mod(uint64_t g, uint64_t x, uint64_t p);
static uint8_t* open_iot_write_message(struct open_iot*, uint32_t, const pb_msgdesc_t*, const void*, bool, bool, size_t*);
static uint32_t open_iot_read_message(struct open_iot*, uint8_t*, size_t, uint32_t, const pb_msgdesc_t*, void*, bool, bool);



///////////////////////////
// Inits / Helpers       //
///////////////////////////

uint64_t open_iot_get_device_id()
{
  return ((uint64_t)HAL_GetUIDw1() << 32) | HAL_GetUIDw2();
}

uint32_t open_iot_is_joined(struct open_iot* iot)
{
  return iot->config->joined;
}

void open_iot_set_joined(struct open_iot* iot, uint32_t value)
{
  iot->set_joined(iot->config, value);
}

void open_iot_init_eeprom(struct open_iot* iot, uint32_t eeprom_address)
{
  memset(iot, 0, sizeof(struct open_iot));

  iot->device_id = open_iot_get_device_id();
  iot->config = (void*)eeprom_address;
  iot->error = OPEN_IOT_OK;
  iot->encryption = EncryptionType_PLAIN;

  // Setup function pointers
  iot->set_sequence_receive = open_iot_eeprom_set_sequence_receive;
  iot->set_sequence_send = open_iot_eeprom_set_sequence_send;
  iot->set_joined = open_iot_eeprom_set_joined;
  iot->set_aes_key = open_iot_eeprom_set_aes_key;
}

///////////////////////////
// Key Exchange          //
///////////////////////////

uint8_t* open_iot_make_key_exchange_request(struct open_iot* iot, size_t *out_len)
{
  KeyExchangeRequest req = KeyExchangeRequest_init_zero;

  iot->error = OPEN_IOT_OK;

  // Prepare Key Exchange message
  req.dh_p = DH_P;
  req.dh_g = DH_G;
  req.encryption_type = iot->encryption;
  req.dh_a_count = AES_BLOCK_SIZE;
  for (uint32_t i = 0; i < req.dh_a_count; i++) {
    // iot->dh_private_key[i] = HAL_GetTick();
    iot->dh_private_key[i] = i;
    req.dh_a[i] = dh_pow_mod(DH_G, iot->dh_private_key[i], DH_P);
  }

  return open_iot_write_message(iot, EncryptionType_PLAIN,
    KeyExchangeRequest_fields, &req,
    true, false,    // key exchange, join request
    out_len);
}

void open_iot_process_key_exchange_response(struct open_iot* iot, uint8_t* payload, size_t payload_len)
{
  KeyExchangeResponse resp = KeyExchangeResponse_init_zero;

  iot->error = open_iot_read_message(iot, payload, payload_len,
      EncryptionType_PLAIN,
      KeyExchangeResponse_fields, &resp,
      true, false);  // key exchange, join request
  if (iot->error != OPEN_IOT_OK) {
    return;
  }

  // dhB must always be even to AES Block Size
  if (resp.dh_b_count != AES_BLOCK_SIZE) {
    iot->error = OPEN_IOT_WRONG_TYPE;
    return;
  }

  // Calculate shared key
  uint8_t key[AES_BLOCK_SIZE];
  for (uint32_t i = 0; i < AES_BLOCK_SIZE; i++) {
    key[i] = dh_pow_mod(resp.dh_b[i], iot->dh_private_key[i], DH_P);
  }
  iot->error = iot->set_aes_key(iot->config, key);
}

///////////////////////////
// Join Network          //
///////////////////////////

static bool pb_join_request_string_cb(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
  const struct open_iot* iot = *arg;
  const char* buffer = NULL;

  switch (field->tag) {
  case JoinRequest_name_tag:
    buffer = iot->name;
    break;
  case JoinRequest_manufacturer_tag:
    buffer = iot->manufacturer;
    break;
  case JoinRequest_product_url_tag:
    buffer = iot->product_url;
    break;
  case JoinRequest_default_handler_tag:
    buffer = iot->default_handler;
    break;
  default:
    return false;
  }

  if (buffer == NULL) {
    // Field is not set
    return true;
  }
  if (!pb_encode_tag_for_field(stream, field)) {
    return false;
  }
  return pb_encode_string(stream, (uint8_t*)buffer, strlen(buffer));
}

uint8_t* open_iot_make_join_request(struct open_iot* iot, size_t *out_len)
{
  JoinRequest req = JoinRequest_init_zero;

  iot->error = OPEN_IOT_OK;

  req.name.arg = iot;
  req.name.funcs.encode = pb_join_request_string_cb;
  req.manufacturer.arg = iot;
  req.manufacturer.funcs.encode = pb_join_request_string_cb;
  req.product_url.arg = iot;
  req.product_url.funcs.encode = pb_join_request_string_cb;
  req.default_handler.arg = iot;
  req.default_handler.funcs.encode = pb_join_request_string_cb;

  return open_iot_write_message(iot, EncryptionType_PLAIN,
    JoinRequest_fields, &req,
    false, true,    // key exchange, join request
    out_len);
}

void open_iot_process_join_response(struct open_iot* iot, uint8_t* payload, size_t payload_len)
{
  JoinResponse resp = JoinResponse_init_zero;

  iot->error = open_iot_read_message(iot, payload, payload_len,
      EncryptionType_PLAIN,
      JoinResponse_fields, &resp,
      false, true);  // key exchange, join request
  if (iot->error != OPEN_IOT_OK) {
    return;
  }

  iot->set_joined(iot->config, 1);
  iot->set_sequence_send(iot->config, 0);
  iot->set_sequence_receive(iot->config, 0);
}


///////////////////////////
// Boilerplaces          //
///////////////////////////

static uint8_t* open_iot_write_message(
    struct open_iot* iot, uint32_t encryption,
    const pb_msgdesc_t *pb_fields, const void *pb_struct,
    bool key_exchange, bool join_request,
    size_t *out_len)
{
  // Serialize Message
  pb_ostream_t stream1 = pb_ostream_from_buffer(iot->buffer1, MAX_MESSAGE_SIZE);
  bool res = pb_encode_delimited(&stream1, pb_fields, pb_struct);
  if (!res) {
    iot->error = OPEN_IOT_PB_ENCODE_FAILED;
    return NULL;
  }
  size_t message_len = stream1.bytes_written;

  // Optionally encrypt it
  switch (encryption) {
  case EncryptionType_PLAIN:
    break;
  case EncryptionType_AES_ECB:
    // struct AES_ctx ctx;
    // AES_init_ctx(&ctx, iot->config->aes_key);
    // AES_ECB_encrypt
    break;
  }

  // Prepare message header
  Header hdr = Header_init_zero;
  hdr.device_id = iot->device_id;
  hdr.key_exchange = key_exchange;
  hdr.join_request = join_request;
  hdr.crc = ~HAL_CRC_Calculate(&hcrc, (uint32_t*)iot->buffer1, message_len);

  // Serialize Header message
  pb_ostream_t stream2 = pb_ostream_from_buffer(iot->buffer2, MAX_MESSAGE_SIZE);
  res = pb_encode_delimited(&stream2, Header_fields, &hdr);
  if (!res) {
    iot->error = OPEN_IOT_PB_ENCODE_FAILED;
    return NULL;
  }

  // Copy Message right after Header
  memcpy(&iot->buffer2[stream2.bytes_written], iot->buffer1, message_len);
  *out_len = stream2.bytes_written + message_len;
  return iot->buffer2;
}

static uint32_t open_iot_read_message(
    struct open_iot* iot,
    uint8_t *payload, size_t payload_len,
    uint32_t encryption,
    const pb_msgdesc_t *pb_fields, void *pb_struct,
    bool key_exchange, bool join_request)
{
  Header hdr = Header_init_zero;

  // De-serialize header
  pb_istream_t istream = pb_istream_from_buffer(payload, payload_len);
  bool res = pb_decode_delimited(&istream, Header_fields, &hdr);
  if (!res) {
    return OPEN_IOT_PB_DECODE_FAILED;
  }
  // Check header
  if (iot->device_id != hdr.device_id) {
    return OPEN_IOT_WRONG_DEVICE_ID;
  }
  // Check flags
  if (hdr.key_exchange != key_exchange || hdr.join_request != join_request) {
    return OPEN_IOT_WRONG_TYPE;
  }
  // Check CRC
  uint32_t hdr_len = payload_len - istream.bytes_left;
  uint32_t crc = ~HAL_CRC_Calculate(&hcrc, (uint32_t*)&payload[hdr_len], istream.bytes_left);
  if (hdr.crc != crc) {
    return OPEN_IOT_CRC_FAILED;
  }

  // De-serialize payload message
  res = pb_decode_delimited(&istream, pb_fields, pb_struct);
  if (!res) {
    return OPEN_IOT_PB_DECODE_FAILED;
  }

  return OPEN_IOT_OK;
}

// Diffie-Hellman: function to compute g^x mod p
static uint64_t dh_pow_mod(uint64_t g, uint64_t x, uint64_t p)
{
  uint64_t r;
  uint64_t y = 1;

  while (x > 0) {
    r = x % 2;
    // Fast exponention
    if (r == 1) {
      y = (y * g) % p;
    }
    g = g * g % p;
    x = x / 2;
  }

  return y;
}

const char *open_iot_str_error(uint32_t error)
{
#define CASES(name, code) case code: return #name;
  switch (error) {
  OPEN_IOT_RETURN_CODES(CASES)
  default:
    return "UNKNOWN";
  }
#undef CASES
}
