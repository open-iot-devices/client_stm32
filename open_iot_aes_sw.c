#include "main.h"
#include "open_iot.h"

#include "aes.c"

#include "app.h"

uint32_t aes_ecb_encrypt_blocks(uint8_t* key, uint8_t* dst, uint8_t* src, size_t len)
{
  struct AES_ctx ctx;

  if ((len % AES_BLOCK_SIZE) != 0) {
    return OPEN_IOT_AES_INVALID_BLOCK_SIZE;
  }

  memcpy(dst, src, len);

  AES_init_ctx(&ctx, key);
  for (unsigned int i = 0; i < len; i += AES_BLOCK_SIZE) {
    AES_ECB_encrypt(&ctx, &dst[i]);
  }

  return HAL_OK;
}

uint32_t aes_ecb_decrypt_blocks(uint8_t* key, uint8_t* dst, uint8_t* src, size_t len)
{
  struct AES_ctx ctx;

  if ((len % AES_BLOCK_SIZE) != 0) {
    return OPEN_IOT_AES_INVALID_BLOCK_SIZE;
  }

  memcpy(dst, src, len);

  AES_init_ctx(&ctx, key);
  for (unsigned int i = 0; i < len; i += AES_BLOCK_SIZE) {
    AES_ECB_decrypt(&ctx, &dst[i]);
  }

  return HAL_OK;
}
