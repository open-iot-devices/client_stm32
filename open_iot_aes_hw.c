#include "main.h"
#include "open_iot.h"

extern CRYP_HandleTypeDef hcryp;

uint32_t aes_ecb_encrypt_blocks(uint8_t* key, uint8_t* dst, uint8_t* src, size_t len)
{
  if ((len % AES_BLOCK_SIZE) != 0) {
    return OPEN_IOT_AES_INVALID_BLOCK_SIZE;
  }

  hcryp.Init.pKey = (uint8_t*) key;
  HAL_CRYP_Init(&hcryp);
  int res = HAL_CRYP_AESECB_Encrypt(&hcryp, src, len, dst, 1000);
  HAL_CRYP_DeInit(&hcryp);

  return res;
}

uint32_t aes_ecb_decrypt_blocks(uint8_t* key, uint8_t* dst, uint8_t* src, size_t len)
{
  if ((len % AES_BLOCK_SIZE) != 0) {
    return OPEN_IOT_AES_INVALID_BLOCK_SIZE;
  }

  hcryp.Init.pKey = (uint8_t*) key;
  HAL_CRYP_Init(&hcryp);
  int res = HAL_CRYP_AESECB_Decrypt(&hcryp, src, len, dst, 1000);
  HAL_CRYP_DeInit(&hcryp);

  return res;
}
