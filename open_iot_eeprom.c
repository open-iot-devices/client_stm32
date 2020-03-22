#include <string.h>
#include <stdlib.h>

#include "main.h"
#include "open_iot.h"


///////////////////////////
// EEPROM writer         //
///////////////////////////

static uint32_t open_iot_write_eeprom(uint32_t address, uint32_t *array, uint32_t array_size)
{
  int err = HAL_FLASHEx_DATAEEPROM_Unlock();
  if (err != HAL_OK) {
    return err;
  }

  uint32_t address_end = address + (array_size * 4);
  for (; address != address_end; address += 4, array++) {
    err = HAL_FLASHEx_DATAEEPROM_Program(FLASH_TYPEPROGRAMDATA_WORD, address, *array);
    if (err != HAL_OK) {
      break;
    }
  }

  HAL_FLASHEx_DATAEEPROM_Lock();
  return err;
}

///////////////////////////
// Helpers for open_iot  //
///////////////////////////

uint32_t open_iot_eeprom_set_sequence_receive(struct open_iot_config *cfg, uint32_t value)
{
  uint32_t address = (uint32_t)cfg + offsetof(struct open_iot_config, sequence_receive);

  return open_iot_write_eeprom(address, &value, 1);
}

uint32_t open_iot_eeprom_set_sequence_send(struct open_iot_config *cfg, uint32_t value)
{
  uint32_t address = (uint32_t)cfg + offsetof(struct open_iot_config, sequence_send);

  return open_iot_write_eeprom(address, &value, 1);
}

uint32_t open_iot_eeprom_set_joined(struct open_iot_config *cfg, uint32_t joined)
{
  uint32_t address = (uint32_t)cfg + offsetof(struct open_iot_config, joined);

  return open_iot_write_eeprom(address, &joined, 1);
}

uint32_t open_iot_eeprom_set_aes_key(struct open_iot_config *cfg, uint8_t *key)
{
  uint32_t address = (uint32_t)cfg + offsetof(struct open_iot_config, aes_key);

  return open_iot_write_eeprom(address, (uint32_t *)key, AES_BLOCK_SIZE / 4);
}
