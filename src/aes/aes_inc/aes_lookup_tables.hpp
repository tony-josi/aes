/** 
 *  @file   aes_lookup_tables.hpp
 *  @brief  AES S-BOX, INV-S-BOX and MUL tables
 *
 *  This file contains the header code for the AES S-BOX, INV-S-BOX and MUL tables.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2021 Tony Josi
 *  @bug            No known bugs.
*/

#ifndef _AES_LUT_HEADER_TJ__
#define _AES_LUT_HEADER_TJ__

/* Forward declarations for Lookup tables */
extern      uint8_t     AES_S_BOX[256];
extern      uint8_t     AES_INV_S_BOX[256];
extern      uint8_t     MUL_2[256];
extern      uint8_t     MUL_3[256];
extern      uint8_t     MUL_9[256];
extern      uint8_t     MUL_11[256];
extern      uint8_t     MUL_13[256];
extern      uint8_t     MUL_14[256];
extern      uint8_t     AES_RCON[11];

#endif /* _AES_LUT_HEADER_TJ__ */
