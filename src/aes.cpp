/** 
 *  @file   aes.cpp
 *  @brief  AES Main Source File
 *
 *  This contains the Source Code for the AES Implementation
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */

#include "../inc/aes.hpp"

#include <stdexcept>

namespace {

    int __aes_expand_key(
        const symmetric_ciphers::   __aes_u8   key[], 
        symmetric_ciphers::         __aes_u8   expand_key[], 
        const symmetric_ciphers::   __aes_u16  key_len
        ) {

        symmetric_ciphers::__aes_u16 expand_key_len = 0;
        symmetric_ciphers::__aes_u16 actual_key_len = 0;

        switch (key_len) {

        case 128:
            actual_key_len = 16;
            expand_key_len = 176;
            break;

        case 192:
            actual_key_len = 24;
            expand_key_len = 208;
            break;

        case 256:
            actual_key_len = 32;
            expand_key_len = 240;
            break;
        
        default:
            throw std::invalid_argument("Unsupported Key Length");
        }

        return 0;
    }

}

