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
#include <string>

namespace {

    constexpr static symmetric_ciphers::__aes_u8 AES_S_BOX[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    constexpr static symmetric_ciphers::__aes_u8 AES_INV_S_BOX[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    constexpr static symmetric_ciphers::__aes_u8 AES_RCON[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    constexpr static symmetric_ciphers::__aes_u8 AES_WORD_SIZE =        4;


    /* Forward declarations for helper functions */
    int __aes_expand_key(
        const symmetric_ciphers::   __aes_u8    key[], 
        symmetric_ciphers::         __aes_u8    expand_key[], 
        const symmetric_ciphers::   __aes_u16   actual_key_len,
        const symmetric_ciphers::   __aes_u16   expand_key_len
    );

    int __aes_key_scheduler(
        symmetric_ciphers::         __aes_u8    round,
        const symmetric_ciphers::   __aes_u8    in[AES_WORD_SIZE],
        symmetric_ciphers::         __aes_u8    out[AES_WORD_SIZE]
    );

    inline void __aes_xor_word(
        symmetric_ciphers::         __aes_u8    target[AES_WORD_SIZE],
        const symmetric_ciphers::   __aes_u8    operand[AES_WORD_SIZE]
    );

    void __aes_compute_remaining_words(
        symmetric_ciphers::         __aes_u8    words_required,
        symmetric_ciphers::         __aes_u8    exp_key[],
        symmetric_ciphers::         __aes_u8   &exp_offset,
        const symmetric_ciphers::   __aes_u16   exp_key_len,
        const symmetric_ciphers::   __aes_u16   act_key_len  
    );

    void __aes_256_key_scheduler_5th_word(
        symmetric_ciphers::         __aes_u8    exp_key[],
        symmetric_ciphers::         __aes_u8   &exp_offset,
        const symmetric_ciphers::   __aes_u16   exp_key_len,
        const symmetric_ciphers::   __aes_u16   act_key_len  
    );

} /* End of anonymous namespace */

symmetric_ciphers::AES::AES(symmetric_ciphers::key_size ks) {

    this->block_size = 16;
    switch(ks) {
    case key_size::AES_128:
        this->key_len_bits = 128;
        this->round_num = 10;
        this->actual_key_len = 16;
        this->expanded_key_len = 176;
        break;
    case key_size::AES_192:
        this->key_len_bits = 192;
        this->round_num = 12;
        this->actual_key_len = 24;
        this->expanded_key_len = 208;
        break;
    case key_size::AES_256:
        this->key_len_bits = 256;
        this->round_num = 14;
        this->actual_key_len = 32;
        this->expanded_key_len = 240;
        break;
    default:
        throw std::invalid_argument("Unsupported Key Length, supports 128/192/256");
    }

}


/* Test Headers*/
#include <iostream>
#include <cstdio>

/* Test code */
int main() {
    symmetric_ciphers::__aes_u8 key[17] = "HELLO_THIS_IS_65";
    symmetric_ciphers::__aes_u8 exp_key[176] {0};
    __aes_expand_key(key, exp_key, 16, 176);
    for(int i = 0; i < 176; i++)
        std::printf("%02x", exp_key[i]);
        //std::cout << std::hex << static_cast<int>(exp_key[i]);
    std::cout << std::endl;
    std::cout << std::strlen((char *)exp_key) << std::endl;

    symmetric_ciphers::__aes_u8 key2[25] = "HELLO_THIS_XS_6512345678";
    symmetric_ciphers::__aes_u8 exp_key2[208] {0};
    __aes_expand_key(key2, exp_key2, 24, 208);
    for(int i = 0; i < 208; i++)
        std::printf("%02x", exp_key2[i]);
        //std::cout << std::hex << static_cast<int>(exp_key2[i]);
    std::cout << std::endl;
    std::cout << std::strlen((char *)exp_key2) << std::endl;

    symmetric_ciphers::__aes_u8 key3[33] = "HELLO_THIS_XS_651234567812345678";
    symmetric_ciphers::__aes_u8 exp_key3[240] {0};
    __aes_expand_key(key3, exp_key3, 32, 240);
    for(int i = 0; i < 240; i++)
        std::printf("%02x", exp_key3[i]);
        //std::cout << std::hex << static_cast<int>(exp_key2[i]);
    std::cout << std::endl;
    std::cout << std::strlen((char *)exp_key3) << std::endl;

}

namespace {

    int __aes_expand_key(
        const symmetric_ciphers::   __aes_u8    key[], 
        symmetric_ciphers::         __aes_u8    expand_key[], 
        const symmetric_ciphers::   __aes_u16   actual_key_len,
        const symmetric_ciphers::   __aes_u16   expand_key_len
    ) {
        /* Clear the expanded key output array & copy initial key */
        memset(expand_key, 0, expand_key_len);
        memcpy(expand_key, key, actual_key_len);

        /* Increment an offset to the current filled 
           position in the expanded key output array */
        symmetric_ciphers::__aes_u8     cur_exp_key_offset = 0;
        cur_exp_key_offset += actual_key_len;

        for(symmetric_ciphers::__aes_u8 round_key_index = 1; cur_exp_key_offset < expand_key_len; ++round_key_index) {

            /* Process the last 4 bytes */
            symmetric_ciphers::__aes_u8     temp_key_buff_1[AES_WORD_SIZE];
            memcpy(temp_key_buff_1, (expand_key + (cur_exp_key_offset - AES_WORD_SIZE)), AES_WORD_SIZE);
            
            symmetric_ciphers::__aes_u8     temp_key_buff_2[AES_WORD_SIZE];
            __aes_key_scheduler(round_key_index, temp_key_buff_1, temp_key_buff_2);

            /* XOR the pre - processed last 4 bytes with corresponding word from 
               previous round */
            memcpy(temp_key_buff_1, (expand_key + (cur_exp_key_offset - actual_key_len)), AES_WORD_SIZE);
            __aes_xor_word(temp_key_buff_1, temp_key_buff_2);
            memcpy((expand_key + cur_exp_key_offset), temp_key_buff_1, AES_WORD_SIZE);
            cur_exp_key_offset += AES_WORD_SIZE;

            /* Compute key for remaining words in the block */
            __aes_compute_remaining_words(3, expand_key, cur_exp_key_offset, expand_key_len, actual_key_len);
            
            if(actual_key_len == 32) {
                /* Do special key schedule if i >= N & (i % n) == 4 */
                __aes_256_key_scheduler_5th_word(expand_key, cur_exp_key_offset, expand_key_len, actual_key_len);
                __aes_compute_remaining_words(3, expand_key, cur_exp_key_offset, expand_key_len, actual_key_len);
            } else if(actual_key_len == 24) 
                __aes_compute_remaining_words(2, expand_key, cur_exp_key_offset, expand_key_len, actual_key_len);
        }
        /* Return expanded key length */
        return expand_key_len;
    }

    int __aes_key_scheduler(
        symmetric_ciphers::         __aes_u8    round,
        const symmetric_ciphers::   __aes_u8    in[AES_WORD_SIZE],
        symmetric_ciphers::         __aes_u8    out[AES_WORD_SIZE]
    ) {

        /* Rotate word */
        for(int i = 0; i < (AES_WORD_SIZE - 1); ++i) 
            out[i] = in[i + 1];
        out[3] = in[0];

        /* Substitute word */
        for(int i = 0; i < AES_WORD_SIZE; ++i) 
            out[i] = AES_S_BOX[ out[i] ];

        /* XOR Round Constant to least significant byte */
        if(round < sizeof(AES_RCON))
            out[0] ^= AES_RCON[round];
        else
            throw std::out_of_range("AES_RCON index out of range"); 

        return 0;

    }

    inline void __aes_xor_word(
        symmetric_ciphers::         __aes_u8    target[AES_WORD_SIZE],
        const symmetric_ciphers::   __aes_u8    operand[AES_WORD_SIZE]
    ) {

        for(int i = 0; i < AES_WORD_SIZE; ++i) 
            target[i] ^= operand[i];

    }

    void __aes_compute_remaining_words(
        symmetric_ciphers::         __aes_u8    words_required,
        symmetric_ciphers::         __aes_u8    exp_key[],
        symmetric_ciphers::         __aes_u8   &exp_offset,
        const symmetric_ciphers::   __aes_u16   exp_key_len,
        const symmetric_ciphers::   __aes_u16   act_key_len  
    ) {
        symmetric_ciphers::__aes_u8     temp_key_buff_1[AES_WORD_SIZE];
        symmetric_ciphers::__aes_u8     temp_key_buff_2[AES_WORD_SIZE];

        for(int i = 0; (i < words_required) && (exp_offset < exp_key_len); ++i) {
            memcpy(temp_key_buff_1, (exp_key + (exp_offset - AES_WORD_SIZE)), AES_WORD_SIZE);
            memcpy(temp_key_buff_2, (exp_key + (exp_offset - act_key_len)), AES_WORD_SIZE);        
            __aes_xor_word(temp_key_buff_1, temp_key_buff_2);
            memcpy((exp_key + exp_offset), temp_key_buff_1, AES_WORD_SIZE);
            exp_offset += AES_WORD_SIZE;
        }
    }

    void __aes_256_key_scheduler_5th_word(
        symmetric_ciphers::         __aes_u8    exp_key[],
        symmetric_ciphers::         __aes_u8   &exp_offset,
        const symmetric_ciphers::   __aes_u16   exp_key_len,
        const symmetric_ciphers::   __aes_u16   act_key_len  
    ) {

        symmetric_ciphers::__aes_u8     temp_key_buff_1[AES_WORD_SIZE];
        symmetric_ciphers::__aes_u8     temp_key_buff_2[AES_WORD_SIZE];

        if(exp_offset < exp_key_len) {

            memcpy(temp_key_buff_1, (exp_key + (exp_offset - AES_WORD_SIZE)), AES_WORD_SIZE);

            for(int i = 0; i < AES_WORD_SIZE; ++i)
                temp_key_buff_1[i] = AES_S_BOX[ temp_key_buff_1[i] ];

            memcpy(temp_key_buff_2, (exp_key + (exp_offset - act_key_len)), AES_WORD_SIZE);        
            __aes_xor_word(temp_key_buff_1, temp_key_buff_2);
            memcpy((exp_key + exp_offset), temp_key_buff_1, AES_WORD_SIZE);
            exp_offset += AES_WORD_SIZE;
        }

    }

} /* End of anonymous namespace */




/** 
 *  
 *  TODO: use pointer based XOR operation instead of loop - individual bytes & XOR
 *
 *  
 *
 *  
 *  
 *  
 */

