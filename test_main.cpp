/** 
 *  @file   main.cpp
 *  @brief  AES Test File
 *
 *  This file tests AES Implementation 128/192/256 bit modes.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */

#include "inc/aes.hpp"
#include <iostream>
#include <cstdio>

using namespace symmetric_ciphers;

int main() {

    __aes_u8 ip_text_128[16] = "testing aes 128";
    __aes_u8 key_128[16] = "123456781234567";
    __aes_u8 cipher_128[16];
    __aes_u8 plain_128[16];
    AES aes128(AES_128);
    aes128.encrpyt_16bytes_ecb(ip_text_128, key_128,cipher_128);
    aes128.decrpyt_16bytes_ecb(cipher_128, key_128, plain_128);
    for(size_t i = 0; i < sizeof(plain_128); ++i)
        std::printf("%c", plain_128[i]);
    std::cout << std::endl;

    __aes_u8 ip_text_192[16] = "testing aes 192";
    __aes_u8 key_192[24] = "12345678123456781234567";
    __aes_u8 cipher_192[16];
    __aes_u8 plain_192[16];
    AES aes192(AES_192);
    aes192.encrpyt_16bytes_ecb(ip_text_192, key_192,cipher_192);
    aes192.decrpyt_16bytes_ecb(cipher_192, key_192, plain_192);
    for(size_t i = 0; i < sizeof(plain_192); ++i)
        std::printf("%c", plain_192[i]);
    std::cout << std::endl;

    __aes_u8 ip_text_256[16] = "testing aes 256";
    __aes_u8 key_256[32] = "1234567812345678123456781234567";
    __aes_u8 cipher_256[16];
    __aes_u8 plain_256[16];
    AES aes256(AES_256);
    aes256.encrpyt_16bytes_ecb(ip_text_256, key_256,cipher_256);
    aes256.decrpyt_16bytes_ecb(cipher_256, key_256, plain_256);
    for(size_t i = 0; i < sizeof(plain_256); ++i)
        std::printf("%c", plain_256[i]);
    std::cout << std::endl;

    __aes_u8 block_ip_test[128] = "And above all these put on love, "
    "which binds everything together in perfect harmony. [Colossians 3:14]"; 
    __aes_u8 block_ip_test_key[32] {0};
    __aes_u8 block_op_test[128] {0};
    __aes_u8 block_op_plain[128] {0};
    char pass[] = "my_password1";
    memcpy(block_ip_test_key, pass, sizeof(pass));
    aes256.encrpyt_block_ecb(block_ip_test, block_ip_test_key, block_op_test, sizeof(block_ip_test), sizeof(block_ip_test_key));
    aes256.decrpyt_block_ecb(block_op_test, block_ip_test_key, block_op_plain, sizeof(block_op_test), sizeof(block_ip_test_key));
    for(size_t i = 0; i < sizeof(block_ip_test); ++i)
        std::printf("%c", block_op_plain[i]);
    std::cout << std::endl;

    AES copy_aes256(aes256);        /* testing default copy constructor */
    memcpy(block_ip_test_key, pass, sizeof(pass));
    copy_aes256.encrpyt_block_ecb(block_ip_test, block_ip_test_key, block_op_test, sizeof(block_ip_test), sizeof(block_ip_test_key));
    copy_aes256.decrpyt_block_ecb(block_op_test, block_ip_test_key, block_op_plain, sizeof(block_op_test), sizeof(block_ip_test_key));
    for(size_t i = 0; i < sizeof(block_ip_test); ++i)
        std::printf("%c", block_op_plain[i]);
    std::cout << std::endl;

    aes192 = copy_aes256;           /* testing default copy assignment constructor */
    memcpy(block_ip_test_key, pass, sizeof(pass));
    aes192.encrpyt_block_ecb(block_ip_test, block_ip_test_key, block_op_test, sizeof(block_ip_test), sizeof(block_ip_test_key));
    aes192.decrpyt_block_ecb(block_op_test, block_ip_test_key, block_op_plain, sizeof(block_op_test), sizeof(block_ip_test_key));
    for(size_t i = 0; i < sizeof(block_ip_test); ++i)
        std::printf("%c", block_op_plain[i]);
    std::cout << std::endl;

    return 0;
}
