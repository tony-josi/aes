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

#include "aes.hpp"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>

using namespace symmetric_ciphers;

int main() {

    auto t1 = std::chrono::high_resolution_clock::now();

    uint8_t ip_text_128[16] = "testing aes 128";
    uint8_t key_128[16] = "123456781234567";
    uint8_t cipher_128[16];
    uint8_t plain_128[16];
    AES aes128(key_size::AES_128);
    aes128.encrpyt_16bytes_ecb(ip_text_128, key_128,cipher_128);
    aes128.decrpyt_16bytes_ecb(cipher_128, key_128, plain_128);
    for(size_t i = 0; i < sizeof(plain_128); ++i)
        std::printf("%c", plain_128[i]);
    std::cout << std::endl;

    uint8_t ip_text_192[16] = "testing aes 192";
    uint8_t key_192[24] = "12345678123456781234567";
    uint8_t cipher_192[16];
    uint8_t plain_192[16];
    AES aes192(key_size::AES_192);
    aes192.encrpyt_16bytes_ecb(ip_text_192, key_192,cipher_192);
    aes192.decrpyt_16bytes_ecb(cipher_192, key_192, plain_192);
    for(size_t i = 0; i < sizeof(plain_192); ++i)
        std::printf("%c", plain_192[i]);
    std::cout << std::endl;

    uint8_t ip_text_256[16] = "testing aes 256";
    uint8_t key_256[32] = "1234567812345678123456781234567";
    uint8_t cipher_256[16];
    uint8_t plain_256[16];
    AES aes256(key_size::AES_256);
    aes256.encrpyt_16bytes_ecb(ip_text_256, key_256,cipher_256);
    aes256.decrpyt_16bytes_ecb(cipher_256, key_256, plain_256);
    for(size_t i = 0; i < sizeof(plain_256); ++i)
        std::printf("%c", plain_256[i]);
    std::cout << std::endl;

    uint8_t block_ip_test[128] = "And above all these put on love, "
    "which binds everything together in perfect harmony. [Colossians 3:14]"; 
    uint8_t block_ip_test_key[32] {0};
    uint8_t block_op_test[128] {0};
    uint8_t block_op_plain[128] {0};
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

    uint8_t key_128_TRD[16] = "123456781234567";
    AES aes128_TRD(key_size::AES_128);
    const size_t test_sz = 1280000;     // 1.28 MB
    uint8_t *aes128_plain_TRD = static_cast<uint8_t *>(std::malloc(test_sz));
    uint8_t *aes128_cipher_TRD = static_cast<uint8_t *>(std::malloc(test_sz));
    uint8_t *aes128_op_TRD = static_cast<uint8_t *>(std::malloc(test_sz));

    aes128_plain_TRD[0] = 'J';
    aes128_plain_TRD[1] = 'E';
    aes128_plain_TRD[2] = 'S';
    aes128_plain_TRD[3] = 'U';
    aes128_plain_TRD[4] = 'S';
    aes128_plain_TRD[5] = ' ';

    for(size_t i = 6; i < test_sz; ++i)
        aes128_plain_TRD[i] = 0x4A;

    aes128_TRD.encrpyt_block_ecb_threaded(aes128_plain_TRD, key_128_TRD, aes128_cipher_TRD, test_sz, 16);
    aes128_TRD.decrpyt_block_ecb_threaded(aes128_cipher_TRD, key_128_TRD, aes128_op_TRD, test_sz, 16);
    
    std::cout << std::endl;
    for(size_t i = 0; i < 10; ++i)
        std::printf("%c", aes128_op_TRD[i]);
    std::cout << std::endl;
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();
    std::cout<<"\nDuration: "<<duration<<"\n";

    return 0;
}
