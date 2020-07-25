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

int main() {
    
    symmetric_ciphers::__aes_u8 my_key[] = "HELLO_THIS_XS_65";
    symmetric_ciphers::__aes_u8 my_ip[] = "**CHRIST_ALONE**"; //"2234567812345678";
    symmetric_ciphers::__aes_u8 my_op[17];
    symmetric_ciphers::__aes_u8 my_plain[17];
    
    /* Test for constructor with 128 bits */
    symmetric_ciphers::AES my_aes(symmetric_ciphers::key_size::AES_128);
    my_aes.encrpyt(my_ip, my_key, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%02X", my_op[i]);
    std::cout << std::endl;

    my_aes.decrpyt(my_op, my_key, my_plain);

    for(int i = 0; i < 16; ++i)
        std::printf("%c", my_plain[i]);
    std::cout << std::endl;

    /* Test for constructor with 192 bits */
    symmetric_ciphers::__aes_u8 my_ip2[] = "&&CHRIST_ALONE&&"; 
    symmetric_ciphers::AES my_aes_copy2(symmetric_ciphers::key_size::AES_192);
    symmetric_ciphers::__aes_u8 my_key2[33] = "HELLO_THIS_XS_651234567";
    my_aes_copy2.encrpyt(my_ip2, my_key2, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%02X", my_op[i]);
    std::cout << std::endl;

    my_aes_copy2.decrpyt(my_op, my_key2, my_plain);
    for(int i = 0; i < 16; ++i)
        std::printf("%c", my_plain[i]);
    std::cout << std::endl;

    /* Test for constructor with 256 bits */
    symmetric_ciphers::__aes_u8 my_ip3[] = "||CHRIST_ALONE||"; 
    symmetric_ciphers::AES my_aes_copy3(symmetric_ciphers::key_size::AES_256);
    symmetric_ciphers::__aes_u8 my_key3[33] = "12345678123456781234567812345678";
    my_aes_copy3.encrpyt(my_ip3, my_key3, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%02X", my_op[i]);
    std::cout << std::endl;

    my_aes_copy3.decrpyt(my_op, my_key3, my_plain);
    for(int i = 0; i < 16; ++i)
        std::printf("%c", my_plain[i]);
    std::cout << std::endl;

    symmetric_ciphers::__aes_u8 block_ip_test[128] = "What, then, shall we say in response to these things? If God is for us, who can be against us?"; 
    symmetric_ciphers::AES my_aes_copy4(symmetric_ciphers::key_size::AES_256);
    symmetric_ciphers::__aes_u8 block_ip_test_key[32] {0};
    symmetric_ciphers::__aes_u8 block_op_test[128] {0};
    symmetric_ciphers::__aes_u8 block_op_plain[128] {0};
    char pass[] = "my_password1";
    memcpy(block_ip_test_key, pass, sizeof(pass));
    my_aes_copy4.encrpyt_ecb(block_ip_test, block_ip_test_key, block_op_test, sizeof(block_ip_test), sizeof(block_ip_test_key));

    for(size_t i = 0; i < sizeof(block_ip_test); ++i)
        std::printf("%02X", block_op_test[i]);
    std::cout << std::endl;

    my_aes_copy4.decrpyt_ecb(block_op_test, block_ip_test_key, block_op_plain, sizeof(block_op_test), sizeof(block_ip_test_key));
    for(size_t i = 0; i < sizeof(block_ip_test); ++i)
        std::printf("%c", block_op_plain[i]);
    std::cout << std::endl;

    return 0;
}
