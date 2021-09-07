/** 
 *  @file   aes_test.cpp
 *  @brief  AES Test Case File
 *
 *  This file contains test cases for testing 
 *  the AES Implementation.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */

#include "../inc/aes.hpp"
#include <iostream>

#include "gtest/gtest.h"


using namespace symmetric_ciphers;

int compare_bytes(uint8_t *a, uint8_t *b, size_t sz) {

    int flag = 0;
    for(int i = 0; i < static_cast<int>(sz); ++i)
        if(a[i] != b[i])
            flag = 1;

    return flag;

}

int test_1_aes_128() {

    AES aes_128(key_size::AES_128);
    uint8_t plaint[16] = "AES 128 Test";
    uint8_t passwd[16] = "AES128821!$";
    uint8_t op[16] = {0};
    uint8_t ciphert[16] = {0};
    aes_128.encrpyt_16bytes_ecb(plaint, passwd, ciphert);
    aes_128.decrpyt_16bytes_ecb(ciphert, passwd, op);

    if(compare_bytes(plaint, op, 16))
        return 1;

    return 0;

}

int test_1_aes_192() {

    AES aes_128(key_size::AES_192);
    uint8_t plaint[16] = "AES libgmockd";
    uint8_t passwd[24] = "AES128821!$";
    uint8_t op[16] = {0};
    uint8_t ciphert[16] = {0};
    aes_128.encrpyt_16bytes_ecb(plaint, passwd, ciphert);
    aes_128.decrpyt_16bytes_ecb(ciphert, passwd, op);

    if(compare_bytes(plaint, op, 16))
        return 1;

    return 0;

}

int test_1_aes_256() {

    AES aes_128(key_size::AES_256);
    uint8_t plaint[16] = "AES 128 Test";
    uint8_t passwd[32] = "libgmockd!$";
    uint8_t op[16] = {0};
    uint8_t ciphert[16] = {0};
    aes_128.encrpyt_16bytes_ecb(plaint, passwd, ciphert);
    aes_128.decrpyt_16bytes_ecb(ciphert, passwd, op);

    if(compare_bytes(plaint, op, 16))
        return 1;

    return 0;

}

int test_2_aes_128() {

    AES aes_128(key_size::AES_128);
    uint8_t plaint[128] = "And above all these put on love, "
    "which binds everything together in perfect harmony. [Colossians 3:14]"; 
    uint8_t passwd[16] = "Building!$";
    uint8_t op[128] = {0};
    uint8_t ciphert[128] = {0};
    aes_128.encrpyt_block_ecb(plaint, passwd, ciphert, 128, 16);
    aes_128.decrpyt_block_ecb(ciphert, passwd, op, 128, 16);

    if(compare_bytes(plaint, op, 128))
        return 1;

    return 0;
}

int test_2_aes_192() {

    AES aes_128(key_size::AES_192);
    uint8_t plaint[128] = "And above all these put on love, "
    "which binds everything together in perfect harmony. [Colossians 3:14]"; 
    uint8_t passwd[24] = "dependencies!$";
    uint8_t op[128] = {0};
    uint8_t ciphert[128] = {0};
    aes_128.encrpyt_block_ecb(plaint, passwd, ciphert, 128, 24);
    aes_128.decrpyt_block_ecb(ciphert, passwd, op, 128, 24);

    if(compare_bytes(plaint, op, 128))
        return 1;

    return 0;
}

int test_2_aes_256() {

    AES aes_128(key_size::AES_256);
    uint8_t plaint[128] = "And above all these put on love, "
    "which binds everything together in perfect harmony. [Colossians 3:14]"; 
    uint8_t passwd[32] = "libgtest_maind!$";
    uint8_t op[128] = {0};
    uint8_t ciphert[128] = {0};
    aes_128.encrpyt_block_ecb(plaint, passwd, ciphert, 128, 32);
    aes_128.decrpyt_block_ecb(ciphert, passwd, op, 128, 32);

    if(compare_bytes(plaint, op, 128))
        return 1;

    return 0;
}

#if 0

int main() {

    if(test_1_aes_128())
        std::cout<<"Fail\n";
    else
        std::cout<<"Pass\n";

    return 0;
}

#endif /* if 0 */

TEST(Test_16bytes_ecb_128, encrypt_decrypt) {

    EXPECT_EQ(test_1_aes_128(), 0);

}

TEST(Test_16bytes_ecb_192, encrypt_decrypt) {

    EXPECT_EQ(test_1_aes_192(), 0);

}

TEST(Test_16bytes_ecb_256, encrypt_decrypt) {

    EXPECT_EQ(test_1_aes_256(), 0);

}

TEST(Test_16block_ecb_128, encrypt_decrypt) {

    EXPECT_EQ(test_2_aes_128(), 0);

}

TEST(Test_16block_ecb_192, encrypt_decrypt) {

    EXPECT_EQ(test_2_aes_192(), 0);

}

TEST(Test_16block_ecb_256, encrypt_decrypt) {

    EXPECT_EQ(test_2_aes_256(), 0);

}

int main(int argc, char **argv) {

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();

}
