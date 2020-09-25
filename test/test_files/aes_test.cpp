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

    AES aes_128(AES_128);
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

    AES aes_128(AES_192);
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

int test_1_aes_256() {

    AES aes_128(AES_256);
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

int main(int argc, char **argv) {

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();

}
