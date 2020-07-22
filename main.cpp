#include "inc/aes.hpp"
#include "iostream"
#include "cstdio"

int main() {
    
    symmetric_ciphers::__aes_u8 my_key[] = "HELLO_THIS_XS_65";
    symmetric_ciphers::__aes_u8 my_ip[] = "2234567812345678";
    symmetric_ciphers::__aes_u8 my_op[17];
    
    /* Test for constructor with 128 bits */
    symmetric_ciphers::AES my_aes(symmetric_ciphers::key_size::AES_128);
    my_aes.encrpyt(my_ip, my_key, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%0x", my_op[i]);
    std::cout << std::endl;

#if 0
    /* Test for copy constructor & copy assignment with 128 bits */
    symmetric_ciphers::AES my_aes_copy_cons(my_aes);
    my_aes_copy_cons.encrpyt(my_ip, my_key, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%0x", my_op[i]);
    std::cout << std::endl;

    symmetric_ciphers::AES my_aes_copy = my_aes;
    my_aes_copy.encrpyt(my_ip, my_key, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%0x", my_op[i]);
    std::cout << std::endl;

    /* Test for constructor with 192 bits */
    symmetric_ciphers::AES my_aes_copy2(symmetric_ciphers::key_size::AES_192);
    symmetric_ciphers::__aes_u8 my_key2[33] = "HELLO_THIS_XS_651234567";
    my_aes_copy2.encrpyt(my_ip, my_key2, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%0x", my_op[i]);
    std::cout << std::endl;
    
    /* Test for constructor with 256 bits */
    symmetric_ciphers::AES my_aes_copy3(symmetric_ciphers::key_size::AES_256);
    symmetric_ciphers::__aes_u8 my_key3[33] = "HELLO_THIS_XS_651234567812345678";
    my_aes_copy3.encrpyt(my_ip, my_key3, my_op);

    for(int i = 0; i < 16; ++i)
        std::printf("%0x", my_op[i]);
    std::cout << std::endl;
#endif
    return 0;
}
