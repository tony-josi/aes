#include "inc/aes.hpp"

int main() {
    symmetric_ciphers::AES my_aes(symmetric_ciphers::key_size::AES_128);
    symmetric_ciphers::__aes_u8 my_key[33] = "HELLO_THIS_XS_651234567";
    symmetric_ciphers::__aes_u8 my_ip[16];
    symmetric_ciphers::__aes_u8 my_op[16];
    my_aes.encrpyt(my_ip, my_key, my_op);
    symmetric_ciphers::AES my_aes_copy = my_aes;
    my_aes_copy.encrpyt(my_ip, my_key, my_op);
    return 0;
}
