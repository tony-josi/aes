## Advanced Encryption Standard

``` 
 █████╗     ███████╗    ███████╗
██╔══██╗    ██╔════╝    ██╔════╝
███████║    █████╗      ███████╗
██╔══██║    ██╔══╝      ╚════██║
██║  ██║    ███████╗    ███████║
╚═╝  ╚═╝    ╚══════╝    ╚══════╝
                                                                                          
```

The Advanced Encryption Standard (AES), also known by its original name Rijndael is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST).

This implementation currently supports Electronic codebook mode with support for 128/192/256 bit keys.

### High-level description of the algorithm
1. `KeyExpansion` – round keys are derived from the cipher key using the AES key schedule. AES requires a separate 128-bit round key block for each round plus one more.
2. Initial round key addition:
    1. `AddRoundKey` – each byte of the state is combined with a byte of the round key using bitwise xor.
    2. 9, 11 or 13 rounds:
        1. `SubBytes` – a non-linear substitution step where each byte is replaced with another according to a lookup table.
        2. `ShiftRows` – a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
        3. `MixColumns` – a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
        4. `AddRoundKey`
3. Final round (making 10, 12 or 14 rounds in total):
    1. `SubBytes`
    2. `ShiftRows`
    3. `AddRoundKey`


[refer](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## Usage

API provides 4 functions - `encrpyt_16bytes_ecb`, `decrpyt_16bytes_ecb`, `encrpyt_block_ecb`, `decrpyt_block_ecb`. 

`encrpyt_16bytes_ecb` & `decrpyt_16bytes_ecb` encrypts/decrypts 16 bytes of data.

`encrpyt_block_ecb` & `decrpyt_block_ecb` encrypts/decrypts given block of data which should be 16 bytes aligned (ie, input size % 16 == 0).

The library uses input data type as arrays of `__aes_u8`, which is a `typedef`ed to **`uint8_t`** - Unsigned Integer type with a width of exactly 8 bits.

#### Example for 16 bytes encrypt/decrypt

``` C++
#include "inc/aes.hpp"

using namespace symmetric_ciphers;

int main() {

    /* Input plain text */
    __aes_u8 ip_text_128[16] = "testing aes 128";

    /* 16 byte key */
    __aes_u8 key_128[16] = "123456781234567";
    
    /* Arrays to hold cipher text and decrypted plain text */
    __aes_u8 cipher_128[16];
    __aes_u8 plain_128[16];

    /* AES 128 bit key object creation */
    AES aes128(AES_128);

    /* Encrypt plain text (ip_text_128) to cipher_128 array */
    aes128.encrpyt_16bytes_ecb(ip_text_128, key_128, cipher_128);

    /* Decrypt cipher text (cipher_128) to plain_128 array */
    aes128.decrpyt_16bytes_ecb(cipher_128, key_128, plain_128);

    /* Display decrypted plain text */
    for(size_t i = 0; i < sizeof(plain_128); ++i)
        std::printf("%c", plain_128[i]);
    std::cout << std::endl;

    return 0;
}
``` 

#### Example for block data encrypt/decrypt

``` C++
#include "inc/aes.hpp"

using namespace symmetric_ciphers;

int main() {
    
    /* AES 256 bit key object creation */
    AES aes256(AES_256);
    
    /* Input plain text */
    __aes_u8 block_ip_test[128] = "And above all these put on love, which binds everything together in perfect harmony. [Colossians 3:14]"; 
    
    /* 32 byte key array */
    __aes_u8 block_ip_test_key[32] {0};
    char pass[] = "my_password1";
    memcpy(block_ip_test_key, pass, sizeof(pass));

    /* Arrays to hold cipher text and decrypted plain text */
    __aes_u8 block_op_test[128] {0};
    __aes_u8 block_op_plain[128] {0};

    /* Encrypt plain text (block_ip_test) to block_op_test array */
    aes256.encrpyt_block_ecb(block_ip_test, block_ip_test_key, block_op_test, sizeof(block_ip_test), sizeof(block_ip_test_key));
    
    /* Decrypt cipher text (block_op_test) to block_op_plain array */
    aes256.decrpyt_block_ecb(block_op_test, block_ip_test_key, block_op_plain, sizeof(block_op_test), sizeof(block_ip_test_key));
    
    /* Display decrypted plain text */
    for(size_t i = 0; i < sizeof(block_ip_test); ++i)
        std::printf("%c", block_op_plain[i]);
    std::cout << std::endl;

    return 0;
}
```

**Note:** The project objective was more of a way to learn C++, hence the efficiency and security side of this AES implementation may not be perfect.

#### To Do:
* Use pointer based XOR operation instead of loop - individual bytes & XOR
* Implement more API functions for encrypting larger chunks of data
* Implement other encryption modes - Cipher block chaining, Output feedback, Counter modes
* Implement algorithm for mix column & inverse mix column instead of lookup table for learning
