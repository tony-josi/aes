## Advanced Encryption Standard 

Current version: `v3.1.0`

#### Build Status:

[![Build Status](https://api.travis-ci.com/tony-josi/aes.svg?branch=master)](https://app.travis-ci.com/github/tony-josi/aes)

``` 
 █████╗     ███████╗    ███████╗
██╔══██╗    ██╔════╝    ██╔════╝
███████║    █████╗      ███████╗
██╔══██║    ██╔══╝      ╚════██║
██║  ██║    ███████╗    ███████║
╚═╝  ╚═╝    ╚══════╝    ╚══════╝
                                                                                          
```

The Advanced Encryption Standard (AES), also known by its original name Rijndael is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST).

This implementation currently supports Electronic Codebook (ECB)  mode with  128/192/256-bit keys and support for multi-threading for large file processing. Python bindings generation for the AES library is also supported for easy usage of the AES Library with python scripts.

###  Speed benchmark

Encrypts/Decrypts 2.6 GB data in ~7 seconds on a 2.90 GHz Hexa-Core Intel® Core™ i5-10400 CPU.

## Usage

### Build & Run

Requires [cmake](https://cmake.org/) to build. Optional - [google test](https://en.wikipedia.org/wiki/Google_Test) and [pybind11](https://pybind11.readthedocs.io/en/stable/faq.html)

Uses Google Test for unit testing.

1. Clone project - The project uses use [`google test`](https://en.wikipedia.org/wiki/Google_Test) and [`pybind11`](https://pybind11.readthedocs.io/en/stable/faq.html) external submodules, if testing and generation of python bindings for the AES library are required (not mandatory for normal build) then those external modules can be cloned using the command:  `git submodule update --init --recursive`.

2. Build project - The project uses CMake generator for generating build files. Use `-DENABLE_TESTING=ON` for building test library and test cases and `-DPYTHON_BINDINGS_GEN=ON` for generating python bindings module.

``` sh
cd aes
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=OFF -DLOW_LEVEL_API_SAMPLE=ON -DWARNINGS_AS_ERRORS=OFF -DENABLE_IPO=ON 
# Test disabled; use -DENABLE_TESTING=ON to build test cases executable. Not building python bindings by default, use -DPYTHON_BINDINGS_GEN=ON if required.
```

After generating the build files the target can be build using the build tools supported by the current platform. (`make` for Unix systems, `Visual Studio` for Windows and `Xcode` for macOS)


### AES Methods (API)

AES Class provides 6 methods - `encrpyt_16bytes_ecb`, `decrpyt_16bytes_ecb`, `encrpyt_block_ecb`, `decrpyt_block_ecb`, `encrpyt_block_ecb_threaded` & `decrpyt_block_ecb_threaded`. 

`encrpyt_16bytes_ecb` & `decrpyt_16bytes_ecb` encrypts/decrypts 16 bytes of data.

`encrpyt_block_ecb` & `decrpyt_block_ecb` encrypts/decrypts given block of data which should be 16 bytes aligned (ie, input size % 16 == 0).

`encrpyt_block_ecb_threaded` & `decrpyt_block_ecb_threaded` encrypts/decrypts given block of data which should be 16 bytes aligned (ie, input size % 16 == 0) with multithread support.

The library uses input data type as arrays of type **`uint8_t`** - Unsigned Integer type with a width of exactly 8 bits.

#### Example for 16 bytes encrypt/decrypt

``` C++
#include "inc/aes.hpp"

using namespace symmetric_ciphers;

int main() {

    /* Input plain text */
    uint8_t ip_text_128[16] = "testing aes 128";

    /* 16 byte key */
    uint8_t key_128[16] = "123456781234567";
    
    /* Arrays to hold cipher text and decrypted plain text */
    uint8_t cipher_128[16];
    uint8_t plain_128[16];

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
    uint8_t block_ip_test[128] = "And above all these put on love, "
    "which binds everything together in perfect harmony. [Colossians 3:14]"; 
    
    /* 32 byte key array */
    uint8_t block_ip_test_key[32] {0};
    char pass[] = "my_password1";
    memcpy(block_ip_test_key, pass, sizeof(pass));

    /* Arrays to hold cipher text and decrypted plain text */
    uint8_t block_op_test[128] {0};
    uint8_t block_op_plain[128] {0};

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

#### Large file encryption API with multi-threaded file IO

For example usage please refer to [`process_file.cpp`](https://github.com/TonyJosi97/aes/blob/master/src/process_file.cpp) file

### Example usage of the python bindings module

If `-DPYTHON_BINDINGS_GEN=ON` option is given during the CMake build file generation the build tools will build the python bindings, the default name for the python module is `py_sc_aes`.

The following code demonstrates the simple usage:

``` py
import py_sc_aes
import sys, time

if __name__ == "__main__":

    if len(sys.argv) >= 4:

        prev_time = time.time()
        aes_128_obj = py_sc_aes.AES(py_sc_aes.AES_128)
        if sys.argv[1] == "e":
            print(aes_128_obj.encrypt_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        elif sys.argv[1] == "d":
            print(aes_128_obj.decrypt_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        if sys.argv[1] == "x":
            print(aes_128_obj.encrypt_large_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        elif sys.argv[1] == "y":
            print(aes_128_obj.decrypt_large_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        print("Duration: ", (time.time() - prev_time) * 1000)

```
### Algorithm
1. `KeyExpansion` – round keys are derived from the cipher key using the AES key schedule. AES requires a separate 128-bit round key block for each round plus one more.
2. Initial round key addition:
    1. `AddRoundKey` – each byte of the state is combined with a byte of the round key using bitwise xor.
    2. 9, 11 or 13 rounds:
        1. `SubBytes` – a non-linear substitution step where each byte is replaced with another according to a lookup table.
        2. `ShiftRows` – a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
        3. `MixColumns` – a linear mixing operation that operates on the columns of the state, combining the four bytes in each column.
        4. `AddRoundKey`
3. Final round (making 10, 12 or 14 rounds in total):
    1. `SubBytes`
    2. `ShiftRows`
    3. `AddRoundKey`

[refer](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

#### v3.0 Update Notes

* Added python bindings for the AES library for file encryption/decryption
* Changed file IO to use basic_stream lib of C++ instead of open() to fix a bug arising from the incorrect calculation of file size for larger files
* Changed plain enums to enum classes
* Changed iteration variable type to size_t to support larger files
* Added D_CRT_SECURE_NO_WARNINGS option to cmake file if the target platform is MSVC to avoid error/warning about fopen() in Visual Studio
* Removed warnings associated with string lib header not used in the AES lib.

#### To Do:
* Use pointer based XOR operation instead of a loop - individual bytes & XOR
* Implement other encryption modes - Cipher block chaining, Output feedback, Counter modes
* Implement algorithm for mix column & inverse mix column instead of a lookup table for learning

###### File TODO:
* Complete todo


#### Notes:

When the file_process.exe is debugged from the Visual Studio its path will be: D:\Projects\aes\build\src
