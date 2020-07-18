
/** 
 *  @file   aes.hpp
 *  @brief  AES Main Header File
 *
 *  This contains the Headers for the AES main file
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */

#include <cstdint>

namespace symmetric_ciphers {

    typedef uint8_t __aes_u8;
    typedef uint16_t __aes_u16;
    typedef uint32_t __aes_u32;

    enum key_size {          /* Enum to handle different AES Modes */
      AES_128,               /* AES 128 bit key mode */
      AES_192,               /* AES 192 bit key mode */
      AES_256                /* AES 256 bit key mode */
    };

    class AES {

    private:
        uint16_t key_len;    /* Stores the length of the Key used in AES */
        uint8_t block_size;  /* Size of the data block used */
        uint8_t round_num;   /* Number of rounds performed */

    public:
        /* Constructor */
        explicit AES(key_size ks);

        /* Copy Constructor */
        explicit AES(AES &aes);

        /* Assignment operator for copy constructor */
        AES &operator=(const AES &aes);

        /* Function to encrypt unsigned char array using AES */
        int encrpyt(const __aes_u8 input[], const __aes_u8 key[], __aes_u8 output[]) const;

        /* Function to decrypt unsigned char array using AES */
        int decrpyt(const __aes_u8 input[], const __aes_u8 key[], __aes_u8 output[]) const;
    };

} /* namespace symmetric_ciphers */