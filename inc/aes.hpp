  
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

    class AES {

        private:
            uint16_t key_len;           
            uint8_t block_size;
            uint8_t round_num;

        public:
            enum key_size {
                AES_128,
                AES_192,
                AES_256
            };
            explicit AES(AES::key_size ks);
            explicit AES(AES &aes);
            AES& operator=(const AES &aes);
            int encrpyt(const uint8_t input[], const uint8_t key[], uint8_t output[]) const;
            int decrpyt(const uint8_t input[], const uint8_t key[], uint8_t output[]) const;
            
    };

}