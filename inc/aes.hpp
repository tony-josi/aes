
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

#ifndef _AES_MAIN_HEADER_TJ__
#define _AES_MAIN_HEADER_TJ__

#include <cstdint>
#include <cstdio>
#include <memory>

namespace symmetric_ciphers {

    enum key_size {          /* Enum to handle different AES Modes */
        AES_128,               /* AES 128 bit key mode */
        AES_192,               /* AES 192 bit key mode */
        AES_256                /* AES 256 bit key mode */
    };

    enum aes_Action {
        _ENCRYPT_0__ = 0,
        _DECRYPT_1__
    };

    class AES {

    public:
        /**
         * @brief  Constructor
         */
        AES(key_size ks);

        /**
         * @brief  Function to encrypt 16 bytes of unsigned integer 8 bit type
         *         using AES ECB.
         */ 
        int encrpyt_16bytes_ecb(const uint8_t input[], const uint8_t key[], uint8_t output[]) const;

        /**
         * @brief  Function to decrypt 16 bytes of unsigned integer 8 bit type
         *         using AES ECB.
         */ 
        int decrpyt_16bytes_ecb(const uint8_t input[], const uint8_t key[], uint8_t output[]) const;

        /**
         * @brief  Function to encrypt given block of unsigned integer 8 bit type
         *         using AES ECB.
         */ 
        int encrpyt_block_ecb(const uint8_t input[], const uint8_t key[], uint8_t output[], \
        const size_t ip_size, const size_t key_size) const;

        /**
         * @brief  Function to decrypt given block of unsigned integer 8 bit type
         *         using AES ECB.
         */ 
        int decrpyt_block_ecb(const uint8_t input[], const uint8_t key[], uint8_t output[], \
        const size_t ip_size, const size_t key_size) const;

        /**
         * @brief  Function to encrypt given block of unsigned integer 8 bit type
         *         with AES ECB using threads.
         */ 
        int encrpyt_block_ecb_threaded(const uint8_t input[], const uint8_t key[], uint8_t output[], \
        const size_t ip_size, const size_t key_size) const;

        /**
         * @brief  Function to decrypt given block of unsigned integer 8 bit type
         *         with AES ECB using threads.
         */ 
        int decrpyt_block_ecb_threaded(const uint8_t input[], const uint8_t key[], uint8_t output[], \
        const size_t ip_size, const size_t key_size) const;

        /**
         * @brief  Function to encrypt given file
         *         with AES ECB using threads.
         */ 
        int encrpyt_file(const std::string &f_Name, const std::string &op_file_name, const uint8_t key[], const size_t key_size) const;

        /**
         * @brief  Function to decrypt given file
         *         with AES ECB using threads.
         */ 
        int decrpyt_file(const std::string &f_Name, const std::string &op_file_name, const uint8_t key[], const size_t key_size) const;

    private:
        size_t       actual_key_len;                  /* Stores the actual length of key in bytes */
        size_t       expanded_key_len;                /* Stores the expanded length of key in bytes */
        int          key_len_bits;                    /* Stores the length of the Key used in AES */
        int          block_size;                      /* Size of the data block used */
        int          round_num;                       /* Number of rounds performed */

        /**
         * @brief  Internal function to encrypt 16 bytes of data pointed to by ip_ptr
         *         thefrom the input[] using the expanded key, exp_key and copy the result
         *         to the output[] pointed to by ip_ptr.
         *         
         */ 
        int __perform_encryption__(const uint8_t input[], std::unique_ptr<uint8_t []> &exp_key, uint8_t output[], const int ip_ptr) const;

        /**
         * @brief  Internal function to decrypt 16 bytes of data pointed to by ip_ptr
         *         thefrom the input[] using the expanded key, exp_key and copy the result
         *         to the output[] pointed to by ip_ptr.
         *         
         */ 
        int __perform_decryption__(const uint8_t input[], std::unique_ptr<uint8_t []> &exp_key, uint8_t output[], const int ip_ptr) const;

        /**
         * @brief  Internal Function to encrypt/decrypt given data of unsigned integer 8 bit type
         *         with AES using threads.
         */ 
        int __ECB_threaded__(const uint8_t input[], const uint8_t key[], uint8_t output[], const size_t ip_size, const size_t key_size, const aes_Action action) const;

        /**
         * @brief  Internal Function to encrypt/decrypt given file
         *         with AES using threads.
         */ 
        int __process_File__(const std::string &f_Name, const std::string &op_file_name, const uint8_t key[], const size_t key_size, const aes_Action action) const;

    };

} /* namespace symmetric_ciphers */

#endif /* _AES_MAIN_HEADER_TJ__ */
