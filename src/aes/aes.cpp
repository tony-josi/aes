/** 
 *  @file   aes.cpp
 *  @brief  AES Main Source File
 *
 *  This file contains the Source Code for the AES Implementation.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */

#include "../inc/aes.hpp"

#include <stdexcept>
#include <string>
#include <algorithm>
#include <cstring>
#include <vector>
#include <mutex>
#include <functional>
#include <thread>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <chrono>

namespace {

    /* AES Word size */
    constexpr   uint8_t     AES_WORD_SIZE                  = 4;

    /* 12.8 KB per data segment. */
    constexpr   int         AES_DATA_SIZE_PER_SEGMENT      = 12800;  
    constexpr   size_t      FILE_IO_CHUNK_SIZE_BYTES       = 12800000;

    /* Metdata size should be (AES_WORD_SIZE * AES_WORD_SIZE) */ 
    constexpr   size_t      AES_META_DATA_SIZE             = AES_WORD_SIZE * AES_WORD_SIZE;  
    constexpr   size_t      AES_META_DATA_PADD_SIZE_OFFSET = 0; 
    constexpr   size_t      AES_META_DATA_CHECK_SUM_OFFSET = 8; 

    /* Maximum supported plain text key size. */
    constexpr   size_t      MAX_SUPPORTED_PLAIN_KEY_SIZE   = 32;

    /* Plain text key size. */
    constexpr   size_t      AES128_PLAIN_KEY_SIZE          = 16;
    constexpr   size_t      AES192_PLAIN_KEY_SIZE          = 24;
    constexpr   size_t      AES256_PLAIN_KEY_SIZE          = 32;

    /* Forward declarations for Lookup tables */
    extern      uint8_t     AES_S_BOX[256];
    extern      uint8_t     AES_INV_S_BOX[256];
    extern      uint8_t     MUL_2[256];
    extern      uint8_t     MUL_3[256];
    extern      uint8_t     MUL_9[256];
    extern      uint8_t     MUL_11[256];
    extern      uint8_t     MUL_13[256];
    extern      uint8_t     MUL_14[256];
    extern      uint8_t     AES_RCON[11];

    /* Forward declarations for helper functions */
    size_t __aes_expand_key(
        const uint8_t               key[], 
        uint8_t                     expand_key[], 
        const size_t                actual_key_len,
        const size_t                expand_key_len
    );

    int __aes_key_scheduler(
        int                         round,
        const uint8_t               in[AES_WORD_SIZE],
        uint8_t                     out[AES_WORD_SIZE]
    );

    inline void __aes_xor_word(
        uint8_t                     target[AES_WORD_SIZE],
        const uint8_t               operand[AES_WORD_SIZE]
    );

    inline void __aes_transposition(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
        const uint8_t               ip[],
        const size_t                offset
    );

    inline void __aes_rev_transposition(
        const uint8_t               cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
        uint8_t                     op[],
        const size_t                offset
    );

    void __aes_compute_remaining_words(
        int                         words_required,
        uint8_t                     exp_key[],
        size_t                     &exp_offset,
        const size_t                exp_key_len,
        const size_t                act_key_len  
    );

    void __aes_key_scheduler_4th_word(
        uint8_t                     exp_key[],
        size_t                     &exp_offset,
        const size_t                exp_key_len,
        const size_t                act_key_len  
    );

    void __aes_get_round_key_block(
        size_t                      round_count,
        size_t                      block_size,
        const uint8_t               exp_key[],
        size_t                      exp_key_len,
        uint8_t                     op_key[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_add_round_key(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
        uint8_t                     round_key[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_substitue_bytes(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_shift_rows(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_mix_columns(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_inv_substitue_bytes(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_inv_shift_rows(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    void __aes_inv_mix_columns(
        uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    );

    size_t __get_File_Size(
        std::unique_ptr<FILE, decltype(&fclose)> &file_Ptr
    );

    std::streampos __get_File_Size_Fstream(
        std::ifstream& ip_file_strm
    );

    uint32_t __aes_calculate_Checksum(
        uint8_t                     buffer[],
        size_t                      siz_
    );

    class file_io_chunk_map_t {
    public:
        size_t      chunk_id;
        size_t      file_indx;
        size_t      chunk_size;
        uint8_t     chunk_data[FILE_IO_CHUNK_SIZE_BYTES];
        bool        last_chunk;
    };

    class file_io_process_DataQueue {
    public:
        std::mutex                                              fiop_Mutex;
        std::vector<std::unique_ptr<file_io_chunk_map_t>>       fiop_DataQueue;
        std::vector<std::unique_ptr<file_io_chunk_map_t>>       fiip_DataQueue;
        std::ofstream                                           op_file_stream;
        bool                                                    encrpt_complete;

        file_io_process_DataQueue(const std::string& op_f_name) {
            op_file_stream = std::ofstream(op_f_name, std::ios::binary);
        }

        ~file_io_process_DataQueue() {
            op_file_stream.close();
        }

        bool pop_and_process_data() {

            std::unique_ptr<file_io_chunk_map_t> cur_chunk;
            std::unique_lock<std::mutex> fio_pop_LOCK(fiop_Mutex);
            if (encrpt_complete == true && fiop_DataQueue.empty() == true) {
                fio_pop_LOCK.unlock();
                return false;
            }
            else if (fiop_DataQueue.empty() != true) {
                cur_chunk = std::move(fiop_DataQueue.back());
                fiop_DataQueue.pop_back();
            }
            else {
                fio_pop_LOCK.unlock();
                return true;
            }

            fio_pop_LOCK.unlock();

            op_file_stream.seekp(cur_chunk.get()->file_indx);
            op_file_stream.write(reinterpret_cast<char*>(cur_chunk.get()->chunk_data), cur_chunk.get()->chunk_size);
            std::cout << "Wrote: " << cur_chunk.get()->chunk_id << " Chunk, size: " << cur_chunk.get()->chunk_size << "\n";

            return true;

        }

    };

} /* End of anonymous namespace */


/**
  * @brief  Constructor
  * 
  * @param  [in] ks      Preferred key size, the argument should be a member of the enum
  *                      #key_size. 
  * 
  * @note   The constructor method initialises the class private variables with 
  *         default values depending on the #key_size argument.
  *         
  * @retval None
  */
symmetric_ciphers::AES::AES(symmetric_ciphers::key_size ks) {

    this->block_size = AES_WORD_SIZE * AES_WORD_SIZE;
    switch(ks) {
    case key_size::AES_128:
        this->key_len_bits = 128;
        this->round_num = 10;
        this->actual_key_len = AES128_PLAIN_KEY_SIZE;
        this->expanded_key_len = 176;
        break;
    case key_size::AES_192:
        this->key_len_bits = 192;
        this->round_num = 12;
        this->actual_key_len = AES192_PLAIN_KEY_SIZE;
        this->expanded_key_len = 208;
        break;
    case key_size::AES_256:
        this->key_len_bits = 256;
        this->round_num = 14;
        this->actual_key_len = AES256_PLAIN_KEY_SIZE;
        this->expanded_key_len = 240;
        break;
    default:
        throw std::invalid_argument("Unsupported Key Length, supports 128/192/256");
    }
}


/**
  * @brief  Function to encrypt 16 bytes of unsigned integer 8 bit type
  *         using AES ECB.
  * 
  * @param  [in]  input      Input plain text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output cipher text array.
  * 
  * @note   This method encrypts the given plain text array of size 16 bytes using
  *         the given #key and outputs it to the output cipher text array.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::encrpyt_16bytes_ecb(
    const uint8_t       input[], 
    const uint8_t       key[], 
    uint8_t             output[]
) const {

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(key, exp_key.get(), this->actual_key_len, this->expanded_key_len);

    this->__perform_encryption__(input, exp_key, output, 0);

    return 0;

}


/**
  * @brief  Function to decrypt 16 bytes of unsigned integer 8 bit type
  *         using AES ECB.
  * 
  * @param  [in]  input      Input plain text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output cipher text array.
  * 
  * @note   This method decrypts the given cipher text input array of size 16 bytes using
  *         the given #key and outputs it to the output plain text array.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::decrpyt_16bytes_ecb(
    const uint8_t           input[], 
    const uint8_t           key[], 
    uint8_t                 output[]
    ) const {

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(key, exp_key.get(), this->actual_key_len, this->expanded_key_len);

    this->__perform_decryption__(input, exp_key, output, 0);

    return 0;

}


/**
  * @brief  Function to encrypt given block of unsigned integer 8 bit type
  *         using AES ECB.
  * 
  * @param  [in]  input      Input plain text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output cipher text array.
  * @param  [in]  ip_size    Input plain text array size.
  * @param  [in]  key_size   Key array size.
  * 
  * @note   This method encrypts the given plain text input array of using
  *         the given #key and outputs it to the output cipher text array.
  * 
  * @note   The input & output array should be of same size and should be 16 byte 
  *         aligned, ie. ip_size % 16 == 0.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::encrpyt_block_ecb(
    const uint8_t           input[], 
    const uint8_t           key[], 
    uint8_t                 output[], 
    const size_t            ip_size,
    const size_t            key_size
    ) const {

    /* Check whether the given arguments are of required size */
    if((ip_size % (AES_WORD_SIZE * AES_WORD_SIZE)) != 0)
        throw std::invalid_argument("encrpyt_block_ecb() - argument ip_size should be 16 byte aligned");
    if(key_size != this->actual_key_len)
        throw std::invalid_argument("encrpyt_block_ecb() - key size should be 16/24/32 bytes "
        "depending on AES - 128/192/256 bit modes used");

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(key, exp_key.get(), this->actual_key_len, this->expanded_key_len);

    /* Loop through the input plain text array, processing 16 bytes of data every iteration */
    for(size_t ip_iter = 0; (ip_iter * this->block_size) < ip_size; ++ip_iter) {

        this->__perform_encryption__(input, exp_key, output, (ip_iter * this->block_size));
    
    }

    return 0;

}

/**
  * @brief  Function to decrypt given block of unsigned integer 8 bit type
  *         using AES ECB.
  * 
  * @param  [in]  input      Input cipher text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output plain text array.
  * @param  [in]  ip_size    Input cipher text array size.
  * @param  [in]  key_size   Key array size.
  * 
  * @note   This method decrypts the given cipher text input array of using
  *         the given #key and outputs it to the output plain text array.
  * 
  * @note   The input & output array should be of same size and should be 16 byte 
  *         aligned, ie. ip_size % 16 == 0.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::decrpyt_block_ecb(
    const uint8_t               input[], 
    const uint8_t               key[], 
    uint8_t                     output[], 
    const size_t                ip_size,
    const size_t                key_size
    ) const {

    /* Check whether the given arguments are of required size */
    if((ip_size % (AES_WORD_SIZE * AES_WORD_SIZE)) != 0)
        throw std::invalid_argument("decrpyt_block_ecb() - argument ip_size should be 16 byte aligned");
    if(key_size != this->actual_key_len)
        throw std::invalid_argument("decrpyt_block_ecb() - key size should be 16/24/32 bytes "
        "depending on AES - 128/192/256 bit modes used");

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(key, exp_key.get(), this->actual_key_len, this->expanded_key_len);

    /* Loop through the input cipher text array, processing 16 bytes of data every iteration */
    for(size_t ip_iter = 0; (ip_iter * this->block_size) < ip_size; ++ip_iter) {

        this->__perform_decryption__(input, exp_key, output, (ip_iter * this->block_size));

    }

    return 0;
    
}

/**
  * @brief  Function to encrypt given block of unsigned integer 8 bit type
  *         wiht AES ECB, using multiple threads.
  * 
  * @param  [in]  input      Input cipher text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output plain text array.
  * @param  [in]  ip_size    Input cipher text array size.
  * @param  [in]  key_size   Key array size.
  * 
  * @note   This method encrypts the given cipher text input array of using
  *         the given #key and outputs it to the output plain text array.
  * 
  * @note   The input & output array should be of same size and should be 16 byte 
  *         aligned, ie. ip_size % 16 == 0.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::encrpyt_block_ecb_threaded(
    const uint8_t               input[], 
    const uint8_t               key[], 
    uint8_t                     output[], 
    const size_t                ip_size,
    const size_t                key_size
    ) const {

    return this->__ECB_threaded__(input, key, output, ip_size, key_size, aes_Action::_ENCRYPT_0__);

}

/**
  * @brief  Function to decrypt given block of unsigned integer 8 bit type
  *         wiht AES ECB, using multiple threads.
  * 
  * @param  [in]  input      Input cipher text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output plain text array.
  * @param  [in]  ip_size    Input cipher text array size.
  * @param  [in]  key_size   Key array size.
  * 
  * @note   This method decrypts the given cipher text input array of using
  *         the given #key and outputs it to the output plain text array.
  * 
  * @note   The input & output array should be of same size and should be 16 byte 
  *         aligned, ie. ip_size % 16 == 0.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::decrpyt_block_ecb_threaded(
    const uint8_t               input[], 
    const uint8_t               key[], 
    uint8_t                     output[], 
    const size_t                ip_size,
    const size_t                key_size
    ) const {

    return this->__ECB_threaded__(input, key, output, ip_size, key_size, aes_Action::_DECRYPT_1__);

}

/**
  * @brief  Function to encrypt given file with AES ECB using threads.
  * 
  * @param  [in]  f_Name     File name to encrypt.
  * @param  [in]  input      Input cipher text array.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::encrpyt_file(
    const std::string          &f_Name,
    const std::string          &op_file_name, 
    const uint8_t               key[],
    const size_t                key_size 
    ) const {

    return this->__process_File__ENC(f_Name, op_file_name, key, key_size);
    
}

/**
  * @brief  Function to decrypt given file with AES ECB using threads.
  * 
  * @param  [in]  f_Name     File name to decrypt.
  * @param  [in]  input      Input cipher text array.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::decrpyt_file(
    const std::string          &f_Name,
    const std::string          &op_file_name, 
    const uint8_t               key[],
    const size_t                key_size 
    ) const {

    return this->__process_File__DEC(f_Name, op_file_name, key, key_size);

}

/**
  * @brief  Function to encrypt given file
  *         with AES ECB using threads. This function acts as the target 
  *         method for pybind11 bindings for encrpyt_file()
  * 
  * @param  [in]  f_Name     File name to encrypt.
  * @param  [in]  input      Output file name.
  * @param  [in]  key        Decryption key.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::encrpyt_file__pybind_target(
    const std::string          &f_Name,
    const std::string          &op_file_name, 
    const std::string          &key 
    ) const {

    uint8_t initzd_key[MAX_SUPPORTED_PLAIN_KEY_SIZE] = { 0 };    /* Max. supported key size. */
    size_t key_len = key.length();
    size_t reqd_key_len;

    switch (this->actual_key_len) {
    case AES128_PLAIN_KEY_SIZE:
        reqd_key_len = AES128_PLAIN_KEY_SIZE;
        std::memcpy(initzd_key, key.c_str(), key_len < AES128_PLAIN_KEY_SIZE ? key_len : AES128_PLAIN_KEY_SIZE);
        break;
    case AES192_PLAIN_KEY_SIZE:
        reqd_key_len = AES192_PLAIN_KEY_SIZE;
        std::memcpy(initzd_key, key.c_str(), key_len < AES192_PLAIN_KEY_SIZE ? key_len : AES192_PLAIN_KEY_SIZE);
        break;
    case AES256_PLAIN_KEY_SIZE:
        reqd_key_len = AES256_PLAIN_KEY_SIZE;
        std::memcpy(initzd_key, key.c_str(), key_len < AES256_PLAIN_KEY_SIZE ? key_len : AES256_PLAIN_KEY_SIZE);
        break;
    default:
        throw std::invalid_argument("Error parsing key");
    }

    return this->__process_File__ENC(f_Name, op_file_name, initzd_key, reqd_key_len);

}

/**
  * @brief  Function to decrypt given file
  *         with AES ECB using threads. This function acts as the target 
  *         method for pybind11 bindings for decrpyt_file()
  * @param  [in]  f_Name     File name to decrypt.
  * @param  [in]  input      Output file name.
  * @param  [in]  key        Decryption key.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::decrpyt_file__pybind_target(
    const std::string          &f_Name,
    const std::string          &op_file_name, 
    const std::string          &key 
    ) const {

    uint8_t initzd_key[MAX_SUPPORTED_PLAIN_KEY_SIZE] = { 0 };    /* Max. supported key size. */
    size_t key_len = key.length();
    size_t reqd_key_len;

    switch (this->actual_key_len) {
    case AES128_PLAIN_KEY_SIZE:
        reqd_key_len = AES128_PLAIN_KEY_SIZE;
        std::memcpy(initzd_key, key.c_str(), key_len < AES128_PLAIN_KEY_SIZE ? key_len : AES128_PLAIN_KEY_SIZE);
        break;
    case AES192_PLAIN_KEY_SIZE:
        reqd_key_len = AES192_PLAIN_KEY_SIZE;
        std::memcpy(initzd_key, key.c_str(), key_len < AES192_PLAIN_KEY_SIZE ? key_len : AES192_PLAIN_KEY_SIZE);
        break;
    case AES256_PLAIN_KEY_SIZE:
        reqd_key_len = AES256_PLAIN_KEY_SIZE;
        std::memcpy(initzd_key, key.c_str(), key_len < AES256_PLAIN_KEY_SIZE ? key_len : AES256_PLAIN_KEY_SIZE);
        break;
    default:
        throw std::invalid_argument("Error parsing key");
    }

    return this->__process_File__DEC(f_Name, op_file_name, initzd_key, reqd_key_len);

}

/**
  * @brief  Internal Function encrypt the given 16 bytes if data.
  * 
  * @param  [in]  input         Input array.
  * @param  [in]  exp_key       Expanded key.
  * @param  [in]  output        Output array.
  * @param  [in]  ip_ptr        Offset pointing to the current section
  *                             of data to be processed in the input array.
  *         
  * @retval Status:
  *             - 0         Success.
  */
inline int symmetric_ciphers::AES::__perform_encryption__(
    const uint8_t                   input[], 
    std::unique_ptr<uint8_t []>    &exp_key, 
    uint8_t                         output[],
    const size_t                    ip_ptr
    ) const {

    uint8_t cur_state[4][4] = {{0}};

    /* Transposition bytes to matrix form - column major */
    __aes_transposition(cur_state, input, ip_ptr);

    /* Initial round key addition */
    uint8_t round_key[AES_WORD_SIZE][AES_WORD_SIZE] = {{0}};
    __aes_get_round_key_block(0, this->block_size, exp_key.get(), \
    this->expanded_key_len, round_key);

    __aes_add_round_key(cur_state, round_key);

    /* Remaining rounds of aes */
    for(size_t i = 1; i <= this->round_num; ++i) {
        __aes_get_round_key_block(i, this->block_size, exp_key.get(), \
        this->expanded_key_len, round_key);

        __aes_substitue_bytes(cur_state);
        __aes_shift_rows(cur_state);
        /* Mix column is not performed for last round */
        if(i != this->round_num)
            __aes_mix_columns(cur_state);
        __aes_add_round_key(cur_state, round_key);
        
    }

    /* Transposition bytes from matrix (column major) back to output array */
    __aes_rev_transposition(cur_state, output, ip_ptr);

    return 0;
}

/**
  * @brief  Internal Function decrypt the given 16 bytes if data.
  * 
  * @param  [in]  input         Input array.
  * @param  [in]  exp_key       Expanded key.
  * @param  [in]  output        Output array.
  * @param  [in]  ip_ptr        Offset pointing to the current section
  *                             of data to be processed in the input array.
  *         
  * @retval Status:
  *             - 0         Success.
  */
inline int symmetric_ciphers::AES::__perform_decryption__(
    const uint8_t                   input[], 
    std::unique_ptr<uint8_t []>    &exp_key, 
    uint8_t                         output[],
    const size_t                    ip_ptr
    ) const {

    /* 2D - Array (matrix) to hold the current round state */
    uint8_t cur_state[4][4] = {{0}};

    /* Transposition bytes to matrix form - column major */
    __aes_transposition(cur_state, input, ip_ptr);
    
    /* Initial round key addition */
    uint8_t round_key[AES_WORD_SIZE][AES_WORD_SIZE] = {{0}};
    __aes_get_round_key_block(this->round_num, this->block_size, \
    exp_key.get(), this->expanded_key_len, round_key);

    __aes_add_round_key(cur_state, round_key);

    /* Remaining rounds of aes */
    for(size_t i = this->round_num; i >= 1; --i) {

        __aes_get_round_key_block(i - 1, this->block_size, exp_key.get(), \
        this->expanded_key_len, round_key);

        __aes_inv_shift_rows(cur_state);
        __aes_inv_substitue_bytes(cur_state);
        __aes_add_round_key(cur_state, round_key);
        /* Mix column is not performed for last round */
        if((i - 1) != 0)
            __aes_inv_mix_columns(cur_state);        

    }

    /* Transposition bytes from matrix (column major) back to output array */
    __aes_rev_transposition(cur_state, output, ip_ptr);

    return 0;
}

/**
  * @brief  Function to process (encrypt/decrypt) given data of unsigned integer 8 bit type
  *         using AES ECB.
  * 
  * @param  [in]  input      Input plain text array.
  * @param  [in]  key        AES Key for encryption.
  * @param  [out] output     Output cipher text array.
  * @param  [in]  ip_size    Input plain text array size.
  * @param  [in]  key_size   Key array size.
  * @param  [in]  action     Encrypt or Decrypt.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::__ECB_threaded__(
    const uint8_t           input[], 
    const uint8_t           key[], 
    uint8_t                 output[], 
    const size_t            ip_size,
    const size_t            key_size,
    const aes_Action        action
    ) const {

    /* Check whether the given arguments are of required size */
    if((ip_size % (AES_WORD_SIZE * AES_WORD_SIZE)) != 0)
        throw std::invalid_argument("encrpyt_block_ecb() - argument ip_size should be 16 byte aligned");
    if(key_size != this->actual_key_len)
        throw std::invalid_argument("encrpyt_block_ecb() - key size should be 16/24/32 bytes "
        "depending on AES - 128/192/256 bit modes used");

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(key, exp_key.get(), this->actual_key_len, this->expanded_key_len);

    /* Data structure to store range of input data buffer being processed
    by a thread at any given instance. */
    struct ip_op_SegmentInfo {
        size_t start__;
        size_t end__;
    };

    /* Data structure handling threading, holds mutex & queue of input data segments. */
    struct ip_Data_SegmentQueue {
        std::mutex                      ipD_Mutex__;
        size_t                          total_DataSegments__;
        std::vector<ip_op_SegmentInfo>  segment_Queue__;

        ip_Data_SegmentQueue(size_t input_Sz) {
            for(size_t i = 0; i < input_Sz; i = i + AES_DATA_SIZE_PER_SEGMENT) {

                /* Slice the input buffer into segments. */
                segment_Queue__.emplace_back(ip_op_SegmentInfo{i, \
                std::min(i + AES_DATA_SIZE_PER_SEGMENT, input_Sz)});
            }
            total_DataSegments__ = segment_Queue__.size();
        }

        /* Feeds each data segment to input function without data races, until
        segment queue is empty. */
        bool pop_Segment(std::function<void(const ip_op_SegmentInfo &)> __Func__) {
            
            std::unique_lock<std::mutex> pop_LOCK(ipD_Mutex__);
            if(segment_Queue__.empty())
                return false;
            ip_op_SegmentInfo cur_segment = segment_Queue__.back();
            segment_Queue__.pop_back();
            pop_LOCK.unlock();
        
            /* Process the data segment. */
            __Func__(cur_segment);
            return true;
        }
    };

    ip_Data_SegmentQueue encrypt_DataSegmentQueue(ip_size);

    /* Encryption thread function. */
    auto thread_MAIN_ENC = [&] {
        auto primary_Worker = [&] (const ip_op_SegmentInfo &this_Segment) {
            /* Loop through the input plain text array, 
            processing 16 bytes of data every iteration */
            for(size_t ip_iter = (this_Segment.start__ / this->block_size); \
            (ip_iter) < (this_Segment.end__ / this->block_size); ++ip_iter) {
                this->__perform_encryption__(input, exp_key, output, (ip_iter * this->block_size));
            }    
        };

        while(encrypt_DataSegmentQueue.pop_Segment(primary_Worker)) {
            /* Do processing */
        }
    }; 
    
    /* Decryption thread function. */
    auto thread_MAIN_DEC = [&] {
        auto primary_Worker = [&] (const ip_op_SegmentInfo &this_Segment) {
            /* Loop through the input plain text array, 
            processing 16 bytes of data every iteration */
            for(size_t ip_iter = (this_Segment.start__ / this->block_size); \
            (ip_iter) < (this_Segment.end__ / this->block_size); ++ip_iter) {
                this->__perform_decryption__(input, exp_key, output, (ip_iter * this->block_size));
            }    
        };

        while(encrypt_DataSegmentQueue.pop_Segment(primary_Worker)) {
            /* Do processing */
        }
    }; 

    std::vector<std::thread> enc_THREADS;
    enc_THREADS.reserve(std::thread::hardware_concurrency());
    for(auto i = 0u; i < std::thread::hardware_concurrency(); ++i) {
        if(action == aes_Action::_ENCRYPT_0__)
            enc_THREADS.emplace_back(thread_MAIN_ENC);
        else if(action == aes_Action::_DECRYPT_1__)
            enc_THREADS.emplace_back(thread_MAIN_DEC);
    }

    for(auto &t : enc_THREADS)
        t.join();

    return 0;

}

/**
  * @brief  Function to encrypt given file
  *         using AES ECB.
  * 
  * @param  [in]  f_Name            Input file name.
  * @param  [in]  op_file_name      Output file name.
  * @param  [in]  key               AES Key for encryption.
  * @param  [in]  key_size          Key array size.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::__process_File__ENC(
    const std::string      &f_Name, 
    const std::string      &op_file_name, 
    const uint8_t           key[], 
    const size_t            key_size 
    ) const {

    
    std::ifstream ip_file_stream(f_Name, std::ios::binary);
    if(!ip_file_stream.is_open())
        throw std::invalid_argument("__process_File__() - Error opening input file");

    const size_t file_Size = __get_File_Size_Fstream(ip_file_stream);
    std::unique_ptr<uint8_t []> padded_Key(new uint8_t[this->actual_key_len]);
    memcpy(padded_Key.get(), key, std::min(key_size, this->actual_key_len));

    if(key_size < this->actual_key_len) {
        /* Padd with zero's if key size is less than expected. */
        memset(padded_Key.get() + key_size, 0, this->actual_key_len - key_size);
    }
    
    std::unique_ptr<uint8_t []> ip_file_Buff;
    std::unique_ptr<uint8_t []> op_file_Buff;
    
    size_t ip_Total_PaddedBufferSize = file_Size;

    /* Calculate the number of bytes needed to be added to make the file size
    a multiple of 16 bytes, ie (AES_WORD_SIZE * AES_WORD_SIZE). */
    size_t pad_Diff = file_Size % (AES_WORD_SIZE * AES_WORD_SIZE);
    pad_Diff = pad_Diff ? ((AES_WORD_SIZE * AES_WORD_SIZE) - pad_Diff) : 0;

    /* Final buffer size including padding and metadata. */
    ip_Total_PaddedBufferSize += AES_META_DATA_SIZE + pad_Diff;

    auto t1 = std::chrono::high_resolution_clock::now();
    ip_file_Buff = std::make_unique<uint8_t []>(ip_Total_PaddedBufferSize);
    ip_file_stream.read(reinterpret_cast<char *>(ip_file_Buff.get()), file_Size);
    op_file_Buff = std::make_unique<uint8_t []>(ip_Total_PaddedBufferSize);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();
    std::cout<<"\nFile Read & Allocation: "<<duration<<"\n";
    
    /* Set the area reserved for padding and metadata as 0. */
    memset(ip_file_Buff.get() + file_Size, 0, ip_Total_PaddedBufferSize - file_Size);

    /* 
    
    Metadata Layout:
    ----------------

    -------------------------------------------------
    | 0| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15|
    -------------------------------------------------

    [0]     -> Padding size, reasonable values ranging from [0, 15]. (1 byte)
    [1:7]   -> Reserved.
    [8:12]  -> Checksum. (4 bytes)
    [13:15] -> Reserved.

    */
    
    /* Add metadata, padding size. */
    ip_file_Buff[file_Size + pad_Diff + AES_META_DATA_PADD_SIZE_OFFSET] = static_cast<uint8_t>(pad_Diff);

    t1 = std::chrono::high_resolution_clock::now();
    uint32_t check_sum = __aes_calculate_Checksum(ip_file_Buff.get(), ip_Total_PaddedBufferSize - AES_META_DATA_SIZE);
    duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();
    std::cout<<"\nChecksum calc.: "<<duration<<"\n";
    
    memcpy(ip_file_Buff.get() + ip_Total_PaddedBufferSize - AES_META_DATA_CHECK_SUM_OFFSET, \
    &check_sum, sizeof(uint32_t));

    t1 = std::chrono::high_resolution_clock::now();
    this->__ECB_threaded__(ip_file_Buff.get(), padded_Key.get(), \
    op_file_Buff.get(), ip_Total_PaddedBufferSize, this->actual_key_len, aes_Action::_ENCRYPT_0__);
    duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();
    std::cout<<"\nAlgo. threaded: "<<duration<<"\n";

    size_t op_File_FinalBufferSize = ip_Total_PaddedBufferSize;
    
    t1 = std::chrono::high_resolution_clock::now();
    std::ofstream op_file_strm(op_file_name.c_str(), std::ios::binary);
    if(!op_file_strm.is_open())
        throw std::invalid_argument("Encrypt - Error opening output file");
    op_file_strm.write(reinterpret_cast<char *>(op_file_Buff.get()), op_File_FinalBufferSize);
    duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();
    std::cout<<"\nFile write: "<<duration<<"\n";

    return 0;

}

/**
  * @brief  Function to decrypt given file
  *         using AES ECB.
  * 
  * @param  [in]  f_Name            Input file name.
  * @param  [in]  op_file_name      Output file name.
  * @param  [in]  key               AES Key for decryption.
  * @param  [in]  key_size          Key array size.
  *         
  * @retval Status:
  *             - 0         Success.
  */
int symmetric_ciphers::AES::__process_File__DEC(
    const std::string      &f_Name, 
    const std::string      &op_file_name, 
    const uint8_t           key[], 
    const size_t            key_size 
    ) const {

    std::ifstream ip_file_stream(f_Name, std::ios::binary);
    if (!ip_file_stream.is_open())
        throw std::invalid_argument("__process_File__() - Error opening input file");

    const size_t file_Size = __get_File_Size_Fstream(ip_file_stream);

    std::unique_ptr<uint8_t []> padded_Key(new uint8_t[this->actual_key_len]);
    memcpy(padded_Key.get(), key, std::min(key_size, this->actual_key_len));

    if(key_size < this->actual_key_len) {
        /* Padd with zero's if key size is less than expected. */
        memset(padded_Key.get() + key_size, 0, this->actual_key_len - key_size);
    }
    
    std::unique_ptr<uint8_t []> ip_file_Buff;
    std::unique_ptr<uint8_t []> op_file_Buff;
    
    size_t ip_Total_PaddedBufferSize = file_Size;

    /* If decrypt, read entire .dec file. */
    ip_file_Buff = std::make_unique<uint8_t []>(file_Size);
    ip_file_stream.read(reinterpret_cast<char *>(ip_file_Buff.get()), file_Size);
    op_file_Buff = std::make_unique<uint8_t []>(file_Size);


    this->__ECB_threaded__(ip_file_Buff.get(), padded_Key.get(), \
    op_file_Buff.get(), ip_Total_PaddedBufferSize, this->actual_key_len, aes_Action::_DECRYPT_1__);

    size_t op_File_FinalBufferSize = 0;
    /* If decryption remove metadata and padding. */
    op_File_FinalBufferSize = file_Size - \
    AES_META_DATA_SIZE - op_file_Buff[file_Size - AES_META_DATA_SIZE + AES_META_DATA_PADD_SIZE_OFFSET];
    uint32_t cur_check_sum = __aes_calculate_Checksum(op_file_Buff.get(), file_Size - AES_META_DATA_SIZE);
    uint32_t actual_check_sum = 0;
    memcpy(&actual_check_sum, op_file_Buff.get() + file_Size - AES_META_DATA_SIZE + AES_META_DATA_CHECK_SUM_OFFSET, \
    sizeof(uint32_t));

    if(actual_check_sum != cur_check_sum)
        throw std::invalid_argument("Decrypt - Incorrect key/invalid format");

    std::ofstream op_file_strm(op_file_name.c_str(), std::ios::binary);
    if (!op_file_strm.is_open())
        throw std::invalid_argument("Decrypt - Error opening output file");
    op_file_strm.write(reinterpret_cast<char*>(op_file_Buff.get()), op_File_FinalBufferSize);

    return 0;

}

int symmetric_ciphers::AES::rewrite_file_threads(
    const std::string&      f_name,
    const uint8_t           key[],
    const size_t            key_size,
    const aes_Action        action
    ) const {

    if (key_size != this->actual_key_len)
        throw std::invalid_argument("encrpyt_block_ecb() - key size should be 16/24/32 bytes "
            "depending on AES - 128/192/256 bit modes used");

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(key, exp_key.get(), this->actual_key_len, this->expanded_key_len);

    std::ifstream ip_file_stream(f_name, std::ios::binary);
    if (!ip_file_stream.is_open())
        throw std::invalid_argument("Error opening input file");

    const size_t ip_file_Size = __get_File_Size_Fstream(ip_file_stream);
    bool last_chunk = false;
    uint32_t file_checksum = 0;

    std::vector<std::unique_ptr<file_io_chunk_map_t>> ip_file_DS;
    file_io_process_DataQueue read_write_DS(f_name + std::string("_copy"));

    auto writer_thread_process = [&] {
        while (read_write_DS.pop_and_process_data()) {
            /* Do processing. */
        }
    };

    auto encrypt_process = [&] {
        
        auto encrypt_chunk_data = [&](const std::unique_ptr<file_io_chunk_map_t> &cur_chunk) {
            
            file_checksum += __aes_calculate_Checksum(cur_chunk.get()->chunk_data, cur_chunk.get()->chunk_size);

            if (cur_chunk.get()->last_chunk) {
                /*Add padding and checksum. & increase chunk_size respectively. */
            }

            std::unique_ptr<file_io_chunk_map_t> ciphr_elem = std::make_unique<file_io_chunk_map_t>();
            for (size_t ip_iter = 0; ip_iter < cur_chunk.get()->chunk_size; ip_iter += this->block_size) {
                this->__perform_encryption__(cur_chunk.get()->chunk_data, exp_key, ciphr_elem.get()->chunk_data, ip_iter);
            }
            ciphr_elem.get()->chunk_id = cur_chunk.get()->chunk_id;
            ciphr_elem.get()->chunk_size = cur_chunk.get()->chunk_size;
            ciphr_elem.get()->file_indx = cur_chunk.get()->file_indx;
            ciphr_elem.get()->last_chunk = cur_chunk.get()->last_chunk;

            std::unique_lock<std::mutex> fio_LOCK_ciphr(read_write_DS.fiop_Mutex);
            read_write_DS.fiop_DataQueue.emplace_back(std::move(ciphr_elem));
            fio_LOCK_ciphr.unlock();

        };

    };

    std::vector<std::thread> lfi_Threads;
    lfi_Threads.reserve(1);
    lfi_Threads.emplace_back(writer_thread_process);

    size_t remaining_data_to_read = ip_file_Size, chunk_cntr = 0;
    while (remaining_data_to_read != 0) {

        std::unique_ptr<file_io_chunk_map_t> temp_elem = std::make_unique<file_io_chunk_map_t>();
        size_t cur_read_size = FILE_IO_CHUNK_SIZE_BYTES;
        if (remaining_data_to_read < FILE_IO_CHUNK_SIZE_BYTES) {
            cur_read_size = remaining_data_to_read;
            last_chunk = true;
        }

        ip_file_stream.read(reinterpret_cast<char*>(temp_elem.get()->chunk_data), cur_read_size);
        temp_elem.get()->chunk_size = cur_read_size;
        temp_elem.get()->file_indx = chunk_cntr * FILE_IO_CHUNK_SIZE_BYTES;
        chunk_cntr++;
        temp_elem.get()->chunk_id = chunk_cntr;
        temp_elem.get()->last_chunk = last_chunk;
        remaining_data_to_read -= cur_read_size;

        std::unique_lock<std::mutex> fio_LOCK(read_write_DS.fiop_Mutex);
        read_write_DS.fiip_DataQueue.emplace_back(std::move(temp_elem));
        fio_LOCK.unlock();

        std::cout << "Read: " << chunk_cntr << " Chunk, size: " << cur_read_size << "\n";

    }

    for (auto& t : lfi_Threads) {
        t.join();
    }

    return 0;

}


namespace {

    size_t __aes_expand_key(
        const uint8_t           key[], 
        uint8_t                 expand_key[], 
        const size_t            actual_key_len,
        const size_t            expand_key_len
    ) {
        /* Clear the expanded key output array & copy initial key */
        memset(expand_key, 0, expand_key_len);
        memcpy(expand_key, key, actual_key_len);

        /* Increment an offset to the current filled 
           position in the expanded key output array */
        size_t cur_exp_key_offset = 0;
        cur_exp_key_offset += actual_key_len;

        for(uint8_t round_key_index = 1; \
        cur_exp_key_offset < expand_key_len; ++round_key_index) {

            /* Process the last 4 bytes */
            uint8_t     temp_key_buff_1[AES_WORD_SIZE];
            memcpy(temp_key_buff_1, \
            (expand_key + (cur_exp_key_offset - AES_WORD_SIZE)), AES_WORD_SIZE);
            
            uint8_t     temp_key_buff_2[AES_WORD_SIZE];
            __aes_key_scheduler(round_key_index, temp_key_buff_1, temp_key_buff_2);

            /* XOR the pre - processed last 4 bytes with corresponding word from 
               previous round */
            memcpy(temp_key_buff_1, \
            (expand_key + (cur_exp_key_offset - actual_key_len)), AES_WORD_SIZE);
            
            __aes_xor_word(temp_key_buff_1, temp_key_buff_2);
            memcpy((expand_key + cur_exp_key_offset), temp_key_buff_1, AES_WORD_SIZE);
            cur_exp_key_offset += AES_WORD_SIZE;

            /* Compute key for remaining words in the block */
            __aes_compute_remaining_words(3, expand_key, cur_exp_key_offset, \
            expand_key_len, actual_key_len);
            
            if(actual_key_len == 32) {
                /* Do special key schedule if i >= N & (i % n) == 4 */
                __aes_key_scheduler_4th_word(expand_key, cur_exp_key_offset, \
                expand_key_len, actual_key_len);
                
                __aes_compute_remaining_words(3, expand_key, cur_exp_key_offset, \
                expand_key_len, actual_key_len);

            } else if(actual_key_len == 24) 
                __aes_compute_remaining_words(2, expand_key, cur_exp_key_offset, \
                expand_key_len, actual_key_len);
        }
        /* Return expanded key length */
        return expand_key_len;
    }

    int __aes_key_scheduler(
        int                                     round,
        const uint8_t    in[AES_WORD_SIZE],
        uint8_t    out[AES_WORD_SIZE]
    ) {

        /* Rotate word */
        for(int i = 0; i < (AES_WORD_SIZE - 1); ++i) 
            out[i] = in[i + 1];
        out[3] = in[0];

        /* Substitute word */
        for(int i = 0; i < AES_WORD_SIZE; ++i) 
            out[i] = AES_S_BOX[ out[i] ];

        /* XOR Round Constant to least significant byte */
        if(round < static_cast<int>(sizeof(AES_RCON)))
            out[0] ^= AES_RCON[round];
        else
            throw std::out_of_range("AES_RCON index out of range"); 

        return 0;

    }

    inline void __aes_xor_word(
        uint8_t             target[AES_WORD_SIZE],
        const uint8_t       operand[AES_WORD_SIZE]
    ) {

        for(int i = 0; i < AES_WORD_SIZE; ++i) 
            target[i] ^= operand[i];

    }

    inline void __aes_transposition(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
        const uint8_t       ip[],
        const size_t           offset
    ) {
        /* Transposition bytes to matrix form - column major */
        for(size_t i = 0; i < AES_WORD_SIZE; ++i)
            for(size_t j = 0; j < AES_WORD_SIZE; ++j)
                cur_state[i][j] = ip[ offset + (j * 4) + i ];

    }

    inline void __aes_rev_transposition(
        const uint8_t       cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
        uint8_t             op[],
        const size_t        offset
    ) {
        /* Transposition bytes from matrix (column major) back to output array */
        for(size_t i = 0; i < AES_WORD_SIZE; ++i)
            for(size_t j = 0; j < AES_WORD_SIZE; ++j)
                op[ offset + (j * 4) + i ] = cur_state[i][j];

    }

    void __aes_compute_remaining_words(
        int                 words_required,
        uint8_t             exp_key[],
        size_t             &exp_offset,
        const size_t        exp_key_len,
        const size_t        act_key_len  
    ) {
        uint8_t     temp_key_buff_1[AES_WORD_SIZE];
        uint8_t     temp_key_buff_2[AES_WORD_SIZE];

        for(int i = 0; (i < words_required) && (exp_offset < exp_key_len); ++i) {
            
            memcpy(temp_key_buff_1, \
            (exp_key + (exp_offset - AES_WORD_SIZE)), AES_WORD_SIZE);
            
            memcpy(temp_key_buff_2, \
            (exp_key + (exp_offset - act_key_len)), AES_WORD_SIZE);        
            
            __aes_xor_word(temp_key_buff_1, temp_key_buff_2);
            
            memcpy((exp_key + exp_offset), temp_key_buff_1, AES_WORD_SIZE);
            exp_offset += AES_WORD_SIZE;
        }
    }

    void __aes_key_scheduler_4th_word(
        uint8_t             exp_key[],
        size_t             &exp_offset,
        const size_t        exp_key_len,
        const size_t        act_key_len  
    ) {

        uint8_t     temp_key_buff_1[AES_WORD_SIZE];
        uint8_t     temp_key_buff_2[AES_WORD_SIZE];

        if(exp_offset < exp_key_len) {

            memcpy(temp_key_buff_1, \
            (exp_key + (exp_offset - AES_WORD_SIZE)), AES_WORD_SIZE);

            for(int i = 0; i < AES_WORD_SIZE; ++i)
                temp_key_buff_1[i] = AES_S_BOX[ temp_key_buff_1[i] ];

            memcpy(temp_key_buff_2, \
            (exp_key + (exp_offset - act_key_len)), AES_WORD_SIZE);        
            
            __aes_xor_word(temp_key_buff_1, temp_key_buff_2);
            
            memcpy((exp_key + exp_offset), temp_key_buff_1, AES_WORD_SIZE);
            exp_offset += AES_WORD_SIZE;
        }

    }

    void __aes_get_round_key_block(
        size_t              round_count,
        size_t              block_size,
        const uint8_t       exp_key[],
        size_t              exp_key_len,
        uint8_t             op_key[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for(size_t i = 0; i < AES_WORD_SIZE; ++i)
            for(size_t j = 0; \
            (j < AES_WORD_SIZE) && \
            ((round_count * block_size + ((j * 4) + i)) < exp_key_len); ++j)
                op_key[i][j] = exp_key[((round_count * block_size) + ((j * 4) + i))];
    }

    void __aes_add_round_key(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
        uint8_t             round_key[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for(int i = 0; i < AES_WORD_SIZE; ++i)
            for(int j = 0; j < AES_WORD_SIZE; ++j) 
                cur_state[i][j] ^= round_key[i][j];
    }

    void __aes_substitue_bytes(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for(int i = 0; i < AES_WORD_SIZE; ++i)
            for(int j = 0; j < AES_WORD_SIZE; ++j) 
                cur_state[i][j] = AES_S_BOX[ cur_state[i][j] ];
    }

    void __aes_shift_rows(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {

        for(int i = 0; i < AES_WORD_SIZE; ++i) {

            if(i > 0) {   

                uint8_t cur_row[AES_WORD_SIZE]; 
                for(int j = 0; j < AES_WORD_SIZE; ++j) 
                    cur_row[j] = cur_state[i][j];
                
                for(int j = 0; j < AES_WORD_SIZE; ++j)
                    cur_state[i][j] = cur_row[ ((i + j) % AES_WORD_SIZE) ];
            }
        }
    }

    void __aes_mix_columns(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for(int i = 0; i < AES_WORD_SIZE; ++i) {
            
            uint8_t column[4] = { cur_state[0][i],
                                                      cur_state[1][i],
                                                      cur_state[2][i],
                                                      cur_state[3][i]
            };

            cur_state[0][i] = MUL_2[ column[0] ] ^ MUL_3[ column[1] ] ^ column[2] ^ column[3];
            cur_state[1][i] = column[0] ^ MUL_2[ column[1] ] ^ MUL_3[ column[2] ] ^ column[3];
            cur_state[2][i] = column[0] ^ column[1] ^ MUL_2[ column[2] ] ^ MUL_3[ column[3] ];
            cur_state[3][i] = MUL_3[ column[0] ] ^ column[1] ^ column[2] ^ MUL_2[ column[3] ];

        }
    }

    void __aes_inv_substitue_bytes(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for(int i = 0; i < AES_WORD_SIZE; ++i)
            for(int j = 0; j < AES_WORD_SIZE;++j)
                cur_state[i][j] = AES_INV_S_BOX[ cur_state[i][j] ];
    }

    /** 
     *      Reverse shift row
     *      -----------------
     * 
     *  [0, 1, 2, 3]            [0, 1, 2, 3]
     *  [0, 1, 2, 3]    ==>>    [3, 0, 1, 2]    
     *  [0, 1, 2, 3]            [2, 3, 0, 1]
     *  [0, 1, 2, 3]            [3, 2, 1, 0]
     *  
     */

    void __aes_inv_shift_rows(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for(int i = 0; i < AES_WORD_SIZE; ++i) {

            if(i > 0) {
                uint8_t t_row[AES_WORD_SIZE];

                for(int j = 0; j < AES_WORD_SIZE; ++j)
                    t_row[j] = cur_state[i][j];

                for(int j = (AES_WORD_SIZE - 1); j >= 0; --j)
                    cur_state[i][j] = t_row[ ((j + (AES_WORD_SIZE - i)) % AES_WORD_SIZE) ];
            }
        }
    }

    void __aes_inv_mix_columns(
        uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE]
    ) {
        for (int i = 0; i < AES_WORD_SIZE; ++i) {

            uint8_t t_col[AES_WORD_SIZE];
            for(int j = 0; j < AES_WORD_SIZE; ++j)
                t_col[j] = cur_state[j][i];

            cur_state[0][i] = MUL_14[t_col[0]] ^ MUL_11[t_col[1]] ^ MUL_13[t_col[2]] ^ MUL_9[t_col[3]];
            cur_state[1][i] = MUL_9[t_col[0]]  ^ MUL_14[t_col[1]] ^ MUL_11[t_col[2]] ^ MUL_13[t_col[3]];
            cur_state[2][i] = MUL_13[t_col[0]] ^ MUL_9[t_col[1]]  ^ MUL_14[t_col[2]] ^ MUL_11[t_col[3]];
            cur_state[3][i] = MUL_11[t_col[0]] ^ MUL_13[t_col[1]] ^ MUL_9[t_col[2]]  ^ MUL_14[t_col[3]];
        }
    }

    size_t __get_File_Size(std::unique_ptr<FILE, decltype(&fclose)> &file_Ptr) {
        size_t file_Size = 0;
        fseek(file_Ptr.get(), 0, SEEK_END);             
        file_Size = static_cast<size_t>(ftell(file_Ptr.get()));              
        rewind(file_Ptr.get());     
        return file_Size;
    }

    std::streampos __get_File_Size_Fstream(
        std::ifstream& ip_file_strm
    ) {

        std::streampos f_size = 0;
        if (ip_file_strm.is_open()) {
            ip_file_strm.seekg(0, ip_file_strm.end);
            f_size = ip_file_strm.tellg();
            ip_file_strm.seekg(0, ip_file_strm.beg);
        }

        return f_size;
    
    }

    uint32_t __aes_calculate_Checksum(
        uint8_t                     buffer[],
        size_t                      siz_
    ) {
        uint32_t c = 0;
        size_t i = 0;
        for(; i < siz_; ++i) {
            c += buffer[i];
            c = c << 3 | c >> (32 - 3); 
            c ^= 0xFFFFFFFF; 
        }
        return c;
    }

    uint8_t AES_S_BOX[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    uint8_t AES_INV_S_BOX[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    uint8_t MUL_2[256] = {
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
        0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
        0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
        0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
        0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
        0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
        0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
        0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
        0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
        0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
        0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
        0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5
    };

    uint8_t MUL_3[256] = {
        0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11,
        0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21,
        0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71,
        0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41,
        0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1,
        0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1,
        0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1,
        0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81,
        0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A,
        0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA,
        0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA,
        0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA,
        0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A,
        0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A,
        0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A,
        0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A
    }; 

    uint8_t MUL_9[256] = {
        0x00, 0x09, 0x12, 0x1B, 0x24, 0x2D, 0x36, 0x3F, 0x48, 0x41, 0x5A, 0x53, 0x6C, 0x65, 0x7E, 0x77,
        0x90, 0x99, 0x82, 0x8B, 0xB4, 0xBD, 0xA6, 0xAF, 0xD8, 0xD1, 0xCA, 0xC3, 0xFC, 0xF5, 0xEE, 0xE7,
        0x3B, 0x32, 0x29, 0x20, 0x1F, 0x16, 0x0D, 0x04, 0x73, 0x7A, 0x61, 0x68, 0x57, 0x5E, 0x45, 0x4C,
        0xAB, 0xA2, 0xB9, 0xB0, 0x8F, 0x86, 0x9D, 0x94, 0xE3, 0xEA, 0xF1, 0xF8, 0xC7, 0xCE, 0xD5, 0xDC,
        0x76, 0x7F, 0x64, 0x6D, 0x52, 0x5B, 0x40, 0x49, 0x3E, 0x37, 0x2C, 0x25, 0x1A, 0x13, 0x08, 0x01,
        0xE6, 0xEF, 0xF4, 0xFD, 0xC2, 0xCB, 0xD0, 0xD9, 0xAE, 0xA7, 0xBC, 0xB5, 0x8A, 0x83, 0x98, 0x91,
        0x4D, 0x44, 0x5F, 0x56, 0x69, 0x60, 0x7B, 0x72, 0x05, 0x0C, 0x17, 0x1E, 0x21, 0x28, 0x33, 0x3A,
        0xDD, 0xD4, 0xCF, 0xC6, 0xF9, 0xF0, 0xEB, 0xE2, 0x95, 0x9C, 0x87, 0x8E, 0xB1, 0xB8, 0xA3, 0xAA,
        0xEC, 0xE5, 0xFE, 0xF7, 0xC8, 0xC1, 0xDA, 0xD3, 0xA4, 0xAD, 0xB6, 0xBF, 0x80, 0x89, 0x92, 0x9B,
        0x7C, 0x75, 0x6E, 0x67, 0x58, 0x51, 0x4A, 0x43, 0x34, 0x3D, 0x26, 0x2F, 0x10, 0x19, 0x02, 0x0B,
        0xD7, 0xDE, 0xC5, 0xCC, 0xF3, 0xFA, 0xE1, 0xE8, 0x9F, 0x96, 0x8D, 0x84, 0xBB, 0xB2, 0xA9, 0xA0,
        0x47, 0x4E, 0x55, 0x5C, 0x63, 0x6A, 0x71, 0x78, 0x0F, 0x06, 0x1D, 0x14, 0x2B, 0x22, 0x39, 0x30,
        0x9A, 0x93, 0x88, 0x81, 0xBE, 0xB7, 0xAC, 0xA5, 0xD2, 0xDB, 0xC0, 0xC9, 0xF6, 0xFF, 0xE4, 0xED,
        0x0A, 0x03, 0x18, 0x11, 0x2E, 0x27, 0x3C, 0x35, 0x42, 0x4B, 0x50, 0x59, 0x66, 0x6F, 0x74, 0x7D,
        0xA1, 0xA8, 0xB3, 0xBA, 0x85, 0x8C, 0x97, 0x9E, 0xE9, 0xE0, 0xFB, 0xF2, 0xCD, 0xC4, 0xDF, 0xD6,
        0x31, 0x38, 0x23, 0x2A, 0x15, 0x1C, 0x07, 0x0E, 0x79, 0x70, 0x6B, 0x62, 0x5D, 0x54, 0x4F, 0x46
    };

    uint8_t MUL_11[256] = {
        0x00, 0x0B, 0x16, 0x1D, 0x2C, 0x27, 0x3A, 0x31, 0x58, 0x53, 0x4E, 0x45, 0x74, 0x7F, 0x62, 0x69,
        0xB0, 0xBB, 0xA6, 0xAD, 0x9C, 0x97, 0x8A, 0x81, 0xE8, 0xE3, 0xFE, 0xF5, 0xC4, 0xCF, 0xD2, 0xD9,
        0x7B, 0x70, 0x6D, 0x66, 0x57, 0x5C, 0x41, 0x4A, 0x23, 0x28, 0x35, 0x3E, 0x0F, 0x04, 0x19, 0x12,
        0xCB, 0xC0, 0xDD, 0xD6, 0xE7, 0xEC, 0xF1, 0xFA, 0x93, 0x98, 0x85, 0x8E, 0xBF, 0xB4, 0xA9, 0xA2,
        0xF6, 0xFD, 0xE0, 0xEB, 0xDA, 0xD1, 0xCC, 0xC7, 0xAE, 0xA5, 0xB8, 0xB3, 0x82, 0x89, 0x94, 0x9F,
        0x46, 0x4D, 0x50, 0x5B, 0x6A, 0x61, 0x7C, 0x77, 0x1E, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2F,
        0x8D, 0x86, 0x9B, 0x90, 0xA1, 0xAA, 0xB7, 0xBC, 0xD5, 0xDE, 0xC3, 0xC8, 0xF9, 0xF2, 0xEF, 0xE4,
        0x3D, 0x36, 0x2B, 0x20, 0x11, 0x1A, 0x07, 0x0C, 0x65, 0x6E, 0x73, 0x78, 0x49, 0x42, 0x5F, 0x54,
        0xF7, 0xFC, 0xE1, 0xEA, 0xDB, 0xD0, 0xCD, 0xC6, 0xAF, 0xA4, 0xB9, 0xB2, 0x83, 0x88, 0x95, 0x9E,
        0x47, 0x4C, 0x51, 0x5A, 0x6B, 0x60, 0x7D, 0x76, 0x1F, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2E,
        0x8C, 0x87, 0x9A, 0x91, 0xA0, 0xAB, 0xB6, 0xBD, 0xD4, 0xDF, 0xC2, 0xC9, 0xF8, 0xF3, 0xEE, 0xE5,
        0x3C, 0x37, 0x2A, 0x21, 0x10, 0x1B, 0x06, 0x0D, 0x64, 0x6F, 0x72, 0x79, 0x48, 0x43, 0x5E, 0x55,
        0x01, 0x0A, 0x17, 0x1C, 0x2D, 0x26, 0x3B, 0x30, 0x59, 0x52, 0x4F, 0x44, 0x75, 0x7E, 0x63, 0x68,
        0xB1, 0xBA, 0xA7, 0xAC, 0x9D, 0x96, 0x8B, 0x80, 0xE9, 0xE2, 0xFF, 0xF4, 0xC5, 0xCE, 0xD3, 0xD8,
        0x7A, 0x71, 0x6C, 0x67, 0x56, 0x5D, 0x40, 0x4B, 0x22, 0x29, 0x34, 0x3F, 0x0E, 0x05, 0x18, 0x13,
        0xCA, 0xC1, 0xDC, 0xD7, 0xE6, 0xED, 0xF0, 0xFB, 0x92, 0x99, 0x84, 0x8F, 0xBE, 0xB5, 0xA8, 0xA3
    };

    uint8_t MUL_13[256] = {
        0x00, 0x0D, 0x1A, 0x17, 0x34, 0x39, 0x2E, 0x23, 0x68, 0x65, 0x72, 0x7F, 0x5C, 0x51, 0x46, 0x4B,
        0xD0, 0xDD, 0xCA, 0xC7, 0xE4, 0xE9, 0xFE, 0xF3, 0xB8, 0xB5, 0xA2, 0xAF, 0x8C, 0x81, 0x96, 0x9B,
        0xBB, 0xB6, 0xA1, 0xAC, 0x8F, 0x82, 0x95, 0x98, 0xD3, 0xDE, 0xC9, 0xC4, 0xE7, 0xEA, 0xFD, 0xF0,
        0x6B, 0x66, 0x71, 0x7C, 0x5F, 0x52, 0x45, 0x48, 0x03, 0x0E, 0x19, 0x14, 0x37, 0x3A, 0x2D, 0x20,
        0x6D, 0x60, 0x77, 0x7A, 0x59, 0x54, 0x43, 0x4E, 0x05, 0x08, 0x1F, 0x12, 0x31, 0x3C, 0x2B, 0x26,
        0xBD, 0xB0, 0xA7, 0xAA, 0x89, 0x84, 0x93, 0x9E, 0xD5, 0xD8, 0xCF, 0xC2, 0xE1, 0xEC, 0xFB, 0xF6,
        0xD6, 0xDB, 0xCC, 0xC1, 0xE2, 0xEF, 0xF8, 0xF5, 0xBE, 0xB3, 0xA4, 0xA9, 0x8A, 0x87, 0x90, 0x9D,
        0x06, 0x0B, 0x1C, 0x11, 0x32, 0x3F, 0x28, 0x25, 0x6E, 0x63, 0x74, 0x79, 0x5A, 0x57, 0x40, 0x4D,
        0xDA, 0xD7, 0xC0, 0xCD, 0xEE, 0xE3, 0xF4, 0xF9, 0xB2, 0xBF, 0xA8, 0xA5, 0x86, 0x8B, 0x9C, 0x91,
        0x0A, 0x07, 0x10, 0x1D, 0x3E, 0x33, 0x24, 0x29, 0x62, 0x6F, 0x78, 0x75, 0x56, 0x5B, 0x4C, 0x41,
        0x61, 0x6C, 0x7B, 0x76, 0x55, 0x58, 0x4F, 0x42, 0x09, 0x04, 0x13, 0x1E, 0x3D, 0x30, 0x27, 0x2A,
        0xB1, 0xBC, 0xAB, 0xA6, 0x85, 0x88, 0x9F, 0x92, 0xD9, 0xD4, 0xC3, 0xCE, 0xED, 0xE0, 0xF7, 0xFA,
        0xB7, 0xBA, 0xAD, 0xA0, 0x83, 0x8E, 0x99, 0x94, 0xDF, 0xD2, 0xC5, 0xC8, 0xEB, 0xE6, 0xF1, 0xFC,
        0x67, 0x6A, 0x7D, 0x70, 0x53, 0x5E, 0x49, 0x44, 0x0F, 0x02, 0x15, 0x18, 0x3B, 0x36, 0x21, 0x2C,
        0x0C, 0x01, 0x16, 0x1B, 0x38, 0x35, 0x22, 0x2F, 0x64, 0x69, 0x7E, 0x73, 0x50, 0x5D, 0x4A, 0x47,
        0xDC, 0xD1, 0xC6, 0xCB, 0xE8, 0xE5, 0xF2, 0xFF, 0xB4, 0xB9, 0xAE, 0xA3, 0x80, 0x8D, 0x9A, 0x97
    };

    uint8_t MUL_14[256] = {
        0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
        0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
        0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
        0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
        0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
        0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
        0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
        0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
        0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
        0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
        0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
        0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
        0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
        0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
        0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
        0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
    };

    uint8_t AES_RCON[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

} /* End of anonymous namespace */




/** 
 *  
 *  TODO: use pointer based XOR operation instead of loop - individual bytes & XOR
 *
 *  
 *
 *  
 *  
 *  
 */

