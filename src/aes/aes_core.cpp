/** 
 *  @file   aes_core.cpp
 *  @brief  AES Core API implementation file
 *
 *  This file contains the source code for the AES Implementation.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */



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

#include "aes.hpp"
#include "aes_core_cfg.hpp"
#include "aes_lookup_tables.hpp"
#include "aes_operations.hpp"
#include "aes_thread_utils.hpp"

// #define AES_DEBUG_FLAG


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
    size_t reqd_key_len;

    this->__convert_string_to_uint8_key(key, initzd_key, &reqd_key_len);

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
    size_t reqd_key_len;

    this->__convert_string_to_uint8_key(key, initzd_key, &reqd_key_len);

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
                std::min(i + static_cast<size_t>(AES_DATA_SIZE_PER_SEGMENT), input_Sz)});
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

    const size_t file_Size = static_cast<size_t>(__get_File_Size_Fstream(ip_file_stream));
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
    ip_file_stream.read(reinterpret_cast<char *>(ip_file_Buff.get()), static_cast<std::streamsize>(file_Size));
    op_file_Buff = std::make_unique<uint8_t []>(ip_Total_PaddedBufferSize);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();


#ifdef AES_DEBUG_FLAG
    std::cout<<"\nFile Read & Allocation: "<<duration<<"\n";
#endif /* AES_DEBUG_FLAG */
    
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

#ifdef AES_DEBUG_FLAG
    std::cout<<"\nChecksum calc.: "<<duration<<"\n";
#endif /* AES_DEBUG_FLAG */

    memcpy(ip_file_Buff.get() + ip_Total_PaddedBufferSize - AES_META_DATA_CHECK_SUM_OFFSET, \
    &check_sum, sizeof(uint32_t));

    t1 = std::chrono::high_resolution_clock::now();
    this->__ECB_threaded__(ip_file_Buff.get(), padded_Key.get(), \
    op_file_Buff.get(), ip_Total_PaddedBufferSize, this->actual_key_len, aes_Action::_ENCRYPT_0__);
    duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();

#ifdef AES_DEBUG_FLAG
    std::cout<<"\nAlgo. threaded: "<<duration<<"\n";
#endif /* AES_DEBUG_FLAG */

    size_t op_File_FinalBufferSize = ip_Total_PaddedBufferSize;
    
    t1 = std::chrono::high_resolution_clock::now();
    std::ofstream op_file_strm(op_file_name.c_str(), std::ios::binary);
    if(!op_file_strm.is_open())
        throw std::invalid_argument("Encrypt - Error opening output file");
    op_file_strm.write(reinterpret_cast<char *>(op_file_Buff.get()), static_cast<std::streamsize>(op_File_FinalBufferSize));
    duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();

#ifdef AES_DEBUG_FLAG
    std::cout<<"\nFile write: "<<duration<<"\n";
#endif /* AES_DEBUG_FLAG */

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

    const size_t file_Size = static_cast<size_t>(__get_File_Size_Fstream(ip_file_stream));

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
    ip_file_stream.read(reinterpret_cast<char *>(ip_file_Buff.get()), static_cast<std::streamsize>(file_Size));
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
    op_file_strm.write(reinterpret_cast<char*>(op_file_Buff.get()), static_cast<std::streamsize>(op_File_FinalBufferSize));

    return 0;

}

int symmetric_ciphers::AES::threaded_file_io_algo(
    const std::string&      f_name,
    const std::string&      op_file_name,
    const uint8_t           key[],
    const size_t            key_size,
    const aes_Action        action
    ) const {

    std::unique_ptr<uint8_t[]> padded_Key(new uint8_t[this->actual_key_len]);
    memcpy(padded_Key.get(), key, std::min(key_size, this->actual_key_len));

    if (key_size < this->actual_key_len) {
        /* Padd with zero's if key size is less than expected. */
        memset(padded_Key.get() + key_size, 0, this->actual_key_len - key_size);
    }

    /* Expand keys to exp_key[] */
    std::unique_ptr<uint8_t[]> exp_key(new uint8_t[this->expanded_key_len]);
    __aes_expand_key(padded_Key.get(), exp_key.get(), this->actual_key_len, this->expanded_key_len);

    std::ifstream ip_file_stream(f_name, std::ios::binary);
    if (!ip_file_stream.is_open())
        throw std::invalid_argument("Error opening input file");

    const size_t ip_file_Size = static_cast<size_t>(__get_File_Size_Fstream(ip_file_stream));
    bool last_chunk = false;

    std::vector<std::unique_ptr<file_io_chunk_map_t>> ip_file_DS;
    file_io_process_DataQueue read_write_DS(op_file_name);

    auto writer_thread_process = [&] {
        while (read_write_DS.pop_and_write_op_file_data()) {
            /* Do processing. */
        }
    };

    auto encrypt_process = [&] (size_t t_id) {
        
        auto encrypt_chunk_data = [&](const std::unique_ptr<file_io_chunk_map_t> &cur_chunk) {

            if (cur_chunk.get()->last_chunk) {
                /*Add padding and increase chunk_size respectively. */
                size_t pad_Diff = cur_chunk.get()->chunk_size % (AES_WORD_SIZE * AES_WORD_SIZE);
                pad_Diff = pad_Diff ? ((AES_WORD_SIZE * AES_WORD_SIZE) - pad_Diff) : 0;
                size_t new_chunk_sz = cur_chunk.get()->chunk_size + pad_Diff + AES_META_DATA_SIZE;
                uint8_t* data_buff = cur_chunk.get()->chunk_data;
                memset(data_buff + cur_chunk.get()->chunk_size, 0, new_chunk_sz - cur_chunk.get()->chunk_size);
                data_buff[cur_chunk.get()->chunk_size + pad_Diff + AES_META_DATA_PADD_SIZE_OFFSET] = static_cast<uint8_t>(pad_Diff);
                cur_chunk.get()->chunk_size = new_chunk_sz;
            }

            std::unique_ptr<file_io_chunk_map_t> ciphr_elem = std::make_unique<file_io_chunk_map_t>();
            for (size_t ip_iter = 0; ip_iter < cur_chunk.get()->chunk_size; ip_iter += this->block_size) {
                this->__perform_encryption__(cur_chunk.get()->chunk_data, exp_key, ciphr_elem.get()->chunk_data, ip_iter);
            }
            ciphr_elem.get()->copy_meta_data(cur_chunk.get());

            std::unique_lock<std::mutex> fio_LOCK_ciphr(read_write_DS.fiop_Mutex);
            read_write_DS.fiop_DataQueue.emplace_back(std::move(ciphr_elem));
            fio_LOCK_ciphr.unlock();

        };

        while (read_write_DS.pop_and_process_ip_data(encrypt_chunk_data, t_id)) {
            /*Do processing. */
        }

    };

    auto decrypt_process = [&](size_t t_id) {

        auto decrypt_chunk_data = [&](const std::unique_ptr<file_io_chunk_map_t>& cur_chunk) {
        
            std::unique_ptr<file_io_chunk_map_t> plain_elem = std::make_unique<file_io_chunk_map_t>();
            for (size_t ip_iter = 0; ip_iter < cur_chunk.get()->chunk_size; ip_iter += this->block_size) {
                this->__perform_decryption__(cur_chunk.get()->chunk_data, exp_key, plain_elem.get()->chunk_data, ip_iter);
            }
            
            plain_elem.get()->copy_meta_data(cur_chunk.get());
            if (cur_chunk.get()->last_chunk) {
                uint8_t* data_buff = plain_elem.get()->chunk_data;
                size_t unpadded_buffer_size = cur_chunk.get()->chunk_size - AES_META_DATA_SIZE - data_buff[cur_chunk.get()->chunk_size - AES_META_DATA_SIZE + AES_META_DATA_PADD_SIZE_OFFSET];
                plain_elem.get()->chunk_size = unpadded_buffer_size;
            }

            std::unique_lock<std::mutex> fio_LOCK_ciphr(read_write_DS.fiop_Mutex);
            read_write_DS.fiop_DataQueue.emplace_back(std::move(plain_elem));
            fio_LOCK_ciphr.unlock();

        };

        while (read_write_DS.pop_and_process_ip_data(decrypt_chunk_data, t_id)) {
            /*Do processing. */
        }

    };

    std::vector<std::thread> lfi_Threads;
    size_t max_threads = std::thread::hardware_concurrency();
    max_threads = max_threads > 2 ? max_threads : 3;
    max_threads -= 1;
    lfi_Threads.reserve(max_threads);
    lfi_Threads.emplace_back(writer_thread_process);
    for (size_t i = 0u; i < (max_threads - 1); ++i) {
        if (action == aes_Action::_ENCRYPT_0__) {
            lfi_Threads.emplace_back(encrypt_process, i);
        }
        else if (action == aes_Action::_DECRYPT_1__) {
            lfi_Threads.emplace_back(decrypt_process, i);
        }
    }


    size_t remaining_data_to_read = ip_file_Size, chunk_cntr = 0;
    while (remaining_data_to_read != 0) {

        std::unique_ptr<file_io_chunk_map_t> temp_elem = std::make_unique<file_io_chunk_map_t>();
        size_t cur_read_size = FILE_IO_CHUNK_SIZE_BYTES;
        if (remaining_data_to_read < FILE_IO_CHUNK_SIZE_BYTES) {
            cur_read_size = remaining_data_to_read;
            last_chunk = true;
        }

        ip_file_stream.read(reinterpret_cast<char*>(temp_elem.get()->chunk_data), static_cast<std::streamsize>(cur_read_size));
        temp_elem.get()->chunk_size = cur_read_size;
        temp_elem.get()->file_indx = chunk_cntr * FILE_IO_CHUNK_SIZE_BYTES;
        chunk_cntr++;
        temp_elem.get()->chunk_id = chunk_cntr;
        temp_elem.get()->last_chunk = last_chunk;
        remaining_data_to_read -= cur_read_size;

        std::unique_lock<std::mutex> fii_LOCK(read_write_DS.fiip_Mutex);
        read_write_DS.fiip_DataQueue.emplace_back(std::move(temp_elem));
        fii_LOCK.unlock();

        if (last_chunk) {
            std::unique_lock<std::mutex> fii_LOCK_Rd(read_write_DS.fiip_Mutex);
            read_write_DS.file_read_complete = true;
            fii_LOCK_Rd.unlock();
        }

#ifdef AES_DEBUG_FLAG
        std::cout << "Read: " << chunk_cntr << " Chunk, size: " << cur_read_size << "\n";
#endif /* AES_DEBUG_FLAG */

    }

    for (auto& t : lfi_Threads) {
        t.join();
    }

    return 0;

}

/**
* @brief  Internal Function to convert string key to
*         uint8_t buffer/array of required size.
*/
int symmetric_ciphers::AES::__convert_string_to_uint8_key(
    const std::string& key,
    uint8_t* const u8_key_buff,
    size_t* reqd_key_len
    ) const {

    size_t key_len = key.length();

    switch (this->actual_key_len) {
    case AES128_PLAIN_KEY_SIZE:
        *reqd_key_len = AES128_PLAIN_KEY_SIZE;
        std::memcpy(u8_key_buff, key.c_str(), key_len < AES128_PLAIN_KEY_SIZE ? key_len : AES128_PLAIN_KEY_SIZE);
        break;
    case AES192_PLAIN_KEY_SIZE:
        *reqd_key_len = AES192_PLAIN_KEY_SIZE;
        std::memcpy(u8_key_buff, key.c_str(), key_len < AES192_PLAIN_KEY_SIZE ? key_len : AES192_PLAIN_KEY_SIZE);
        break;
    case AES256_PLAIN_KEY_SIZE:
        *reqd_key_len = AES256_PLAIN_KEY_SIZE;
        std::memcpy(u8_key_buff, key.c_str(), key_len < AES256_PLAIN_KEY_SIZE ? key_len : AES256_PLAIN_KEY_SIZE);
        break;
    default:
        throw std::invalid_argument("Error parsing key");
    }

    return 0;

}

/**
 * @brief  Function to encrypt given large files (> 1 GB)
 *         with AES ECB using threads. This function acts as the target
 *         method for pybind11 bindings for encrpyt_file()
 */
int symmetric_ciphers::AES::encrpyt_large_file__pybind_target(
    const std::string& f_Name, 
    const std::string& op_file_name, 
    const std::string& key
    ) const {

    uint8_t initzd_key[MAX_SUPPORTED_PLAIN_KEY_SIZE] = { 0 };    /* Max. supported key size. */
    size_t reqd_key_len;

    this->__convert_string_to_uint8_key(key, initzd_key, &reqd_key_len);

    return this->threaded_file_io_algo(f_Name, op_file_name, initzd_key, reqd_key_len, aes_Action::_ENCRYPT_0__);

}

/**
 * @brief  Function to decrypt given large files (> 1 GB)
 *         with AES ECB using threads. This function acts as the target
 *         method for pybind11 bindings for decrpyt_file()
 */
int symmetric_ciphers::AES::decrpyt_large_file__pybind_target(
    const std::string& f_Name, 
    const std::string& op_file_name, 
    const std::string& key
    ) const {

    uint8_t initzd_key[MAX_SUPPORTED_PLAIN_KEY_SIZE] = { 0 };    /* Max. supported key size. */
    size_t reqd_key_len;

    this->__convert_string_to_uint8_key(key, initzd_key, &reqd_key_len);

    return this->threaded_file_io_algo(f_Name, op_file_name, initzd_key, reqd_key_len, aes_Action::_DECRYPT_1__);

}




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

