/** 
 *  @file   aes_operations.hpp
 *  @brief  AES process steps header.
 *
 *  This file contains the header code for the individual steps involved in
 *  the encryption/decryption process.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2021 Tony Josi
 *  @bug            No known bugs.
 */

#ifndef _AES_OPRN_HEADER_TJ__
#define _AES_OPRN_HEADER_TJ__

#include <memory>

#include "aes_core_cfg.hpp"

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

void __aes_xor_word(
    uint8_t                     target[AES_WORD_SIZE],
    const uint8_t               operand[AES_WORD_SIZE]
);

void __aes_transposition(
    uint8_t                     cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
    const uint8_t               ip[],
    const size_t                offset
);

void __aes_rev_transposition(
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

#endif /* _AES_OPRN_HEADER_TJ__ */