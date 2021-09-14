/** 
 *  @file   aes_operations.cpp
 *  @brief  AES process steps.
 *
 *  This file contains the source code for the individual steps involved in
 *  the encryption/decryption process.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2021 Tony Josi
 *  @bug            No known bugs.
 */

#include <cstdint>
#include <string>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <fstream>

#include "aes_operations.hpp"
#include "aes_lookup_tables.hpp"

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

void __aes_xor_word(
    uint8_t             target[AES_WORD_SIZE],
    const uint8_t       operand[AES_WORD_SIZE]
) {

    for(int i = 0; i < AES_WORD_SIZE; ++i) 
        target[i] ^= operand[i];

}

void __aes_transposition(
    uint8_t             cur_state[AES_WORD_SIZE][AES_WORD_SIZE],
    const uint8_t       ip[],
    const size_t           offset
) {
    /* Transposition bytes to matrix form - column major */
    for(size_t i = 0; i < AES_WORD_SIZE; ++i)
        for(size_t j = 0; j < AES_WORD_SIZE; ++j)
            cur_state[i][j] = ip[ offset + (j * 4) + i ];

}

void __aes_rev_transposition(
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