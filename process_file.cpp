/** 
 *  @file   main.cpp
 *  @brief  AES Test File
 *
 *  This file tests AES Implementation 128/192/256 bit modes.
 *
 *  @author         Tony Josi   https://tonyjosi97.github.io/profile/
 *  @copyright      Copyright (C) 2020 Tony Josi
 *  @bug            No known bugs.
 */

#include "inc/aes.hpp"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>

using namespace symmetric_ciphers;

namespace {

    constexpr uint8_t key_128_TRD[24] = "12345678123456781234567";

    size_t get_File_Size(std::unique_ptr<FILE, decltype(&fclose)> &file_Ptr) {
        size_t file_Size = 0;
        fseek(file_Ptr.get(), 0, SEEK_END);             // Jump to the end of the file
        file_Size = ftell(file_Ptr.get());              // Get the current byte offset in the file
        rewind(file_Ptr.get());                         // Jump back to the beginning of the file
        return file_Size;
    }

    size_t get_FSize(const char *f_Name) {
        std::unique_ptr<FILE, decltype(&fclose)> ip_file_Ptr(fopen(f_Name, "rb"), &fclose);
        return get_File_Size(ip_file_Ptr);
    }

    void encrypt_File(const char *f_Name){

        std::unique_ptr<FILE, decltype(&fclose)> ip_file_Ptr(fopen(f_Name, "rb"), &fclose);
        size_t file_Size = get_File_Size(ip_file_Ptr);

        /* read data from file to buffer */
        std::unique_ptr<uint8_t []> pt_file_Buff(new uint8_t[file_Size]);
        fread(pt_file_Buff.get(), file_Size, 1, ip_file_Ptr.get());
    
        std::unique_ptr<uint8_t []> ct_file_Buff(new uint8_t[file_Size]);
        AES file_enc(AES_128);
        file_enc.encrpyt_block_ecb_threaded(pt_file_Buff.get(), key_128_TRD, ct_file_Buff.get(), file_Size, 16);

        std::unique_ptr<FILE, decltype(&fclose)> ct_file_Ptr(fopen("ct.txt", "wb"), &fclose);
        fwrite(ct_file_Buff.get(), 1, file_Size, ct_file_Ptr.get());
    }

    void decrypt_File(const char *f_Name){

        std::unique_ptr<FILE, decltype(&fclose)> ip_file_Ptr(fopen(f_Name, "rb"), &fclose);
        size_t file_Size = get_File_Size(ip_file_Ptr);

        /* read data from file to buffer */
        std::unique_ptr<uint8_t []> ct_file_Buff(new uint8_t[file_Size]);
        fread(ct_file_Buff.get(), file_Size, 1, ip_file_Ptr.get());
    
        std::unique_ptr<uint8_t []> op_file_Buff(new uint8_t[file_Size]);
        AES file_enc(AES_128);
        file_enc.decrpyt_block_ecb_threaded(ct_file_Buff.get(), key_128_TRD, op_file_Buff.get(), file_Size, 16);

        std::unique_ptr<FILE, decltype(&fclose)> op_file_Ptr(fopen("op.txt", "wb"), &fclose);
        fwrite(op_file_Buff.get(), 1, file_Size, op_file_Ptr.get());
    }
}

int main(int argc, char *argv[]) {

    AES file_tests(AES_192);
    std::cout<<argv[1]<<std::endl;
    if(argc > 2) {
        if(strcmp(argv[1], "s") == 0)
            std::cout<<get_FSize(argv[2])<<std::endl;
        else if(strcmp(argv[1], "e") == 0)
            file_tests.encrpyt_file(argv[2], key_128_TRD, 24);
        else if(strcmp(argv[1], "d") == 0)
            file_tests.decrpyt_file(argv[2], key_128_TRD, 24);
        else
            std::cout<<"Invalid option\n";
    }

    return 0;
}