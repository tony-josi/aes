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

#include "aes.hpp"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <string>

using namespace symmetric_ciphers;
namespace {

    constexpr uint8_t key_128_TRD[24] = "12345678123456781234567";

    size_t get_File_Size(std::unique_ptr<FILE, decltype(&fclose)> &file_Ptr) {
        size_t file_Size = 0;
        fseek(file_Ptr.get(), 0, SEEK_END);             // Jump to the end of the file
        file_Size = static_cast<size_t>(ftell(file_Ptr.get()));              // Get the current byte offset in the file
        rewind(file_Ptr.get());                         // Jump back to the beginning of the file
        return file_Size;
    }

    size_t get_FSize(const char *f_Name) {
        std::unique_ptr<FILE, decltype(&fclose)> ip_file_Ptr(fopen(f_Name, "rb"), &fclose);
        return get_File_Size(ip_file_Ptr);
    }

}

int main(int argc, char *argv[]) {

    auto t1 = std::chrono::high_resolution_clock::now();
    AES file_tests(key_size::AES_128);
    

    if(argc > 2) {
        if(strcmp(argv[1], "s") == 0)
            std::cout<<get_FSize(argv[2])<<std::endl;
        else if(argc > 3) {
            std::string pass_wd((char *) key_128_TRD), op_f_name(argv[3]);
            if (strcmp(argv[1], "e") == 0) {
                file_tests.encrpyt_file(argv[2], argv[3], key_128_TRD, 24);
                file_tests.encrpyt_file__pybind_target(argv[2], op_f_name + "pyb", pass_wd);
            }
            else if (strcmp(argv[1], "d") == 0) {
                file_tests.decrpyt_file(argv[2], argv[3], key_128_TRD, 24);
                file_tests.decrpyt_file__pybind_target(argv[2], op_f_name + "pyb", pass_wd);
            }
        }
        else
            std::cout<<"Invalid option\n";
    }

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>\
    ( std::chrono::high_resolution_clock::now() - t1 ).count();
    std::cout<<"\nDuration: "<<duration<<"\n";

    return 0;
}