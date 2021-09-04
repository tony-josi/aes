#include "pybind11/pybind11.h"

#include "aes.hpp"

PYBIND11_MODULE(py_sc_aes, module) {

	module.doc() = "Python binding of the AES symmetric cipher algorithm library written in C++. "
		"Uses electronic codebook mode with support for 128/192/256 bit keys. "
		"\n"
		"The Advanced Encryption Standard (AES), also known by its original name Rijndael "
		"is a specification for the encryption of electronic data established by the U.S. "
		"National Institute of Standards and Technology(NIST). "
		"\n"
		"This implementation currently supports Electronic codebook mode with support for "
		"128 / 192 / 256 bit keys and option for multi threading that spawns upto std::thread::hardware_concurrency() threads.";

	pybind11::enum_<symmetric_ciphers::key_size>(module, "key_size")
		.value("AES_128", symmetric_ciphers::AES_128)
		.value("AES_192", symmetric_ciphers::AES_192)
		.value("AES_256", symmetric_ciphers::AES_256)
		.export_values();

	pybind11::class_<symmetric_ciphers::AES>(module, "AES")
		.def(pybind11::init<symmetric_ciphers::key_size>())
		.def("encrypt_file", &symmetric_ciphers::AES::encrpyt_file__pybind_target)
		.def("decrypt_file", &symmetric_ciphers::AES::decrpyt_file__pybind_target);

}