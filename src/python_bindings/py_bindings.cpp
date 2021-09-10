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
		.value("AES_128", symmetric_ciphers::key_size::AES_128, "AES 128 bit key mode")
		.value("AES_192", symmetric_ciphers::key_size::AES_192, "AES 192 bit key mode")
		.value("AES_256", symmetric_ciphers::key_size::AES_256, "AES 256 bit key mode")
		.export_values();

	pybind11::class_<symmetric_ciphers::AES>(module, "AES")
		.def(pybind11::init<symmetric_ciphers::key_size>())
		.def("encrypt_file", &symmetric_ciphers::AES::encrpyt_file__pybind_target, \
			"Encrypt the given file (ip_file_name), name the output file (op_file_name), with the given key.", \
			pybind11::arg("ip_file_name"), pybind11::arg("op_file_name") = "op_file.enc", pybind11::arg("key") = "passwd1234")
		.def("decrypt_file", &symmetric_ciphers::AES::decrpyt_file__pybind_target, \
			"Decrypt the given file (ip_file_name), name the output file (op_file_name), with the given key.", \
			pybind11::arg("ip_file_name"), pybind11::arg("op_file_name") = "decrypted_noname_file", pybind11::arg("key") = "passwd1234")
		.def("encrypt_large_file", &symmetric_ciphers::AES::encrpyt_large_file__pybind_target, \
			"Encrypt the given large file (> 1 GB) (ip_file_name), name the output file (op_file_name), with the given key.", \
			pybind11::arg("ip_file_name"), pybind11::arg("op_file_name") = "op_file.enc", pybind11::arg("key") = "passwd1234")
		.def("decrypt_large_file", &symmetric_ciphers::AES::decrpyt_large_file__pybind_target, \
			"Decrypt the given large file (> 1 GB) (ip_file_name), name the output file (op_file_name), with the given key.", \
			pybind11::arg("ip_file_name"), pybind11::arg("op_file_name") = "decrypted_noname_file", pybind11::arg("key") = "passwd1234");

}
