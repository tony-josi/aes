import py_sc_aes
import sys, time

if __name__ == "__main__":

    if len(sys.argv) >= 5:

        prev_time = time.time()
        aes_128_obj = py_sc_aes.AES(py_sc_aes.AES_128)
        if sys.argv[1] == "e":
            print(aes_128_obj.encrypt_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        elif sys.argv[1] == "d":
            print(aes_128_obj.decrypt_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        if sys.argv[1] == "x":
            print(aes_128_obj.encrypt_large_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        elif sys.argv[1] == "y":
            print(aes_128_obj.decrypt_large_file(sys.argv[2], sys.argv[3], sys.argv[4]))
        print("Duration: ", (time.time() - prev_time) * 1000)