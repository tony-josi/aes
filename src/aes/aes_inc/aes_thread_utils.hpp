

class file_io_chunk_map_t {
public:
    size_t      chunk_id;
    size_t      file_indx;
    size_t      chunk_size;
    uint8_t     chunk_data[FILE_IO_CHUNK_SIZE_BYTES];
    bool        last_chunk;

    void copy_meta_data(
        file_io_chunk_map_t *src_
    );
};

class file_io_process_DataQueue {
public:
    std::mutex                                              fiop_Mutex;
    std::mutex                                              fiip_Mutex;
    std::mutex                                              worker_Status_Mutex;
    std::vector<std::unique_ptr<file_io_chunk_map_t>>       fiop_DataQueue;
    std::vector<std::unique_ptr<file_io_chunk_map_t>>       fiip_DataQueue;
    std::ofstream                                           op_file_stream;
    bool                                                    encrpt_complete;
    bool                                                    file_read_complete;
    std::vector<bool>                                       algo_worker_status;

    file_io_process_DataQueue(
        const std::string& op_f_name
    );
    bool get_algo_worker_status();
    bool pop_and_write_op_file_data();
    bool pop_and_process_ip_data(
        std::function<void(const std::unique_ptr<file_io_chunk_map_t>&)> __Func__, 
        size_t t_id
    );

};
