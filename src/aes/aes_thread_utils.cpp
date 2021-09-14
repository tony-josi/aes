#include <string>
#include <fstream>
#include <mutex>
#include <functional>
#include <memory>

#include "aes_thread_utils.hpp"

void file_io_chunk_map_t::copy_meta_data(file_io_chunk_map_t *src_) {
    chunk_id = src_->chunk_id;
    file_indx = src_->file_indx;
    chunk_size = src_->chunk_size;
    last_chunk = src_->last_chunk;
}

file_io_process_DataQueue::file_io_process_DataQueue(const std::string& op_f_name) : algo_worker_status(MAX_ALGO_WORKER_THREAD_COUNT, false) {
    encrpt_complete = false;
    file_read_complete = false;
    op_file_stream = std::ofstream(op_f_name, std::ios::binary);
}

bool file_io_process_DataQueue::get_algo_worker_status() {
    bool status_ = false;
    for (auto itr : algo_worker_status)
        status_ |= itr;
    return status_;
}

bool file_io_process_DataQueue::pop_and_write_op_file_data() {

    std::unique_ptr<file_io_chunk_map_t> cur_chunk;
    std::unique_lock<std::mutex> fio_pop_LOCK(fiop_Mutex);
    size_t rem_elements = 777;
    if (encrpt_complete == true && fiop_DataQueue.empty() == true) {
        fio_pop_LOCK.unlock();

        std::unique_lock<std::mutex> wrk_s__LOCK(worker_Status_Mutex);
        bool wrk_status = get_algo_worker_status();
        wrk_s__LOCK.unlock();

        return wrk_status;
    }
    else if (fiop_DataQueue.empty() != true) {
        cur_chunk = std::move(fiop_DataQueue.back());
        fiop_DataQueue.pop_back();
        rem_elements = fiop_DataQueue.size();
    }
    else {
        fio_pop_LOCK.unlock();
        return true;
    }

    fio_pop_LOCK.unlock();

    op_file_stream.seekp(cur_chunk.get()->file_indx);
    op_file_stream.write(reinterpret_cast<char*>(cur_chunk.get()->chunk_data), cur_chunk.get()->chunk_size);

#ifdef AES_DEBUG_FLAG
    std::cout << "Wrote: " << cur_chunk.get()->chunk_id << " Chunk, size: " << cur_chunk.get()->chunk_size << " Rem ele: "<< rem_elements<< "\n";
#endif /* AES_DEBUG_FLAG */

    return true;

}

bool file_io_process_DataQueue::pop_and_process_ip_data(std::function<void(const std::unique_ptr<file_io_chunk_map_t>&)> __Func__, size_t t_id) {
    std::unique_ptr<file_io_chunk_map_t> cur_chunk;
    std::unique_lock<std::mutex> fii_pop_LOCK(fiip_Mutex);
    if (file_read_complete == true && fiip_DataQueue.empty() == true) {
        encrpt_complete = true;
        fii_pop_LOCK.unlock();
        return false;
    }
    else if (fiip_DataQueue.empty() != true) {
        cur_chunk = std::move(fiip_DataQueue.back());
        fiip_DataQueue.pop_back();
    }
    else {
        fii_pop_LOCK.unlock();
        return true;
    }

    fii_pop_LOCK.unlock();

    std::unique_lock<std::mutex> wrk_s__LOCK(worker_Status_Mutex);
    algo_worker_status[t_id] = true;
    wrk_s__LOCK.unlock();

    __Func__(cur_chunk);
    
    std::unique_lock<std::mutex> wrk_s__LOCK2(worker_Status_Mutex);
    algo_worker_status[t_id] = false;
    wrk_s__LOCK2.unlock();

#ifdef AES_DEBUG_FLAG
    std::cout << "Enc:Dec: " << cur_chunk.get()->chunk_id << " Chunk, size: " << cur_chunk.get()->chunk_size<<"\n";
#endif /* AES_DEBUG_FLAG */

    return true;
}