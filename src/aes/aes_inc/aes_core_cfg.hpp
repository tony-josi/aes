
/* AES Word size */
constexpr   uint8_t     AES_WORD_SIZE                  = 4;

/* 12.8 KB per data segment. */
constexpr   int         AES_DATA_SIZE_PER_SEGMENT      = 12800;  
constexpr   size_t      FILE_IO_CHUNK_SIZE_BYTES       = 12800000 * 2;
constexpr   size_t      MAX_ALGO_WORKER_THREAD_COUNT   = 50;

/* Metdata size should be (AES_WORD_SIZE * AES_WORD_SIZE) */ 
constexpr   size_t      AES_META_DATA_SIZE             = AES_WORD_SIZE * AES_WORD_SIZE;  
constexpr   size_t      AES_META_DATA_PADD_SIZE_OFFSET = 0; 
constexpr   size_t      AES_META_DATA_CHECK_SUM_OFFSET = 8; 

/* Maximum supported plain text key size. */
constexpr   size_t      MAX_SUPPORTED_PLAIN_KEY_SIZE   = 32;

/* Plain text key size. */
constexpr   size_t      AES128_PLAIN_KEY_SIZE          = 16;
constexpr   size_t      AES192_PLAIN_KEY_SIZE          = 24;
constexpr   size_t      AES256_PLAIN_KEY_SIZE          = 32;

