
/* AES Word size */
#define     AES_WORD_SIZE					(4ULL)

/* 12.8 KB per data segment. */
#define   AES_DATA_SIZE_PER_SEGMENT			(12800ULL)
#define   FILE_IO_CHUNK_SIZE_BYTES			(12800000ULL * 2)
#define   MAX_ALGO_WORKER_THREAD_COUNT		(50ULL)

/* Metdata size should be (AES_WORD_SIZE * AES_WORD_SIZE) */ 
#define   AES_META_DATA_SIZE				(AES_WORD_SIZE * AES_WORD_SIZE)  
#define   AES_META_DATA_PADD_SIZE_OFFSET	(0ULL) 
#define   AES_META_DATA_CHECK_SUM_OFFSET	(8ULL) 

/* Maximum supported plain text key size. */
#define   MAX_SUPPORTED_PLAIN_KEY_SIZE		(32ULL)

/* Plain text key size. */
#define   AES128_PLAIN_KEY_SIZE				(16ULL)
#define   AES192_PLAIN_KEY_SIZE				(24ULL)
#define   AES256_PLAIN_KEY_SIZE				(32ULL)

