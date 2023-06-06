#ifndef CUCKOO_USR_H
#define CUCKOO_USR_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifndef LIBCUCKOO_API
#define LIBCUCKOO_API __attribute__((visibility("default")))
#endif

#define CUCKOO_ERROR_MSG_SIZE 256
#define HASH_SEED_1 0x2d31e867
#define HASH_SEED_2 0x6ad611c4

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int error_code;
    char error_msg[CUCKOO_ERROR_MSG_SIZE];
} cuckoo_error_t;

typedef struct {
    int map_fd;
    int map_id;
    size_t key_size;
    size_t value_size;
    uint32_t max_entries;
    size_t hash_cell_size;
    size_t table_size;
    size_t entire_map_size;
} cuckoo_hashmap_t;

/**
 * @brief **cuckoo_table_init()** initializes the internal cuckoo hashmap object
 * to be used for all other operations.
 * @param map_id The map id to be used for the hashmap. This is used to identify
 * the cuckoo hashmap in the kernel.
 * @param key_size The size of the key in bytes.
 * @param value_size The size of the value in bytes.
 * @param max_entries The maximum number of entries that can be stored in the
 * hashmap.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return A pointer to a **cuckoo_hashmap_t** object if the function succeeds,
 * NULL otherwise, and the error code and message will be populated in the
 * **cuckoo_error_t** object.
 */
LIBCUCKOO_API cuckoo_hashmap_t *cuckoo_table_init(int map_id, size_t key_size, size_t value_size,
                                                  uint32_t max_entries, cuckoo_error_t *err);

/**
 * @brief **cuckoo_insert()** inserts a key-value pair into the cuckoo hashmap.
 * If the key already exists, the value will be overwritten.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @param key Pointer to the key to be inserted.
 * @param value Pointer to the value to be inserted.
 * @param key_size The size of the key in bytes.
 * @param value_size The size of the value in bytes.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return 0 if the function succeeds, -1 otherwise, and the error code and
 * message will be populated in the **cuckoo_error_t** object.
 */
LIBCUCKOO_API int cuckoo_insert(const cuckoo_hashmap_t *map, const void *key, const void *value,
                                size_t key_size, size_t value_size, cuckoo_error_t *err);

/**
 * @brief **cuckoo_lookup()** looks up a key in the cuckoo hashmap and returns
 * the value if the key exists.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @param key Pointer to the key to be looked up.
 * @param key_size The size of the key in bytes.
 * @param value_to_read Pointer to the value to be read. The value will be
 * copied into this pointer. The caller is responsible for allocating the memory
 * for this pointer.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return 0 if the function succeeds, -1 otherwise, and the error code and
 * message will be populated in the **cuckoo_error_t** object.
 */
LIBCUCKOO_API int cuckoo_lookup(const cuckoo_hashmap_t *map, const void *key, size_t key_size,
                                void *value_to_read, cuckoo_error_t *err);

/**
 * @brief **cuckoo_delete()** deletes a key-value pair from the cuckoo hashmap.
 * If the key does not exist, the function will return success.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @param key Pointer to the key to be deleted.
 * @param key_size The size of the key in bytes.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return 0 if the function succeeds, -1 otherwise, and the error code and
 * message will be populated in the **cuckoo_error_t** object.
 */
LIBCUCKOO_API int cuckoo_delete(const cuckoo_hashmap_t *map, const void *key, size_t key_size,
                                cuckoo_error_t *err);

/**
 * @brief **cuckoo_table_destroy()** destroys the internal cuckoo hashmap object
 * and frees all the resources.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @return void
 */
LIBCUCKOO_API void cuckoo_table_destroy(cuckoo_hashmap_t *map);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // CUCKOO_USR_H