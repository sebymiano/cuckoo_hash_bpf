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

// Function declarations
LIBCUCKOO_API cuckoo_hashmap_t *cuckoo_table_init(int map_id, size_t key_size, size_t value_size, uint32_t max_entries, cuckoo_error_t *err);
LIBCUCKOO_API int cuckoo_insert(const cuckoo_hashmap_t *map, const void *key, const void *value, size_t key_size, size_t value_size, cuckoo_error_t *err);
LIBCUCKOO_API int cuckoo_lookup(const cuckoo_hashmap_t *map, const void *key, size_t key_size, void *value_to_read, cuckoo_error_t *err);
LIBCUCKOO_API int cuckoo_delete(const cuckoo_hashmap_t *map, const void *key, size_t key_size, cuckoo_error_t *err);
LIBCUCKOO_API void cuckoo_table_destroy(cuckoo_hashmap_t *map);

#endif  // CUCKOO_USR_H