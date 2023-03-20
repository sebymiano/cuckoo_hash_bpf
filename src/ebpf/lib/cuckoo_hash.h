// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG2(x)                                                                                    \
    ({                                                                                             \
        unsigned _x = (x);                                                                         \
        unsigned _result = 0;                                                                      \
        while (_x >>= 1) {                                                                         \
            _result++;                                                                             \
        }                                                                                          \
        _result;                                                                                   \
    })

#define NUMBER_OF_HASH_TABLES 2
#define HASH_TYPE_NUM 2

#if HASH_TYPE_NUM == 1
#define HASH_TYPE xxhash64
#include "xxhash64.h"
#elif HASH_TYPE_NUM == 2
#define HASH_TYPE fasthash32
#include "fasthash.h"
#endif

#include "cilium_builtin.h"

#define HASH_SEED_1 0x2d31e867
#define HASH_SEED_2 0x6ad611c4

#define MAX_LOOP(x)                                                                                \
    ({                                                                                             \
        uint32_t _x = (x);                                                                         \
        4 + (int)(4 * LOG2(_x) / LOG2(2) + 0.5);                                                   \
    })

#define BPF_CUCKOO_HASH(_name, _key_type, _leaf_type, _max_entries)                                \
    static const uint32_t _name##_map_capacity = _max_entries;                                     \
    typedef _leaf_type _name##_cuckoo_val_t;                                                       \
    typedef _key_type _name##_cuckoo_key_t;                                                        \
                                                                                                   \
    struct _name##_cuckoo_hash_cell {                                                              \
        bool is_filled;                                                                            \
        _name##_cuckoo_key_t key;                                                                  \
        _name##_cuckoo_val_t val;                                                                  \
    };                                                                                             \
                                                                                                   \
    struct _name##_cuckoo_hash_table {                                                             \
        int current_size;                                                                          \
        struct _name##_cuckoo_hash_cell elem_list[_max_entries];                                   \
    };                                                                                             \
                                                                                                   \
    struct _name##_cuckoo_hash_map {                                                               \
        int current_size;                    /* Current size */                                    \
        struct _name##_cuckoo_hash_table t1; /* First hash table */                                \
        struct _name##_cuckoo_hash_table t2; /* Second hash table */                               \
    };                                                                                             \
                                                                                                   \
    struct {                                                                                       \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                   \
        __type(key, __u32);                                                                        \
        __type(value, struct _name##_cuckoo_hash_map);                                             \
        __uint(max_entries, 1);                                                                    \
    } _name SEC(".maps");                                                                          \
                                                                                                   \
    static __always_inline void _name##_sync_total_map_size(struct _name##_cuckoo_hash_map *map) { \
        map->current_size = map->t1.current_size + map->t2.current_size;                           \
    }                                                                                              \
                                                                                                   \
    struct _name##_cuckoo_insert_loop_ctx {                                                        \
        struct _name##_cuckoo_hash_map *map;                                                       \
        uint32_t hash1;                                                                            \
        uint32_t hash2;                                                                            \
        struct _name##_cuckoo_hash_cell new_elem;                                                  \
        bool inserted;                                                                             \
        uint32_t idx;                                                                              \
    };                                                                                             \
                                                                                                   \
    static int _name##_cuckoo_insert_loop(uint32_t index, void *data) {                            \
        struct _name##_cuckoo_insert_loop_ctx *ctx =                                               \
            (struct _name##_cuckoo_insert_loop_ctx *)data;                                         \
        struct _name##_cuckoo_hash_cell *elem;                                                     \
        struct _name##_cuckoo_hash_cell x, tmp;                                                    \
                                                                                                   \
        memset(&x, 0, sizeof(struct _name##_cuckoo_hash_cell));                                    \
        memset(&tmp, 0, sizeof(struct _name##_cuckoo_hash_cell));                                  \
                                                                                                   \
        memcpy(&x, &ctx->new_elem, sizeof(struct _name##_cuckoo_hash_cell));                       \
                                                                                                   \
        uint32_t idx = ctx->hash1 & (_name##_map_capacity - 1);                                    \
        if (idx >= _name##_map_capacity) {                                                         \
            return 1;                                                                              \
        }                                                                                          \
        elem = &ctx->map->t1.elem_list[idx];                                                       \
        memcpy(&tmp, elem, sizeof(struct _name##_cuckoo_hash_cell));                               \
                                                                                                   \
        memcpy(elem, &x, sizeof(struct _name##_cuckoo_hash_cell));                                 \
                                                                                                   \
        if (!tmp.is_filled) {                                                                      \
            ctx->map->t1.current_size++;                                                           \
            _name##_sync_total_map_size(ctx->map);                                                 \
            ctx->inserted = true;                                                                  \
            ctx->idx = idx;                                                                        \
            return 1;                                                                              \
        }                                                                                          \
                                                                                                   \
        memcpy(&x, &tmp, sizeof(struct _name##_cuckoo_hash_cell));                                 \
        ctx->hash2 = HASH_TYPE((void *)&x.key, sizeof(_name##_cuckoo_key_t), HASH_SEED_2);         \
        idx = ctx->hash2 & (_name##_map_capacity - 1);                                             \
        if (idx >= _name##_map_capacity) {                                                         \
            return 1;                                                                              \
        }                                                                                          \
        elem = &ctx->map->t2.elem_list[idx];                                                       \
                                                                                                   \
        memcpy(&tmp, elem, sizeof(struct _name##_cuckoo_hash_cell));                               \
                                                                                                   \
        memcpy(elem, &x, sizeof(struct _name##_cuckoo_hash_cell));                                 \
                                                                                                   \
        if (!tmp.is_filled) {                                                                      \
            ctx->map->t2.current_size++;                                                           \
            _name##_sync_total_map_size(ctx->map);                                                 \
            ctx->inserted = true;                                                                  \
            ctx->idx = idx;                                                                        \
            return 1;                                                                              \
        }                                                                                          \
                                                                                                   \
        memcpy(&ctx->new_elem, &tmp, sizeof(struct _name##_cuckoo_hash_cell));                     \
        ctx->hash1 = HASH_TYPE((void *)&tmp.key, sizeof(_name##_cuckoo_key_t), HASH_SEED_1);       \
                                                                                                   \
        return 0;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static __always_inline bool _name##_cuckoo_insert(struct _name##_cuckoo_hash_map *map,         \
                                                      _name##_cuckoo_key_t *key,                   \
                                                      _name##_cuckoo_val_t *val) {                 \
        struct _name##_cuckoo_hash_cell *elem;                                                     \
        struct _name##_cuckoo_hash_cell x;                                                         \
        uint32_t hash1, hash2;                                                                     \
                                                                                                   \
        hash1 = HASH_TYPE((void *)key, sizeof(_name##_cuckoo_key_t), HASH_SEED_1);                 \
        uint32_t idx = hash1 & (_name##_map_capacity - 1);                                         \
        if (idx >= _name##_map_capacity) {                                                         \
            return false;                                                                          \
        }                                                                                          \
        elem = &map->t1.elem_list[idx];                                                            \
        if (elem->is_filled) {                                                                     \
            if (memcmp(key, &(elem->key), sizeof(_name##_cuckoo_key_t)) == 0) {                    \
                memcpy(&(elem->val), val, sizeof(_name##_cuckoo_val_t));                           \
                return false;                                                                      \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        hash2 = HASH_TYPE((void *)key, sizeof(_name##_cuckoo_key_t), HASH_SEED_2);                 \
        idx = hash2 & (_name##_map_capacity - 1);                                                  \
        if (idx >= _name##_map_capacity) {                                                         \
            return false;                                                                          \
        }                                                                                          \
        elem = &map->t2.elem_list[idx];                                                            \
        if (elem->is_filled) {                                                                     \
            if (memcmp(key, &(elem->key), sizeof(_name##_cuckoo_key_t)) == 0) {                    \
                memcpy(&(elem->val), val, sizeof(_name##_cuckoo_val_t));                           \
                return false;                                                                      \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        memset(&x, 0, sizeof(struct _name##_cuckoo_hash_cell));                                    \
                                                                                                   \
        x.is_filled = true;                                                                        \
        memcpy(&x.key, key, sizeof(_name##_cuckoo_key_t));                                         \
        memcpy(&x.val, val, sizeof(_name##_cuckoo_val_t));                                         \
                                                                                                   \
        struct _name##_cuckoo_insert_loop_ctx loop_ctx;                                            \
        memset(&loop_ctx, 0, sizeof(struct _name##_cuckoo_insert_loop_ctx));                       \
        loop_ctx.map = map;                                                                        \
        loop_ctx.hash1 = hash1;                                                                    \
        loop_ctx.hash2 = hash2;                                                                    \
                                                                                                   \
        memcpy(&loop_ctx.new_elem, &x, sizeof(struct _name##_cuckoo_hash_cell));                   \
        loop_ctx.inserted = false;                                                                 \
        loop_ctx.idx = 0;                                                                          \
                                                                                                   \
        bpf_loop(MAX_LOOP(_name##_map_capacity), &_name##_cuckoo_insert_loop, &loop_ctx, 0);       \
                                                                                                   \
        if (loop_ctx.inserted) {                                                                   \
            return true;                                                                           \
        }                                                                                          \
                                                                                                   \
        return false;                                                                              \
    }                                                                                              \
                                                                                                   \
    static __always_inline _name##_cuckoo_val_t *_name##_cuckoo_lookup(                            \
        struct _name##_cuckoo_hash_map *map, const _name##_cuckoo_key_t *key) {                    \
        struct _name##_cuckoo_hash_cell *elem;                                                     \
        uint32_t hash;                                                                             \
                                                                                                   \
        hash = HASH_TYPE((void *)key, sizeof(_name##_cuckoo_key_t), HASH_SEED_1);                  \
        uint32_t idx = hash & (_name##_map_capacity - 1);                                          \
        if (idx >= _name##_map_capacity) {                                                         \
            return NULL;                                                                           \
        }                                                                                          \
        elem = &map->t1.elem_list[idx];                                                            \
        if (elem->is_filled) {                                                                     \
            if (memcmp(key, &(elem->key), sizeof(_name##_cuckoo_key_t)) == 0) {                    \
                return &(elem->val);                                                               \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        hash = HASH_TYPE((void *)key, sizeof(_name##_cuckoo_key_t), HASH_SEED_2);                  \
        idx = hash & (_name##_map_capacity - 1);                                                   \
        if (idx >= _name##_map_capacity) {                                                         \
            return false;                                                                          \
        }                                                                                          \
        elem = &map->t2.elem_list[idx];                                                            \
        if (elem->is_filled) {                                                                     \
            if (memcmp(key, &(elem->key), sizeof(_name##_cuckoo_key_t)) == 0) {                    \
                return &(elem->val);                                                               \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        return NULL;                                                                               \
    }                                                                                              \
                                                                                                   \
    static __always_inline bool _name##_cuckoo_delete(struct _name##_cuckoo_hash_map *map,         \
                                                      const _name##_cuckoo_key_t *key) {           \
        struct _name##_cuckoo_hash_cell *elem;                                                     \
        uint32_t hash;                                                                             \
                                                                                                   \
        hash = HASH_TYPE((void *)key, sizeof(_name##_cuckoo_key_t), HASH_SEED_1);                  \
        uint32_t idx = hash & (_name##_map_capacity - 1);                                          \
        if (idx >= _name##_map_capacity) {                                                         \
            return false;                                                                          \
        }                                                                                          \
        elem = &map->t1.elem_list[idx];                                                            \
        if (elem->is_filled) {                                                                     \
            if (memcmp(key, &(elem->key), sizeof(_name##_cuckoo_key_t)) == 0) {                    \
                elem->is_filled = false;                                                           \
                map->t1.current_size--;                                                            \
                _name##_sync_total_map_size(map);                                                  \
                return true;                                                                       \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        hash = HASH_TYPE((void *)key, sizeof(_name##_cuckoo_key_t), HASH_SEED_2);                  \
        idx = hash & (_name##_map_capacity - 1);                                                   \
        if (idx >= _name##_map_capacity) {                                                         \
            return false;                                                                          \
        }                                                                                          \
        elem = &map->t2.elem_list[idx];                                                            \
        if (elem->is_filled) {                                                                     \
            if (memcmp(key, &(elem->key), sizeof(_name##_cuckoo_key_t)) == 0) {                    \
                elem->is_filled = false;                                                           \
                map->t2.current_size--;                                                            \
                _name##_sync_total_map_size(map);                                                  \
                return true;                                                                       \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        return false;                                                                              \
    }