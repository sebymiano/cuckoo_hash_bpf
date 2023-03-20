// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG2(x) ({                 \
    unsigned _x = (x);             \
    unsigned _result = 0;          \
    while (_x >>= 1) {             \
        _result++;                 \
    }                               \
    _result;                        \
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

#define MAP_CAPACITY 256

#define HASH_SEED_1 0x2d31e867
#define HASH_SEED_2 0x6ad611c4

#define MAX_LOOP (4 + (int)(4 * LOG2(MAP_CAPACITY) / LOG2(2) + 0.5))

struct flow_key {
  uint8_t protocol;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
};

#define BPF_CUCKOO_HASH_TYPES(_key_type, _leaf_type) \
typedef _leaf_type cuckoo_val_t; \
typedef _key_type cuckoo_key_t; \

BPF_CUCKOO_HASH_TYPES(struct flow_key, uint64_t)

struct cuckoo_hash_cell { 
  bool is_filled; 
  cuckoo_key_t key; 
  cuckoo_val_t val; 
}; 

struct cuckoo_hash_table { 
  int current_size; 
  struct cuckoo_hash_cell elem_list[MAP_CAPACITY]; 
}; 
  
struct cuckoo_hash_map { 
  int current_size;                   /* Current size */
  struct cuckoo_hash_table t1;        /* First hash table */
  struct cuckoo_hash_table t2;        /* Second hash table */
}; 

struct { 
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); 
  __type(key, __u32); 
  __type(value, struct cuckoo_hash_map); 
  __uint(max_entries, 1); 
} test_map SEC(".maps");


static __always_inline void sync_total_map_size(struct cuckoo_hash_map* map) {
  map->current_size = map->t1.current_size + map->t2.current_size;
}

struct cuckoo_insert_loop_ctx {
  struct cuckoo_hash_map* map;
  uint32_t hash1;
  uint32_t hash2;
  struct cuckoo_hash_cell new_elem;
  bool inserted;
  uint32_t idx;
};

static int cuckoo_insert_loop(uint32_t index, void *data) {
  struct cuckoo_insert_loop_ctx *ctx = (struct cuckoo_insert_loop_ctx *)data;
  struct cuckoo_hash_cell *elem;
  struct cuckoo_hash_cell tmp, x;

  memset(&x, 0, sizeof(struct cuckoo_hash_cell));
  memset(&tmp, 0, sizeof(struct cuckoo_hash_cell));

  memcpy(&x, &ctx->new_elem, sizeof(struct cuckoo_hash_cell));

  uint32_t idx = ctx->hash1 & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return 1;
  }
  elem = &ctx->map->t1.elem_list[idx];
  memcpy(&tmp, elem, sizeof(struct cuckoo_hash_cell));

  //Set the new element
  memcpy(elem, &x, sizeof(struct cuckoo_hash_cell));

  if (!tmp.is_filled) {
    ctx->map->t1.current_size++;
    sync_total_map_size(ctx->map);
    ctx->inserted = true;
    ctx->idx = idx; 
    // This will stop the loop
    return 1;
  }

  // Set the element in the second table
  memcpy(&x, &tmp, sizeof(struct cuckoo_hash_cell));
  ctx->hash2 = HASH_TYPE((void*)&x.key, sizeof(cuckoo_key_t), HASH_SEED_2);
  idx = ctx->hash2 & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return 1;
  }

  elem = &ctx->map->t2.elem_list[idx];

  memcpy(&tmp, elem, sizeof(struct cuckoo_hash_cell));

  //Set the new element
  memcpy(elem, &x, sizeof(struct cuckoo_hash_cell));

  if (!tmp.is_filled) {
    ctx->map->t2.current_size++;
    sync_total_map_size(ctx->map);
    ctx->inserted = true;
    ctx->idx = idx;
    // This will stop the loop
    return 1;
  }

  memcpy(&ctx->new_elem, &tmp, sizeof(struct cuckoo_hash_cell));
  ctx->hash1 = HASH_TYPE((void*)&tmp.key, sizeof(cuckoo_key_t), HASH_SEED_1);
  

  // This will continue the loop
  return 0;
}

static __always_inline bool cuckoo_insert(struct cuckoo_hash_map* map, cuckoo_key_t *key, cuckoo_val_t *val) { 
  struct cuckoo_hash_cell *elem;
  struct cuckoo_hash_cell x;
  struct cuckoo_hash_table *table;
  uint32_t hash1, hash2;

  /*
   * If the element is already in the table, then overwrite and return.
   */
  hash1 = HASH_TYPE((void*)key, sizeof(cuckoo_key_t), HASH_SEED_1);
  uint32_t idx = hash1 & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return false;
  }
  elem = &map->t1.elem_list[idx];
  if (elem->is_filled) {
    if (memcmp(key, &(elem->key), sizeof(cuckoo_key_t)) == 0) {
      memcpy(&(elem->val), val, sizeof(cuckoo_val_t));
      return false;
    }
  }

  /* (hash / MAP_CAPACITY) % MAP_CAPACITY; */
  hash2 = HASH_TYPE((void*)key, sizeof(cuckoo_key_t), HASH_SEED_2);
  idx = hash2 & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return false;
  }
  elem = &map->t2.elem_list[idx];
  if (elem->is_filled) {
    if (memcmp(key, &(elem->key), sizeof(cuckoo_key_t)) == 0) {
      memcpy(&(elem->val), val, sizeof(cuckoo_val_t));
      return false;
    }
  }

  memset(&x, 0, sizeof(struct cuckoo_hash_cell));
  /*
   * If not, the insert the new element in the table.
   */
  x.is_filled = true;
  memcpy(&x.key, key, sizeof(cuckoo_key_t));
  memcpy(&x.val, val, sizeof(cuckoo_val_t));
  
  struct cuckoo_insert_loop_ctx loop_ctx;
  memset(&loop_ctx, 0, sizeof(struct cuckoo_insert_loop_ctx));
  loop_ctx.map = map;
  loop_ctx.hash1 = hash1;
  loop_ctx.hash2 = hash2;

  memcpy(&loop_ctx.new_elem, &x, sizeof(struct cuckoo_hash_cell));
  loop_ctx.inserted = false;
  loop_ctx.idx = 0;

  bpf_loop(MAX_LOOP, &cuckoo_insert_loop, &loop_ctx, 0);

  if (loop_ctx.inserted) {
    return true;
  }

  // TODO: If we arrive here, I should rehash the table
  // table_rehash(map);
  // cuckoo_insert(map, key, val);
  // return true;

  return false;
}

// void print_hash(int table_number, uint32_t hash, uint32_t index) {
//  printf("at table: %d; hash key: %u; index: %u\n", table_number, hash, index);
// }

static __always_inline void* cuckoo_lookup(struct cuckoo_hash_map* map, const void* key) {
  struct cuckoo_hash_cell *elem;
  struct cuckoo_hash_table *table;
  uint32_t hash;

  hash = HASH_TYPE((void*)key, sizeof(cuckoo_key_t), HASH_SEED_1);
  uint32_t idx = hash & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return NULL;
  }
  elem = &map->t1.elem_list[idx];
  if (elem->is_filled) {
    if (memcmp(key, &(elem->key), sizeof(cuckoo_key_t)) == 0) {
      return &(elem->val);
    }
  }

  /* (hash / MAP_CAPACITY) % MAP_CAPACITY; */
  hash = HASH_TYPE((void*)key, sizeof(cuckoo_key_t), HASH_SEED_2);
  idx = hash & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return NULL;
  }
  elem = &map->t2.elem_list[idx];
  if (elem->is_filled) {
    if (memcmp(key, &(elem->key), sizeof(cuckoo_key_t)) == 0) {
      return &(elem->val);
    }
  }

  return NULL;
}

static __always_inline bool cuckoo_delete(struct cuckoo_hash_map* map, const void* key) {
  struct cuckoo_hash_cell *elem;
  struct cuckoo_hash_table *table;
  uint32_t hash;

  hash = HASH_TYPE((void*)key, sizeof(cuckoo_key_t), HASH_SEED_1);
  elem = &map->t1.elem_list[hash % MAP_CAPACITY];
  uint32_t idx = hash & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return false;
  }
  elem = &map->t1.elem_list[idx];
  if (elem->is_filled) {
    if (memcmp(key, &(elem->key), sizeof(cuckoo_key_t)) == 0) {
      elem->is_filled = false;
      map->t1.current_size--;
      sync_total_map_size(map);
      return true;
    }
  }

  /* (hash / MAP_CAPACITY) % MAP_CAPACITY; */
  hash = HASH_TYPE((void*)key, sizeof(cuckoo_key_t), HASH_SEED_2);
  idx = hash & (MAP_CAPACITY - 1);
  if (idx >= MAP_CAPACITY) {
    return false;
  }
  elem = &map->t2.elem_list[idx];
  if (elem->is_filled) {
    if (memcmp(key, &(elem->key), sizeof(cuckoo_key_t)) == 0) {
      elem->is_filled = false;
      map->t2.current_size--;
      sync_total_map_size(map);
      return true;
    }
  }

  return false;
}