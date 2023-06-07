/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lib/cilium_builtin.h"

#include "lib/cuckoo_hash.h"
#include "cuckoo_test_usr_cfg.h"

extern __u32 LINUX_KERNEL_VERSION __kconfig;

BPF_CUCKOO_HASH(test_map, struct flow_key, uint32_t, 512)

static bool __always_inline test_case1(struct test_map_cuckoo_hash_map *map) {
    bpf_printk("Number of entries in map: %d\n", map->current_size);
    bpf_printk("Number of entries in t1: %d\n", map->t1.current_size);
    bpf_printk("Number of entries in t2: %d\n", map->t2.current_size);
#if __clang_major__ < 15
#pragma unroll
#endif
    for (int i = 0; i < (sizeof(keys) / sizeof(struct flow_key)); i++) {
        test_map_cuckoo_val_t expected_value = keys[i].protocol;
        test_map_cuckoo_val_t *map_val = test_map_cuckoo_lookup(map, &(keys[i]));
        if (!map_val || *map_val != expected_value) {
            return false;
        }
        bpf_printk("key %d found. Map val: %d/%d\n", i, *map_val, expected_value);
    }
    return true;
}

static bool __always_inline test_case2(struct test_map_cuckoo_hash_map *map) {
    unsigned int array_len = sizeof(keys) / sizeof(keys[0]);

#if __clang_major__ < 15
#pragma unroll
#endif
    for (int i = array_len / 2; i < array_len; i++) {
        test_map_cuckoo_val_t val = keys[i].protocol;
        test_map_cuckoo_insert(map, &(keys[i]), &val);
    }

    return test_case1(map);
}

static bool __always_inline test_case3(struct test_map_cuckoo_hash_map *map) {
#if __clang_major__ < 15
#pragma unroll
#endif
    for (int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        test_map_cuckoo_val_t val = keys[i].protocol;
        test_map_cuckoo_insert(map, &(keys[i]), &val);
    }

    return true;
}

static bool __always_inline test_case4(struct test_map_cuckoo_hash_map *map) {
#if __clang_major__ < 15
#pragma unroll
#endif
    for (int i = 0; i < (sizeof(keys) / sizeof(struct flow_key)); i++) {
        test_map_cuckoo_val_t *map_val = test_map_cuckoo_lookup(map, &(keys[i]));
        if (map_val != NULL) {
            return false;
        }
    }
    return true;
}

SEC("xdp")
int xdp_cuckoo_test_prog(struct xdp_md *ctx) {
    bpf_printk("xdp_cuckoo_test_prog");
    uint32_t zero = 0;
    struct test_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&test_map, &zero);
    bool ret = false;
    if (!map) {
        bpf_printk("map not found");
        return XDP_DROP;
    }

    bpf_printk("Running test case %d", cuckoo_test_cfg.test_case);

    switch (cuckoo_test_cfg.test_case) {
    case 1:
        ret = test_case1(map);
        break;
    case 2:
        ret = test_case2(map);
        break;
    case 3:
        ret = test_case3(map);
        break;
    case 4:
        ret = test_case4(map);
        break;
    default:
        return XDP_ABORTED;
    }

    bpf_printk("Test case %d %s", cuckoo_test_cfg.test_case, ret ? "passed" : "failed");

    if (ret) {
        return XDP_PASS;
    } else {
        return XDP_DROP;
    }
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";