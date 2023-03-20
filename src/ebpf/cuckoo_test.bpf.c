/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com> */

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
#include "cuckoo_test_cfg.h"

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct flow_key {
    uint8_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

BPF_CUCKOO_HASH(test_map, struct flow_key, uint64_t, 256)

static bool __always_inline test_case1(struct test_map_cuckoo_hash_map *map) {
    struct flow_key flow1 = {
        .protocol = 17, .src_ip = 0x10101010, .dst_ip = 0x10101011, .src_port = 1, .dst_port = 2};
    uint64_t *val = test_map_cuckoo_lookup(map, &flow1);
    if (val == NULL)
        return true;

    return false;
}

static bool __always_inline test_case2(struct test_map_cuckoo_hash_map *map) {
    struct flow_key flow1 = {
        .protocol = 17, .src_ip = 0x10101010, .dst_ip = 0x10101011, .src_port = 1, .dst_port = 2};
    uint64_t val = 64;
    if (test_map_cuckoo_insert(map, &flow1, &val)) {
        return true;
    }
    return false;
}

static bool __always_inline test_case3(struct test_map_cuckoo_hash_map *map) {
    struct flow_key flow1 = {
        .protocol = 17, .src_ip = 0x10101010, .dst_ip = 0x10101011, .src_port = 1, .dst_port = 2};
    uint64_t val = 64;
    test_map_cuckoo_insert(map, &flow1, &val);

    uint64_t *ret_val = test_map_cuckoo_lookup(map, &flow1);
    if (ret_val) {
        bpf_printk("ret_val: %d", *ret_val);
    }
    if (!ret_val || *ret_val != 64)
        return false;

    return true;
}

static bool __always_inline test_case4(struct test_map_cuckoo_hash_map *map) {
    struct flow_key flow1 = {
        .protocol = 17, .src_ip = 0x10101010, .dst_ip = 0x10101011, .src_port = 1, .dst_port = 2};
    uint64_t val = 64;
    test_map_cuckoo_insert(map, &flow1, &val);

    uint64_t *ret_val = test_map_cuckoo_lookup(map, &flow1);
    if (!ret_val || *ret_val != 64)
        return false;

    test_map_cuckoo_delete(map, &flow1);

    ret_val = test_map_cuckoo_lookup(map, &flow1);
    if (ret_val)
        return false;

    return true;
}

static bool __always_inline test_case5(struct test_map_cuckoo_hash_map *map) {
    struct flow_key flow3 = {
        .protocol = 17, .src_ip = 0x10101010, .dst_ip = 0x10101013, .src_port = 2, .dst_port = 1};
    struct flow_key flow4 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 10};
    struct flow_key flow5 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 22};
    struct flow_key flow6 = {
        .protocol = 50, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 15, .dst_port = 10};
    struct flow_key flow7 = {
        .protocol = 70, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 20};
    struct flow_key flow8 = {
        .protocol = 50, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 7};
    struct flow_key flow9 = {
        .protocol = 100, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 2, .dst_port = 3};
    struct flow_key flow10 = {
        .protocol = 1, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 1};
    struct flow_key flow11 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 3, .dst_port = 3};
    struct flow_key flow12 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 4, .dst_port = 5};
    struct flow_key flow_array[] = {flow3, flow4, flow5,  flow6,  flow7,
                                    flow8, flow9, flow10, flow11, flow12};

    for (int i = 0; i < (sizeof(flow_array) / sizeof(struct flow_key)); i++) {
        uint64_t value = flow_array[i].protocol + flow_array[i].src_port + flow_array[i].dst_port;
        test_map_cuckoo_insert(map, &(flow_array[i]), &value);
        uint64_t *map_val = test_map_cuckoo_lookup(map, &(flow_array[i]));
        if (!map_val || *map_val != value) {
            return false;
        }
    }
    return true;
}

static bool __always_inline test_case6(struct test_map_cuckoo_hash_map *map) {
    struct flow_key flow3 = {
        .protocol = 17, .src_ip = 0x10101010, .dst_ip = 0x10101013, .src_port = 2, .dst_port = 1};
    struct flow_key flow4 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 10};
    struct flow_key flow5 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 22};
    struct flow_key flow6 = {
        .protocol = 50, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 15, .dst_port = 10};
    struct flow_key flow7 = {
        .protocol = 70, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 20};
    struct flow_key flow8 = {
        .protocol = 50, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 7};
    struct flow_key flow9 = {
        .protocol = 100, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 2, .dst_port = 3};
    struct flow_key flow10 = {
        .protocol = 1, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 1};
    struct flow_key flow11 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 3, .dst_port = 3};
    struct flow_key flow12 = {
        .protocol = 30, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 4, .dst_port = 5};
    struct flow_key flow_array[] = {flow3, flow4, flow5,  flow6,  flow7,
                                    flow8, flow9, flow10, flow11, flow12};

    for (int i = 0; i < (sizeof(flow_array) / sizeof(struct flow_key)); i++) {
        uint64_t value = flow_array[i].protocol + flow_array[i].src_port + flow_array[i].dst_port;
        if (!test_map_cuckoo_insert(map, &(flow_array[i]), &value)) {
            return false;
        }
    }

    struct flow_key flow13 = {
        .protocol = 100, .src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 2};
    /* look up element that does not exist */
    uint64_t *map_val = test_map_cuckoo_lookup(map, &flow13);
    if (map_val == NULL) {
        return true;
    }
    return false;
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
    case 5:
        ret = test_case5(map);
        break;
    case 6:
        ret = test_case6(map);
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