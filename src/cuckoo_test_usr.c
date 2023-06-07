/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

#include <greatest.h>
#include <net/if.h>

#include "cuckoo_test_usr.skel.h"
#include "ebpf/cuckoo_test_usr_cfg.h"

#include <cuckoo_usr.h>

#define IFINDEX_LO 1
#define MAGIC_BYTES 123

#define TEST_USR_INSERT_BPF_LOOKUP 1
#define TEST_HALF_USR_INSERT_BPF_LOOKUP 2
#define TEST_BPF_INSERT_USR_LOOKUP 3
#define TEST_USR_DELETE_BPF_LOOKUP 4

struct ipv4_packet {
    struct ethhdr eth;
    struct iphdr iph;
    struct tcphdr tcp;
} __packed;

struct ipv4_packet pkt_v4 = {
    .eth.h_proto = __bpf_constant_htons(ETH_P_IP),
    .iph.ihl = 5,
    .iph.protocol = IPPROTO_TCP,
    .iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
    .tcp.urg_ptr = 123,
    .tcp.doff = 5,
};

void sigint_handler(int sig_no) {
    exit(0);
}

TEST test1_check_usr_insertion_bpf_lookup(void) {
    char buf[256] = {};
    struct cuckoo_test_usr_bpf *skel;
    int err;
    unsigned int array_len = sizeof(keys) / sizeof(keys[0]);

    /* Open and load BPF application */
    skel = cuckoo_test_usr_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to open BPF skeleton");
    }

    skel->rodata->cuckoo_test_cfg.test_case = (unsigned int)TEST_USR_INSERT_BPF_LOOKUP;

    err = cuckoo_test_usr_bpf__load(skel);
    if (err) {
        printf("Failed to load program\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to load program");
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_cuckoo_test_prog);
    int map_fd = bpf_map__fd(skel->maps.test_map);

    cuckoo_error_t err_map;
    /* Init userspace cuckoo hashmap */
    cuckoo_hashmap_t *cuckoo_map = cuckoo_table_init_by_fd(map_fd, sizeof(struct flow_key),
                                                           sizeof(__u32), 512, false, &err_map);

    if (cuckoo_map == NULL) {
        printf("%s\n", err_map.error_msg);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to init cuckoo map");
    }

    memset(&err_map, 0, sizeof(err_map));
    for (int i = 0; i < array_len; i++) {
        struct flow_key key = keys[i];
        __u32 value = keys[i].protocol;

        if (cuckoo_insert(cuckoo_map, &key, &value, sizeof(key), sizeof(value), &err_map) != 0) {
            printf("Failed to insert key %d in map\n", i);
            printf("%s\n", err_map.error_msg);
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            FAILm("Failed to insert key in map");
        }
    }

    struct xdp_md ctx_in = {
        .data = sizeof(__u32),
        .data_end = sizeof(pkt_v4) + sizeof(__u32),
        .ingress_ifindex = IFINDEX_LO,
    };

    LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = &pkt_v4,
                .data_size_in = sizeof(pkt_v4) + sizeof(__u32), .data_out = buf,
                .data_size_out = sizeof(buf) + sizeof(__u32), .ctx_in = &ctx_in,
                .ctx_size_in = sizeof(ctx_in));

    err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        printf("Error running the BPF program: %d\n", err);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Error running the BPF program");
    }

    // printf("Return value from program is: %d\n", topts.retval);

    /* Clean up */
    cuckoo_table_destroy(cuckoo_map);
    cuckoo_test_usr_bpf__destroy(skel);

    int retval_expect = XDP_PASS;
    ASSERT_EQ_FMT(retval_expect, topts.retval, "%d");

    PASSm("Test on checking usr insertion and BPF lookup passed");
}

TEST test2_check_half_usr_insertion_bpf_lookup(void) {
    char buf[256] = {};
    struct cuckoo_test_usr_bpf *skel;
    int err;
    unsigned int array_len = sizeof(keys) / sizeof(keys[0]);

    /* Open and load BPF application */
    skel = cuckoo_test_usr_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to open BPF skeleton");
    }

    skel->rodata->cuckoo_test_cfg.test_case = (unsigned int)TEST_HALF_USR_INSERT_BPF_LOOKUP;

    err = cuckoo_test_usr_bpf__load(skel);
    if (err) {
        printf("Failed to load program\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to load program");
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_cuckoo_test_prog);
    int map_fd = bpf_map__fd(skel->maps.test_map);

    cuckoo_error_t err_map;
    /* Init userspace cuckoo hashmap */
    cuckoo_hashmap_t *cuckoo_map = cuckoo_table_init_by_fd(map_fd, sizeof(struct flow_key),
                                                           sizeof(__u32), 512, false, &err_map);

    if (cuckoo_map == NULL) {
        printf("%s\n", err_map.error_msg);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to init cuckoo map");
    }

    memset(&err_map, 0, sizeof(err_map));
    for (int i = 0; i < array_len / 2; i++) {
        struct flow_key key = keys[i];
        __u32 value = keys[i].protocol;

        if (cuckoo_insert(cuckoo_map, &key, &value, sizeof(key), sizeof(value), &err_map) != 0) {
            printf("Failed to insert key %d in map\n", i);
            printf("%s\n", err_map.error_msg);
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            FAILm("Failed to insert key in map");
        }
    }

    struct xdp_md ctx_in = {
        .data = sizeof(__u32),
        .data_end = sizeof(pkt_v4) + sizeof(__u32),
        .ingress_ifindex = IFINDEX_LO,
    };

    LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = &pkt_v4,
                .data_size_in = sizeof(pkt_v4) + sizeof(__u32), .data_out = buf,
                .data_size_out = sizeof(buf) + sizeof(__u32), .ctx_in = &ctx_in,
                .ctx_size_in = sizeof(ctx_in));

    err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        printf("Error running the BPF program: %d\n", err);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Error running the BPF program");
    }

    /* Clean up */
    cuckoo_table_destroy(cuckoo_map);
    cuckoo_test_usr_bpf__destroy(skel);

    int retval_expect = XDP_PASS;
    ASSERT_EQ_FMT(retval_expect, topts.retval, "%d");

    PASSm("Test on checking half entries inserted by usr and half by BPF passed");
}

TEST test3_check_bpf_insert_usr_lookup(void) {
    char buf[256] = {};
    struct cuckoo_test_usr_bpf *skel;
    int err;
    unsigned int array_len = sizeof(keys) / sizeof(keys[0]);

    /* Open and load BPF application */
    skel = cuckoo_test_usr_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to open BPF skeleton");
    }

    skel->rodata->cuckoo_test_cfg.test_case = (unsigned int)TEST_BPF_INSERT_USR_LOOKUP;

    err = cuckoo_test_usr_bpf__load(skel);
    if (err) {
        printf("Failed to load program\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to load program");
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_cuckoo_test_prog);
    int map_fd = bpf_map__fd(skel->maps.test_map);

    cuckoo_error_t err_map;
    /* Init userspace cuckoo hashmap */
    cuckoo_hashmap_t *cuckoo_map = cuckoo_table_init_by_fd(map_fd, sizeof(struct flow_key),
                                                           sizeof(__u32), 512, false, &err_map);

    if (cuckoo_map == NULL) {
        printf("%s\n", err_map.error_msg);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to init cuckoo map");
    }

    struct xdp_md ctx_in = {
        .data = sizeof(__u32),
        .data_end = sizeof(pkt_v4) + sizeof(__u32),
        .ingress_ifindex = IFINDEX_LO,
    };

    LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = &pkt_v4,
                .data_size_in = sizeof(pkt_v4) + sizeof(__u32), .data_out = buf,
                .data_size_out = sizeof(buf) + sizeof(__u32), .ctx_in = &ctx_in,
                .ctx_size_in = sizeof(ctx_in));

    err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        printf("Error running the BPF program: %d\n", err);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Error running the BPF program");
    }

    int retval_expect = XDP_PASS;
    ASSERT_EQ_FMT(retval_expect, topts.retval, "%d");

    memset(&err_map, 0, sizeof(err_map));
    for (int i = 0; i < array_len; i++) {
        struct flow_key key = keys[i];
        size_t values_size = sizeof(__u32) * cuckoo_map->num_cpus;
        size_t results_size = sizeof(bool) * cuckoo_map->num_cpus;

        uint32_t *values = (uint32_t *)malloc(values_size);
        bool *results = (bool *)malloc(results_size);

        if (values == NULL || results == NULL) {
            printf("Failed to allocate memory for values and results\n");
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            FAILm("Failed to allocate memory for values and results");
            return -1;
        }

        memset(values, 0, values_size);
        memset(results, 0, results_size);

        if (cuckoo_lookup(cuckoo_map, &key, sizeof(key), (void *)values, values_size,
                          (void *)results, results_size, &err_map) != 0) {
            printf("Failed to lookup key %d in map\n", i);
            printf("%s\n", err_map.error_msg);
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            free(values);
            free(results);
            FAILm("Failed to lookup key in map");
            return -1;
        }

        for (int j = 0; j < cuckoo_map->num_cpus; j++) {
            if (results[j] == true) {
                if (values[j] != keys[i].protocol) {
                    printf("Value %d does not match expected value %d\n", values[j],
                           keys[i].protocol);
                    cuckoo_table_destroy(cuckoo_map);
                    cuckoo_test_usr_bpf__destroy(skel);
                    free(values);
                    free(results);
                    FAILm("Value does not match expected value");
                }
                break;
            }
        }
        free(values);
        free(results);
    }

    /* Clean up */
    cuckoo_table_destroy(cuckoo_map);
    cuckoo_test_usr_bpf__destroy(skel);

    PASSm("Test on checking BPF table insertion and userspace lookup passed");
}

TEST test4_check_usr_insert_usr_delete_bpf_lookup(void) {
    char buf[256] = {};
    struct cuckoo_test_usr_bpf *skel;
    int err;
    unsigned int array_len = sizeof(keys) / sizeof(keys[0]);

    /* Open and load BPF application */
    skel = cuckoo_test_usr_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to open BPF skeleton");
    }

    skel->rodata->cuckoo_test_cfg.test_case = (unsigned int)TEST_USR_DELETE_BPF_LOOKUP;

    err = cuckoo_test_usr_bpf__load(skel);
    if (err) {
        printf("Failed to load program\n");
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to load program");
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_cuckoo_test_prog);
    int map_fd = bpf_map__fd(skel->maps.test_map);

    cuckoo_error_t err_map;
    /* Init userspace cuckoo hashmap */
    cuckoo_hashmap_t *cuckoo_map = cuckoo_table_init_by_fd(map_fd, sizeof(struct flow_key),
                                                           sizeof(__u32), 512, false, &err_map);

    if (cuckoo_map == NULL) {
        printf("%s\n", err_map.error_msg);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Failed to init cuckoo map");
    }

    memset(&err_map, 0, sizeof(err_map));
    for (int i = 0; i < array_len; i++) {
        struct flow_key key = keys[i];
        __u32 value = keys[i].protocol;

        if (cuckoo_insert(cuckoo_map, &key, &value, sizeof(key), sizeof(value), &err_map) != 0) {
            printf("Failed to insert key %d in map\n", i);
            printf("%s\n", err_map.error_msg);
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            FAILm("Failed to insert key in map");
        }
    }

    /* After the insertion, I check if the values are in the map */
    memset(&err_map, 0, sizeof(err_map));
    for (int i = 0; i < array_len; i++) {
        struct flow_key key = keys[i];
        size_t values_size = sizeof(__u32) * cuckoo_map->num_cpus;
        size_t results_size = sizeof(bool) * cuckoo_map->num_cpus;

        uint32_t *values = (uint32_t *)malloc(values_size);
        bool *results = (bool *)malloc(results_size);

        if (values == NULL || results == NULL) {
            printf("Failed to allocate memory for values and results\n");
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            FAILm("Failed to allocate memory for values and results");
            return -1;
        }

        memset(values, 0, values_size);
        memset(results, 0, results_size);

        if (cuckoo_lookup(cuckoo_map, &key, sizeof(key), (void *)values, values_size,
                          (void *)results, results_size, &err_map) != 0) {
            printf("Failed to lookup key %d in map\n", i);
            printf("%s\n", err_map.error_msg);
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            free(values);
            free(results);
            FAILm("Failed to lookup key in map");
            return -1;
        }

        for (int j = 0; j < cuckoo_map->num_cpus; j++) {
            if (results[j] == true) {
                if (values[j] != keys[i].protocol) {
                    printf("Value %d does not match expected value %d\n", values[j],
                           keys[i].protocol);
                    cuckoo_table_destroy(cuckoo_map);
                    cuckoo_test_usr_bpf__destroy(skel);
                    free(values);
                    free(results);
                    FAILm("Value does not match expected value");
                }
                break;
            }
        }
        free(values);
        free(results);
    }

    /* Then, I delete all the values from the map */
    memset(&err_map, 0, sizeof(err_map));
    for (int i = 0; i < array_len; i++) {
        struct flow_key key = keys[i];

        if (cuckoo_delete(cuckoo_map, &key, sizeof(key), &err_map) != 0) {
            printf("Failed to delete key %d in map\n", i);
            printf("%s\n", err_map.error_msg);
            cuckoo_table_destroy(cuckoo_map);
            cuckoo_test_usr_bpf__destroy(skel);
            FAILm("Failed to delete key in map");
        }
    }

    /* Let check if the BPF program agrees */
    struct xdp_md ctx_in = {
        .data = sizeof(__u32),
        .data_end = sizeof(pkt_v4) + sizeof(__u32),
        .ingress_ifindex = IFINDEX_LO,
    };

    LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = &pkt_v4,
                .data_size_in = sizeof(pkt_v4) + sizeof(__u32), .data_out = buf,
                .data_size_out = sizeof(buf) + sizeof(__u32), .ctx_in = &ctx_in,
                .ctx_size_in = sizeof(ctx_in));

    err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        printf("Error running the BPF program: %d\n", err);
        cuckoo_test_usr_bpf__destroy(skel);
        FAILm("Error running the BPF program");
    }

    int retval_expect = XDP_PASS;
    ASSERT_EQ_FMT(retval_expect, topts.retval, "%d");

    /* Clean up */
    cuckoo_table_destroy(cuckoo_map);
    cuckoo_test_usr_bpf__destroy(skel);

    PASSm("Test on checking userspace insert + userspace delete + BPF lookup passed");
}

/* Add definitions that need to be in the test runner's main file. */
GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN(); /* command-line options, initialization. */

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // libbpf_set_print(libbpf_print_fn);

    /* Individual tests can be run directly in main, outside of suites. */
    RUN_TEST(test1_check_usr_insertion_bpf_lookup);
    RUN_TEST(test2_check_half_usr_insertion_bpf_lookup);
    RUN_TEST(test3_check_bpf_insert_usr_lookup);
    RUN_TEST(test4_check_usr_insert_usr_delete_bpf_lookup);

    printf("Program stopped correctly\n");
    GREATEST_MAIN_END(); /* display results */
}
