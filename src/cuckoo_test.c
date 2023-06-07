/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com> */
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

#include "cuckoo_test.skel.h"
#include "ebpf/cuckoo_test_cfg.h"

#define IFINDEX_LO 1
#define MAGIC_BYTES 123

#define TEST_LOOKUP 1
#define TEST_INSERTION 2
#define TEST_INSERT_AND_LOOKUP 3
#define TEST_INSERT_DELETE_LOOKUP 4
#define TEST_MULTIPLE_INSERT 5
#define TEST_LOOKUP_AFTER_INSERT 6

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

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
//     return vfprintf(stderr, format, args);
// }

void sigint_handler(int sig_no) {
    // log_debug("Closing program...");
    // cleanup_ifaces();
    exit(0);
}

int load_and_run_program(unsigned int test_case) {
    char buf[256] = {};
    struct cuckoo_test_bpf *skel;
    int err;
    /* Open and load BPF application */
    skel = cuckoo_test_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        cuckoo_test_bpf__destroy(skel);
        return -1;
    }

    skel->rodata->cuckoo_test_cfg.test_case = test_case;

    err = cuckoo_test_bpf__load(skel);
    if (err) {
        printf("Failed to load program\n");
        cuckoo_test_bpf__destroy(skel);
        return -1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_cuckoo_test_prog);

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
        cuckoo_test_bpf__destroy(skel);
        return -1;
    }

    // printf("Return value from program is: %d\n", topts.retval);

    /* Clean up */
    cuckoo_test_bpf__destroy(skel);
    return topts.retval;
}

TEST test1_check_lookup(void) {
    int retval_expect = XDP_PASS;
    int ret = load_and_run_program(TEST_LOOKUP);

    // Assert that EXPECTED >= ACTUAL
    ASSERT_GTEm("Failed to load and run BPF program", ret, 0);

    ASSERT_EQ_FMT(retval_expect, ret, "%d");

    PASSm("Test on checking lookups passed");
}

TEST test2_insertion(void) {
    int retval_expect = XDP_PASS;
    int ret = load_and_run_program(TEST_INSERTION);

    // Assert that EXPECTED >= ACTUAL
    ASSERT_GTEm("Failed to load and run BPF program", ret, 0);

    ASSERT_EQ_FMT(retval_expect, ret, "%d");

    PASSm("Test on checking lookups passed");
}

TEST test3_insert_and_lookup(void) {
    int retval_expect = XDP_PASS;
    int ret = load_and_run_program(TEST_INSERT_AND_LOOKUP);

    // Assert that EXPECTED >= ACTUAL
    ASSERT_GTEm("Failed to load and run BPF program", ret, 0);

    ASSERT_EQ_FMT(retval_expect, ret, "%d");

    PASSm("Test on checking lookups passed");
}

TEST test4_insert_delete_lookup(void) {
    int retval_expect = XDP_PASS;
    int ret = load_and_run_program(TEST_INSERT_DELETE_LOOKUP);

    // Assert that EXPECTED >= ACTUAL
    ASSERT_GTEm("Failed to load and run BPF program", ret, 0);

    ASSERT_EQ_FMT(retval_expect, ret, "%d");

    PASSm("Test on checking lookups passed");
}

TEST test5_multiple_insert(void) {
    int retval_expect = XDP_PASS;
    int ret = load_and_run_program(TEST_MULTIPLE_INSERT);

    // Assert that EXPECTED >= ACTUAL
    ASSERT_GTEm("Failed to load and run BPF program", ret, 0);

    ASSERT_EQ_FMT(retval_expect, ret, "%d");

    PASSm("Test on checking lookups passed");
}

TEST test6_lookup_after_insert(void) {
    int retval_expect = XDP_PASS;
    int ret = load_and_run_program(TEST_LOOKUP_AFTER_INSERT);

    // Assert that EXPECTED >= ACTUAL
    ASSERT_GTEm("Failed to load and run BPF program", ret, 0);

    ASSERT_EQ_FMT(retval_expect, ret, "%d");

    PASSm("Test on checking lookups passed");
}

/* Add definitions that need to be in the test runner's main file. */
GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN(); /* command-line options, initialization. */

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // libbpf_set_print(libbpf_print_fn);

    /* Individual tests can be run directly in main, outside of suites. */
    RUN_TEST(test1_check_lookup);
    RUN_TEST(test2_insertion);
    RUN_TEST(test3_insert_and_lookup);
    RUN_TEST(test4_insert_delete_lookup);
    RUN_TEST(test5_multiple_insert);
    RUN_TEST(test6_lookup_after_insert);

    printf("Program stopped correctly\n");
    GREATEST_MAIN_END(); /* display results */
}
