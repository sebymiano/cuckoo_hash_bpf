/*
 * Copyright 2022 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CUCKOO_TEST_CFG_H_
#define CUCKOO_TEST_CFG_H_

#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>

const volatile struct {
    __u32 test_case;
} cuckoo_test_cfg = {};

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

static struct flow_key keys[] = {
    {.src_ip = 0x10101010, .dst_ip = 0x10101011, .src_port = 1, .dst_port = 2, .protocol = 17},
    {.src_ip = 0x10101010, .dst_ip = 0x10101013, .src_port = 2, .dst_port = 1, .protocol = 17},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 10, .protocol = 30},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 22, .protocol = 30},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 15, .dst_port = 10, .protocol = 50},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 20, .protocol = 70},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 10, .dst_port = 7, .protocol = 50},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 2, .dst_port = 3, .protocol = 100},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 1, .dst_port = 1, .protocol = 1},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 3, .dst_port = 3, .protocol = 30},
    {.src_ip = 0x10101010, .dst_ip = 0x10101014, .src_port = 4, .dst_port = 5, .protocol = 30}};

#endif // CUCKOO_TEST_CFG_H_