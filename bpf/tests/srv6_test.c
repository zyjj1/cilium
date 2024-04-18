// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_SRV6
#define ENABLE_IPV6

#include <bpf/ctx/xdp.h>
#include <node_config.h>
#include "common.h"
#include "pktgen.h"
#include "lib/common.h"
#include "lib/drop.h"
#include "lib/trace.h"
#define ROUTER_IP
#include "config_replacement.h"
#undef ROUTER_IP
#include "lib/srv6.h"


PKTGEN("xdp", "srv6_encapsulation")
int srv6_encapsulation_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_node_one, (__u8 *)v6_node_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "srv6_encapsulation")
int srv6_encapsulation_setup(__maybe_unused struct __ctx_buff *ctx)
{
	return 123;
}

CHECK("xdp", "srv6_encapsulation")
int srv6_encapsulation_check(__maybe_unused struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	__u32 *status_code;
	__u8 nexthdr;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == 123);

	xdp_adjust_head(ctx, 4);


	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		test_fatal("l2 out of bounds");

	assert(l2->h_proto == __bpf_htons(ETH_P_IPV6));

	l3 = (void *)l2 + ETH_HLEN;
	if ((void *)(l3 + 1) > data_end)
		test_fatal("l3 out of bounds");

	nexthdr = l3->nexthdr;
	assert(ipv6_hdrlen(ctx, &nexthdr) > 0);
	assert(nexthdr == IPPROTO_TCP);


	// union v6addr saddr = {};
	// struct in6_addr sid = {};
	// int growth = sizeof(struct ipv6hdr);
	// __u16 new_payload_len = bpf_ntohs(l3->payload_len) + sizeof(struct ipv6hdr);
	// __u8 nexthdr2 = IPPROTO_IPV6;
	// int status = srv6_encapsulation(ctx, growth, new_payload_len, nexthdr2, &saddr, &sid);
	// assert(status == 0);


	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
