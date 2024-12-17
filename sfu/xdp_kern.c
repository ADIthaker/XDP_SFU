/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "parsing_helpers.h"
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_endian.h>

#define MAX_UDP_SIZE 1480
#define RTP_VERSION 2
#define RTP_MIN_HEADER_SIZE 12
/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */

// v1
// List of all IPs
#define TARGET_COUNT 5
__u32 target_ips[TARGET_COUNT] = {
    htonl(0x7F000001),
    htonl(0x7F000001),
    htonl(0x7F000001),
    htonl(0x7F000001),
    htonl(0x7F000001), 
};
__u32 target_ports[TARGET_COUNT] = {
    htonl(0x7D0),
    htonl(0x7D1),
    htonl(0x7D2),
    htonl(0x7D3),
    htonl(0x7D4),
};

 
//v2
//List of SSRCs
// List of all IP Packets
SEC("xdp")

int xdp_sfu(struct xdp_md * ctx) 
{
	void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int eth_type, ip_type, udp_payload_len;
	struct hdr_cursor nh;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct bpf_fib_lookup fib_params = {};
	int rc;
	__u32 *udp_payload;
    __be32 orig_saddr, orig_daddr;
	__be16 orig_udphdr_len;
    int action;
    nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_DROP;
		goto out;
	}
	if (eth_type != bpf_htons(ETH_P_IP))
		goto out;

	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type < 0) {
		action = XDP_DROP;
		goto out;
	}
	if (ip_type != IPPROTO_UDP)
		goto out;

	udp_payload_len = parse_udphdr(&nh, data_end, &udphdr);
	if (udp_payload_len < 0) {
		action = XDP_DROP;
		goto out;
	} else if (udp_payload_len > MAX_UDP_SIZE) {
		goto out;
	}
	orig_udphdr_len = udphdr->len;

    // Ensure UDP payload has enough space for RTP header
    if ((void *)udphdr + sizeof(*udphdr) + RTP_MIN_HEADER_SIZE > data_end)
    {
        action = XDP_PASS;
        goto out;
    }

    // Access the RTP header
    unsigned char *rtp_header = (unsigned char *)(udphdr + 1);

    // Check the RTP version (first two bits)
    if ((rtp_header[0] >> 6) != RTP_VERSION)
        return XDP_PASS;

	


}

// SEC("xdp")
// int xdp_sfu(struct xdp_md *ctx)
// {
// 	void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;
//     struct ethhdr *eth = data;
//     int eth_type, ip_type, udp_payload_len;
// 	struct hdr_cursor nh;
// 	struct iphdr *iphdr;
// 	struct udphdr *udphdr;
// 	struct bpf_fib_lookup fib_params = {};
// 	int rc;
// 	__u32 *udp_payload;
//     __be32 orig_saddr, orig_daddr;
// 	__be16 orig_udphdr_len;
//     int action;
//     nh.pos = data;

// 	eth_type = parse_ethhdr(&nh, data_end, &eth);
// 	if (eth_type < 0) {
// 		action = XDP_DROP;
// 		goto out;
// 	}
// 	if (eth_type != bpf_htons(ETH_P_IP))
// 		goto out;

// 	ip_type = parse_iphdr(&nh, data_end, &iphdr);
// 	if (ip_type < 0) {
// 		action = XDP_DROP;
// 		goto out;
// 	}
// 	if (ip_type != IPPROTO_UDP)
// 		goto out;

// 	udp_payload_len = parse_udphdr(&nh, data_end, &udphdr);
// 	if (udp_payload_len < 0) {
// 		action = XDP_DROP;
// 		goto out;
// 	} else if (udp_payload_len > MAX_UDP_SIZE) {
// 		goto out;
// 	}
// 	orig_udphdr_len = udphdr->len;

//     // Ensure UDP payload has enough space for RTP header
//     if ((void *)udphdr + sizeof(*udphdr) + RTP_MIN_HEADER_SIZE > data_end)
//     {
//         action = XDP_PASS;
//         goto out;
//     }

//     // Access the RTP header
//     unsigned char *rtp_header = (unsigned char *)(udphdr + 1);

//     // Check the RTP version (first two bits)
//     if ((rtp_header[0] >> 6) != RTP_VERSION)
//         return XDP_PASS;

//     // Optionally, check payload type (PT) or other fields
//     // Example: unsigned char payload_type = rtp_header[1] & 0x7F;

// 	 #pragma unroll
//     for (int i = 0; i < TARGET_COUNT; i++) {

// 		if(i >= sizeof(target_ips)/sizeof(target_ips[0])) 
// 			break;

//         struct ethhdr new_eth = *eth;
//         struct iphdr new_iph = *iphdr;
//         struct udphdr new_udph = *udphdr;

//         // Update IP header
//         new_iph.daddr = target_ips[i];
//         new_iph.check = 0; // Reset checksum
//         new_iph.check = bpf_csum_diff(0, 0, (__be32 *)&new_iph, sizeof(new_iph), 0);

//         // Update Ethernet header (modify MACs as needed)
//         // Assuming target MACs are resolved externally
// 		fib_params.family = AF_INET;
// 		fib_params.tos = iphdr->tos;
// 		fib_params.l4_protocol = iphdr->protocol;
// 		fib_params.sport = 0;
// 		fib_params.dport = 0;
// 		fib_params.tot_len = bpf_ntohs(iphdr->tot_len);
// 		fib_params.ipv4_src = iphdr->saddr;
// 		fib_params.ipv4_dst = iphdr->daddr;

// 		fib_params.ifindex = ctx->ingress_ifindex;

// 		rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
// 		switch (rc) {
// 			case BPF_FIB_LKUP_RET_SUCCESS: // lookup successful
// 				// set eth addrs
// 				memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
// 				memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

// 				// update IP source address with the interface's address
// 				orig_saddr = iphdr->saddr;
// 				__be32 *new_saddr;
// 				new_saddr = target_ips[i]; // get the IP for this
// 				if (!new_saddr) {
// 					action = XDP_DROP;
// 					goto out;
// 				}
// 				iphdr->saddr = *new_saddr;

// 				// update ip and udp checksums
// 				iphdr->check = update_udp_checksum(iphdr->check, orig_saddr, iphdr->saddr);
// 				udphdr->check = update_udp_checksum(udphdr->check, orig_saddr, iphdr->saddr);

// 				// redirect packet
// 				action = bpf_clone_redirect(fib_params.ifindex, 0);
// 				break;

// 			case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
// 			case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
// 			case BPF_FIB_LKUP_RET_PROHIBIT:	   /* dest not allowed; can be dropped */
// 				action = XDP_DROP;
// 				break;

// 			case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
// 			case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
// 			case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
// 			case BPF_FIB_LKUP_RET_NO_NEIGH:	    /* no neighbor entry for nh */
// 			case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
// 				break;
// 		}
//         // // Copy new headers into packet
//         // if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct ethhdr)) < 0)
//         //     return XDP_DROP;

//         // data = (void *)(long)ctx->data;
//         // data_end = (void *)(long)ctx->data_end;

//         // // Ensure new packet fits within bounds
//         // if (data + sizeof(new_eth) + sizeof(new_iph) + sizeof(new_udph) > data_end)
//         //     return XDP_DROP;

//         // // Write headers
//         // __builtin_memcpy(data, &new_eth, sizeof(new_eth));
//         // __builtin_memcpy(data + sizeof(new_eth), &new_iph, sizeof(new_iph));
//         // __builtin_memcpy(data + sizeof(new_eth) + sizeof(new_iph), &new_udph, sizeof(new_udph));

//         // Redirect packet to the original interface (or use a specific ifindex for egress)
//         // bpf_redirect(ctx->ingress_ifindex, 0);
//     }

// out:
//     return action;
// }

char _license[] SEC("license") = "GPL";

