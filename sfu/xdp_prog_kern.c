#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_endian.h>

#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#include "../common/rewrite_helpers.h"
#include "../common/parsing_helpers.h"
// #include "utils.h"


#define MAX_PACKET_SIZE 1000
#define MAX_UDP_SIZE 1480
#define RTP_VERSION 2
#define RTP_MIN_HEADER_SIZE 12

struct my_value {
    __be32 participant_ip;
 	__be16 participant_port;
};


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct my_value); 
	__uint(max_entries, 3);
} xdp_ip_map SEC(".maps");


static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}
static __always_inline void ipv4_csum(void *data_start, int data_size,
								__u64 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}


/* from AirVantage/sbulb/sbulb/bpf/checksum.c */
// Update checksum following RFC 1624 (Eqn. 3):
// https://tools.ietf.org/html/rfc1624
//     HC' = ~(~HC + ~m + m')
// Where :
//   HC	 - old checksum in header
//   HC' - new checksum in header
//   m	 - old value
//   m'	 - new value

static __always_inline void update_csum(__u64 *csum, __be32 old_addr,
								  __be32 new_addr)
{
	// ~HC
	*csum = ~*csum;
	*csum = *csum & 0xffff;
	// + ~m
	__u32 tmp;
	tmp = ~old_addr;
	*csum += tmp;
	// + m
	*csum += new_addr;
	// then fold and complement result !
	*csum = csum_fold_helper(*csum);
}

/* from AirVantage/sbulb/sbulb/bpf/ipv4.c */
static __always_inline int update_udp_checksum(__u64 cs, int old_addr,
									 int new_addr)
{
	update_csum(&cs, old_addr, new_addr);
	return cs;
}


SEC("xdp")
int xdp_store_packet(struct xdp_md *ctx) {
    // Get packet data pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse and verify packet
    
	struct ethhdr *eth = data;
    int eth_type;
	struct hdr_cursor nh;
	struct iphdr *iphdr;
    int ip_type, i= 0;
	struct udphdr *udphdr;
    int udp_payload_len;
	struct bpf_fib_lookup fib_params = {0};
	int rc;
	//__u32 *udp_payload;
    __be32 orig_saddr, orig_daddr;
    int action = XDP_PASS;
    nh.pos = data;	

	// Add one client to map
	__be16 p_port = bpf_htons(2001);
	__be32 p_ip = bpf_htonl(0x7F000001);

    struct my_value ips = { .participant_ip = p_ip,  .participant_port = p_port};
    struct my_value *ip_pointer = &ips;
    int res = bpf_map_update_elem(&xdp_ip_map, &i, &ip_pointer, 0);
	bpf_printk("THE UPDATE RES IS %d, %d, %d", res, p_port, p_ip);

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_DROP;
		goto out;
	}

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
    }

	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type < 0) {
		action = XDP_DROP;
		goto out;
	}
	if (ip_type != IPPROTO_UDP) {
        goto out;
    }

	udp_payload_len = parse_udphdr(&nh, data_end, &udphdr);
	if (udp_payload_len < 0) {
		action = XDP_DROP;
		goto out;
	} else if (udp_payload_len > MAX_UDP_SIZE) {
		goto out;
	}


    // Ensure UDP payload has enough space for RTP header
    if ((void *)udphdr + sizeof(*udphdr) + RTP_MIN_HEADER_SIZE > data_end)
    {
        goto out;
    }

    // // Access the RTP header
    unsigned char *rtp_header = (unsigned char *)(udphdr + 1);

    // Check the RTP version (first two bits)
    if ((rtp_header[0] >> 6) != RTP_VERSION)
	{
        goto out;
	}


    // Edit packet 
    // Change IP
    orig_saddr = iphdr->saddr;
	orig_daddr = iphdr->daddr;
    struct my_value *client = (struct my_value *)bpf_map_lookup_elem(&xdp_ip_map, &i);
	if (!client)
		return XDP_ABORTED;
	bpf_printk("The client I got is %pI4:%d", client->participant_ip, bpf_ntohs(client->participant_port));

    iphdr->saddr = iphdr->daddr;
	iphdr->daddr = client->participant_ip;
	iphdr->check = 0;
	__u64 ip_csum = 0;
	ipv4_csum(iphdr, sizeof(*iphdr), &ip_csum);
	iphdr->check = ip_csum;
	
    // // // Change Port
    __be16 orig_sport = udphdr->source; 
    __be16 orig_dport = udphdr->dest;

    // // // set source to this destination
    udphdr->source = udphdr->dest;
	udphdr->dest = client->participant_port;

    // // // Update UDP Header
    udphdr->check = update_udp_checksum(udphdr->check, orig_sport, udphdr->source);
	udphdr->check = update_udp_checksum(udphdr->check, orig_dport, udphdr->dest);

	udphdr->check = update_udp_checksum(udphdr->check, orig_saddr, iphdr->saddr);
	udphdr->check = update_udp_checksum(udphdr->check, orig_daddr, iphdr->daddr);
    
    // // Change MAC

    fib_params.family = AF_INET;
	fib_params.tos = iphdr->tos;
	fib_params.l4_protocol = iphdr->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(iphdr->tot_len);
	fib_params.ipv4_src = iphdr->saddr;
	fib_params.ipv4_dst = iphdr->daddr;

	fib_params.ifindex = ctx->ingress_ifindex;
	
    // Redirect packet
	bpf_printk("Packet is RTP and now redirecting...");
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

	// const char lookup[] = "The result of the lookup is: %d\n"; 
	// bpf_trace_printk(lookup, sizeof(lookup), rc);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
		// set eth addrs
		bpf_printk("The lookup was successful");

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

		// redirect packet
		action = bpf_redirect(fib_params.ifindex, 0);
		break;

	case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:	   /* dest not allowed; can be dropped */
		bpf_printk("The lookup was failed, DROPPING");

		action = XDP_DROP;
		break;

	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
		bpf_printk("The lookup was BPF_FIB_LKUP_RET_NOT_FWDED, PASSING");
		break;

	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
		bpf_printk("The lookup was BPF_FIB_LKUP_RET_FWD_DISABLED, PASSING");
		break;

	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
		bpf_printk("The lookup was BPF_FIB_LKUP_RET_UNSUPP_LWT, PASSING");
		break;

	case BPF_FIB_LKUP_RET_NO_NEIGH:	    /* no neighbor entry for nh */
		bpf_printk("The lookup was BPF_FIB_LKUP_RET_NO_NEIGH, PASSING");
		break;

	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		bpf_printk("The lookup was BPF_FIB_LKUP_RET_FRAG_NEEDED, PASSING");

		break;
	}

out:
    return xdp_stats_record_action(ctx, action);

}
char _license[] SEC("license") = "GPL";


