#ifndef REX_ABI_USER_H
#define REX_ABI_USER_H

#if !defined(__bpf__)
#include <linux/types.h>
#include <linux/bpf.h>
#define __ksym
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure describing a match event.
 */
struct rex_event {
	unsigned int expression;
	unsigned long long from;
	unsigned long long to;
	unsigned long long flags;
};

/* handler_flags */
enum {
	REX_SINGLE_SHOT = 1 << 0,
};

/**
 * Attributes for bpf_scan_bytes() and bpf_xdp_scan_bytes().
 *
 * @database_id:	Numeric database handle taken from configfs (in).
 * @handler_flags:	Customize match handler behaviour (in).
 * @event_count:	Output number of events (inout).
 * @last_event:		Space to store match details. (out).
 */
struct rex_scan_attr {
	__u32 database_id;
	__u32 handler_flags;
	__u32 nr_events;
	struct rex_event last_event;
};

/**
 * 5-tuple key used to identify a TCP flow for bpf_xdp_stream_scan_bytes().
 * Must be exactly 16 bytes (4 x u32) for jhash2 in the kernel module.
 */
struct rex_flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   proto;
	__u8   close_flag;  /* 1 = FIN/RST: close and free this stream */
	__u8   _pad[2];
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // REX_ABI_USER_H
