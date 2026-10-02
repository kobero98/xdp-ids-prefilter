/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <pcap.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

static volatile bool force_quit;

static int promiscuous_on = 1;

#define RTE_LOGTYPE_PCAP_REPLAY RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 64
#define BURST_TX_DRAIN_US 100
#define MEMPOOL_CACHE_SIZE 256
#define MAX_CORES 16

#define MIN_PKT_LEN 64
#define MAX_PKT_LEN 1514

#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 2048
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static struct rte_eth_dev_tx_buffer *tx_buffer[MAX_CORES];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *rx_pktmbuf_pool[MAX_CORES];
struct rte_mempool *pcap_pool[MAX_CORES];

struct lcore_queue_conf {
	unsigned qid;
	unsigned port_id;
	struct rte_mempool *tx_pool;
};
static struct lcore_queue_conf lcore_queue_conf[MAX_CORES];

static pcap_t *pcap_handle;

/* Per-core statistics */
struct core_statistics {
	uint64_t tx_pkts;
	uint64_t tx_bytes;
	uint64_t dropped;
} __rte_cache_aligned;
static struct core_statistics core_stats[MAX_CORES];

/* Snapshot for rate calculation */
static uint64_t prev_tx_pkts;
static uint64_t prev_tx_bytes;
static uint64_t prev_tsc_stats;

#define MAX_TIMER_PERIOD 86400
static uint64_t timer_period = 1; /* 1 second */

static bool use_single_mempool;
static bool replicate_pkt;
static bool timing_mode;		/* Replay with original timing */
static uint64_t pkt_limit;		/* 0 = unlimited */
static uint64_t global_tx_pkts;		/* shared atomic counter */
static uint64_t duration_tsc;		/* 0 = unlimited */
static unsigned int pkt_size;		/* 0 = use original size */
static uint64_t rate_mbps;		/* 0 = unlimited, target TX rate in Mbps (L1) */
static uint64_t rate_pps;		/* 0 = unlimited, target TX rate in pkts/s */

/*
 * Token bucket for rate limiting.
 * Tokens represent bytes at L1 (including 24-byte overhead) in -R mode,
 * or whole packets in -P mode.
 * Refilled at the target rate using TSC for precision.
 */
struct token_bucket {
	uint64_t tokens;	/* Current tokens (bytes or packets) */
	uint64_t last_tsc;	/* TSC at last refill */
	uint64_t rate_bps;	/* Units per TSC tick (scaled by 2^32) */
	uint64_t burst;		/* Max burst size (bytes or packets) */
} __rte_cache_aligned;

static struct token_bucket tb[MAX_CORES];

/*
 * Preloaded packets as an ordered array, swept round-robin in the TX loop.
 *
 * FIX: the old TX path used rte_mempool_get_bulk() + free-after-TX. With the
 * per-core mempool cache, get_bulk keeps returning the same cache-hot mbufs
 * (the front of the pool) and the post-TX free puts them right back — so only
 * the first ~cache_size packets of the pcap were ever transmitted, looped
 * forever. Every other preloaded packet sat untouched in the pool.
 *
 * We instead drain ALL preloaded mbufs into this array once and iterate over
 * every entry (round-robin, per-core index). Before each TX we bump the mbuf
 * refcnt so the driver's post-TX free returns it to baseline (still held by
 * the array) instead of recycling it — the whole pcap is replayed in order.
 */
static struct rte_mbuf **preload_pkts;          /* ordered array of all preloaded mbufs */
static unsigned int      preload_count;         /* number of entries */
static unsigned int      preload_idx[MAX_CORES];/* per-core sweep position */

/* Timing metadata stored in mbuf private area */
struct timing_meta {
	uint64_t timestamp_ns;  /* Nanoseconds since first packet */
};

#define MIN_BUF_LEN 60
static char pkt_rep[MIN_BUF_LEN];
static uint64_t first_pkt_ts_ns;  /* First packet timestamp for timing mode */

static uint64_t
print_stats(void)
{
	uint64_t total_pkts = 0, total_bytes = 0, total_dropped = 0;
	unsigned int lcores = rte_lcore_count();
	uint64_t cur_tsc = rte_rdtsc();
	double elapsed_s, mpps, gbps;
	uint64_t delta_pkts, delta_bytes;

	for (unsigned int i = 0; i < lcores; i++) {
		total_pkts += core_stats[i].tx_pkts;
		total_bytes += core_stats[i].tx_bytes;
		total_dropped += core_stats[i].dropped;
	}

	/* Calculate rates from deltas */
	delta_pkts = total_pkts - prev_tx_pkts;
	delta_bytes = total_bytes - prev_tx_bytes;

	if (prev_tsc_stats > 0) {
		elapsed_s = (double)(cur_tsc - prev_tsc_stats) / rte_get_tsc_hz();
	} else {
		elapsed_s = 0;
	}

	if (elapsed_s > 0) {
		mpps = (double)delta_pkts / elapsed_s / 1e6;
		/* L1 Gbps: preamble(7) + SFD(1) + CRC(4) + IFG(12) = 24 bytes/pkt */
		gbps = (double)(delta_bytes + delta_pkts * 24) * 8.0 / elapsed_s / 1e9;
	} else {
		mpps = 0;
		gbps = 0;
	}

	prev_tx_pkts = total_pkts;
	prev_tx_bytes = total_bytes;
	prev_tsc_stats = cur_tsc;

	/* Clear screen and move to top left */
	printf("\033[2J\033[1;1H");

	printf("+----------------------------------------------------------+\n");
	printf("|                  PCAP Replay Statistics                   |\n");
	printf("+----------------------------------------------------------+\n");
	printf("|  Cores active     :  %-20u               |\n", lcores);
	printf("+----------------------------------------------------------+\n");
	printf("|  TX packets       :  %-20"PRIu64"               |\n", total_pkts);
	printf("|  TX bytes         :  %-20"PRIu64"               |\n", total_bytes);
	printf("|  Dropped          :  %-20"PRIu64"               |\n", total_dropped);
	printf("+----------------------------------------------------------+\n");
	printf("|  TX rate          :  %10.3f Mpps                    |\n", mpps);
	printf("|  TX throughput    :  %10.3f Gbps                    |\n", gbps);
	printf("+----------------------------------------------------------+\n");

	fflush(stdout);
	return total_pkts;
}

/* Main processing loop */
static void
pcap_replay_main_loop(void)
{
	struct rte_mbuf *tx_bufs[MAX_PKT_BURST];
	int sent;
	unsigned lcore_id, queue_id, portid;
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	uint64_t start_tsc;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
				    US_PER_S * BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	lcore_id = rte_lcore_index(rte_lcore_id());
	qconf = &lcore_queue_conf[lcore_id];
	queue_id = qconf->qid;
	portid = qconf->port_id;
	buffer = tx_buffer[queue_id];
	start_tsc = rte_rdtsc();

	/* Init per-core token bucket (-R: unita' = byte L1; -P: unita' = pkt) */
	if (rate_mbps > 0 || rate_pps > 0) {
		uint64_t hz = rte_get_tsc_hz();
		/* Per-core rate = total rate / nb_lcores */
		uint64_t units_per_sec;
		uint64_t min_burst;

		if (rate_pps > 0) {
			units_per_sec = rate_pps / rte_lcore_count();
			min_burst = MAX_PKT_BURST;
		} else {
			uint64_t core_mbps = rate_mbps / rte_lcore_count();
			units_per_sec = core_mbps * 1000000ULL / 8;
			min_burst = (uint64_t)MAX_PKT_BURST * MAX_PKT_LEN;
		}

		/* Scale: tokens_per_tick = units_per_sec / hz, stored as fixed-point */
		tb[queue_id].rate_bps = (units_per_sec << 32) / hz;
		/* Burst = 100µs worth of data; minimum covers one full MAX_PKT_BURST */
		tb[queue_id].burst = units_per_sec / 10000;
		if (tb[queue_id].burst < min_burst)
			tb[queue_id].burst = min_burst;
		tb[queue_id].tokens = tb[queue_id].burst;
		tb[queue_id].last_tsc = start_tsc;
	}

	RTE_LOG(INFO, PCAP_REPLAY, "entering main loop on lcore %u\n", lcore_id);

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		if (unlikely(diff_tsc > drain_tsc)) {
			sent = rte_eth_tx_buffer_flush(portid, queue_id, buffer);
			if (sent)
				core_stats[queue_id].tx_pkts += sent;

			if (timer_period > 0) {
				timer_tsc += diff_tsc;
				if (unlikely(timer_tsc >= timer_period)) {
					if (lcore_id == rte_get_main_lcore())
						print_stats();
					timer_tsc = 0;
				}
			}
			prev_tsc = cur_tsc;
		}

		/* Check global packet limit */
		if (pkt_limit &&
		    unlikely(__atomic_load_n(&global_tx_pkts, __ATOMIC_RELAXED) >= pkt_limit)) {
			force_quit = true;
			break;
		}

		/* Check duration limit */
		if (duration_tsc && unlikely(cur_tsc - start_tsc >= duration_tsc)) {
			force_quit = true;
			break;
		}

		/* Send packets from pcap mempool */
		if (timing_mode) {
			/* Timing mode: send one packet at a time with precise delays.
			 * Take the next packet from the preloaded array (pcap order)
			 * and bump refcnt so the post-TX free keeps it for replay. */
			struct rte_mbuf *pkt = preload_pkts[preload_idx[lcore_id]];
			if (++preload_idx[lcore_id] >= preload_count)
				preload_idx[lcore_id] = 0;
			rte_mbuf_refcnt_update(pkt, 1);

			struct timing_meta *meta = (struct timing_meta *)rte_mbuf_to_priv(pkt);
			uint64_t target_tsc = start_tsc + (meta->timestamp_ns * rte_get_tsc_hz()) / 1000000000ULL;

			/* Busy-wait until target time */
			while (rte_rdtsc() < target_tsc && !force_quit)
				rte_pause();

			if (!force_quit) {
				sent = rte_eth_tx_burst(portid, queue_id, &pkt, 1);
				if (sent) {
					core_stats[queue_id].tx_pkts += 1;
					core_stats[queue_id].tx_bytes += pkt->pkt_len;
					__atomic_fetch_add(&global_tx_pkts, 1, __ATOMIC_RELAXED);
				} else {
					rte_pktmbuf_free(pkt);
				}
			} else {
				rte_pktmbuf_free(pkt);
			}
		} else {
			/* Fast mode: send bursts as fast as possible.
			 * Take the next MAX_PKT_BURST packets from the preloaded
			 * array (round-robin, per-core index) and bump their refcnt
			 * so the NIC's post-TX free returns them to baseline (still
			 * held by the array) rather than recycling only the cache
			 * front — this replays every packet of the pcap in order. */
			unsigned int start_idx = preload_idx[lcore_id];
			unsigned int idx = start_idx;
			for (int i = 0; i < MAX_PKT_BURST; i++) {
				struct rte_mbuf *m = preload_pkts[idx];
				rte_mbuf_refcnt_update(m, 1);
				tx_bufs[i] = m;
				if (++idx >= preload_count)
					idx = 0;
			}

			int nb_to_send = MAX_PKT_BURST;

			/* Token bucket rate limiting */
			if (rate_mbps > 0 || rate_pps > 0) {
				struct token_bucket *t = &tb[queue_id];

				/* Refill tokens based on elapsed time */
				uint64_t now = rte_rdtsc();
				uint64_t elapsed = now - t->last_tsc;
				t->tokens += (elapsed * t->rate_bps) >> 32;
				if (t->tokens > t->burst)
					t->tokens = t->burst;
				t->last_tsc = now;

				/* Count how many packets fit in available tokens */
				nb_to_send = 0;
				for (int i = 0; i < MAX_PKT_BURST; i++) {
					/* -P: 1 token/pkt; -R: byte a L1 */
					uint64_t cost = rate_pps > 0 ?
						1 : tx_bufs[i]->pkt_len + 24;
					if (t->tokens < cost)
						break;
					t->tokens -= cost;
					nb_to_send++;
				}

				/* Return mbufs not selected by rate limiter */
				for (int i = nb_to_send; i < MAX_PKT_BURST; i++)
					rte_pktmbuf_free(tx_bufs[i]);
			}

			sent = 0;
			if (nb_to_send > 0) {
				/* Save lengths before TX: driver may free mbufs immediately */
				uint32_t pkt_lens[MAX_PKT_BURST];
				for (int i = 0; i < nb_to_send; i++)
					pkt_lens[i] = tx_bufs[i]->pkt_len;

				sent = rte_eth_tx_burst(portid, queue_id, tx_bufs, nb_to_send);
				core_stats[queue_id].tx_pkts += sent;
				__atomic_fetch_add(&global_tx_pkts, sent, __ATOMIC_RELAXED);

				for (int i = 0; i < sent; i++)
					core_stats[queue_id].tx_bytes += pkt_lens[i];

				/* Free mbufs the NIC could not send (TX ring full) */
				for (int i = sent; i < nb_to_send; i++)
					rte_pktmbuf_free(tx_bufs[i]);
			}

			/* Advance only past the packets actually sent: packets
			 * rejected by the token bucket or by a full TX ring stay
			 * next in line. Skipping them biases the mix — the byte
			 * budget runs out preferentially on large packets, so at
			 * low rates the wire would carry only small packets. */
			preload_idx[lcore_id] = (start_idx + sent) % preload_count;
		}
	}
}

static int
pcap_replay_launch_one_lcore(__rte_unused void *dummy)
{
	pcap_replay_main_loop();
	return 0;
}

static uint64_t
parse_count(const char *str)
{
	char *end;
	uint64_t val = strtoull(str, &end, 10);

	switch (*end) {
	case 'G': case 'g': val *= 1000000000ULL; break;
	case 'M': case 'm': val *= 1000000ULL; break;
	case 'K': case 'k': val *= 1000ULL; break;
	case '\0': break;
	default:
		rte_exit(EXIT_FAILURE, "Invalid count suffix '%c' in '%s'\n",
			 *end, str);
	}
	return val;
}

static void
pcap_replay_usage(void)
{
	printf("[EAL options] -- -p PCAP_FILE\n"
	       "  -p PCAP_FILE: path to the pcap to replay\n"
	       "  -c COUNT: stop after sending COUNT packets total\n"
	       "            supports K/M/G suffixes (e.g. -c 10M)\n"
	       "  -d SECONDS: stop after SECONDS seconds\n"
	       "  -L SIZE: set packet size in bytes (64-1514, default: original)\n"
	       "  -R MBPS: limit TX rate to MBPS megabits per second at L1\n"
	       "           (e.g. -R 1000 for 1 Gbps, -R 10000 for 10 Gbps)\n"
	       "  -P PPS: limit TX rate to PPS packets per second\n"
	       "          (total across lcores; mutually exclusive with -R/-t)\n"
	       "  -t: timing mode - replay with original inter-packet gaps from pcap\n"
	       "  -s: uses a single mempool and all lcores will take packets from it\n"
	       "  -r: takes the first packet of the provided pcap file and replicates\n"
	       "      it in the per-lcore mempools.\n"
	       "  NOTE: -r and -s are mutually exclusive\n"
	       "  NOTE: -t (timing mode) is incompatible with -r (replicate)\n"
	       "  NOTE: -R and -t are mutually exclusive\n");
}

static const char short_options[] =
	"p:"
	"c:"
	"d:"
	"L:"
	"R:"
	"P:"
	"t"
	"s"
	"r"
	;

static const struct option lgopts[] = {
	{ "pcap", 1, 0, 'p' },
	{ "count", 1, 0, 'c' },
	{ "duration", 1, 0, 'd' },
	{ "length", 1, 0, 'L' },
	{ "rate", 1, 0, 'R' },
	{ "pps", 1, 0, 'P' },
	{ "timing", 0, 0, 't' },
	{ "single-mempool", 0, 0, 's' },
	{ "replicate", 0, 0, 'r' },
	{ NULL, 0, 0, 0 }
};

static int
pcap_replay_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt = argv;
	int option_index;
	char *prgname = argv[0];
	char errbuf[PCAP_ERRBUF_SIZE];

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'p':
			pcap_handle = pcap_open_offline(optarg, errbuf);
			if (!pcap_handle) {
				pcap_replay_usage();
				return -1;
			}
			break;
		case 'c':
			pkt_limit = parse_count(optarg);
			break;
		case 'd':
			duration_tsc = strtoull(optarg, NULL, 10);
			break;
		case 'L':
			pkt_size = atoi(optarg);
			if (pkt_size < MIN_PKT_LEN || pkt_size > MAX_PKT_LEN) {
				printf("Packet size must be between %d and %d\n",
				       MIN_PKT_LEN, MAX_PKT_LEN);
				return -1;
			}
			break;
		case 'R':
			rate_mbps = strtoull(optarg, NULL, 10);
			break;
		case 'P':
			rate_pps = strtoull(optarg, NULL, 10);
			break;
		case 't':
			timing_mode = true;
			break;
		case 's':
			use_single_mempool = true;
			break;
		case 'r':
			replicate_pkt = true;
			break;
		default:
			pcap_replay_usage();
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1;
	return ret;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void
pcap_rep_pktmbuf_ctor(struct rte_mempool *mp, void *opaque_arg,
		      void *_m, __rte_unused unsigned i)
{
	struct rte_mbuf *m = _m;
	uint32_t mbuf_size, buf_len, priv_size;
	char *p = (char *)opaque_arg;

	priv_size = rte_pktmbuf_priv_size(mp);
	buf_len = rte_pktmbuf_data_room_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;
	memset(m, 0, mbuf_size);

	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_iova = rte_mempool_virt2iova(m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, m->buf_len);
	m->pool = mp;
	m->nb_segs = 1;
	m->port = MBUF_INVALID_PORT;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;

	unsigned int len = pkt_size ? pkt_size : MIN_BUF_LEN;
	unsigned int copy_len = RTE_MIN(len, (unsigned int)MIN_BUF_LEN);

	m->data_len = len;
	m->pkt_len = len;

	/* Copy original header bytes; rest stays zeroed from memset */
	rte_memcpy((uint8_t *)m->buf_addr + m->data_off, p, copy_len);
}

static void
pcap_pktmbuf_ctor(struct rte_mempool *mp, void *opaque_arg,
		  void *_m, __rte_unused unsigned i)
{
	struct rte_mbuf *m = _m;
	uint32_t mbuf_size, buf_len, priv_size;
	const u_char *buffer;
	struct pcap_pkthdr *hdr;
	unsigned int len;
	pcap_t *p = (pcap_t *)opaque_arg;

	priv_size = rte_pktmbuf_priv_size(mp);
	buf_len = rte_pktmbuf_data_room_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;
	memset(m, 0, mbuf_size);

	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_iova = rte_mempool_virt2iova(m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, m->buf_len);
	m->pool = mp;
	m->nb_segs = 1;
	m->port = MBUF_INVALID_PORT;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;

	if (unlikely(pcap_next_ex(p, &hdr, &buffer) <= 0))
		rte_exit(EXIT_FAILURE, "Cannot create mbuf from pcap\n");

	if (pkt_size) {
		len = pkt_size;
	} else if (hdr->caplen < MIN_PKT_LEN) {
		len = MIN_PKT_LEN;
	} else if (hdr->caplen > MAX_PKT_LEN) {
		len = MAX_PKT_LEN;
	} else {
		len = hdr->caplen;
	}

	unsigned int copy_len = RTE_MIN(len, (unsigned int)hdr->caplen);

	m->data_len = len;
	m->pkt_len = len;

	/* Copy available pcap data; rest stays zeroed from memset */
	rte_memcpy((uint8_t *)m->buf_addr + m->data_off, buffer, copy_len);

	/* Store timestamp for timing mode */
	if (timing_mode) {
		struct timing_meta *meta = (struct timing_meta *)rte_mbuf_to_priv(m);
		uint64_t ts_ns = (uint64_t)hdr->ts.tv_sec * 1000000000ULL +
				 (uint64_t)hdr->ts.tv_usec * 1000ULL;

		if (first_pkt_ts_ns == 0)
			first_pkt_ts_ns = ts_ns;

		meta->timestamp_ns = ts_ns - first_pkt_ts_ns;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t portid;
	unsigned lcore_id;
	unsigned int nb_lcores;
	unsigned int i;
	const u_char *pkt_ptr_pcap;
	struct pcap_pkthdr *hdr;
	unsigned int pcap_pkt_count = 0, per_core_pcap_pkt_count = 0;
	long init_pos;

	/* Init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nb_lcores = rte_lcore_count();

	ret = pcap_replay_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid PCAP_REPLAY arguments\n");

	if (timing_mode && replicate_pkt)
		rte_exit(EXIT_FAILURE,
			 "Timing mode (-t) and replicate mode (-r) are mutually exclusive\n");

	if (timing_mode && rate_mbps)
		rte_exit(EXIT_FAILURE,
			 "Timing mode (-t) and rate limit (-R) are mutually exclusive\n");

	if (rate_mbps && rate_pps)
		rte_exit(EXIT_FAILURE,
			 "-R (Mbps) and -P (pps) are mutually exclusive\n");

	if (timing_mode && rate_pps)
		rte_exit(EXIT_FAILURE,
			 "Timing mode (-t) and pps limit (-P) are mutually exclusive\n");

	/* Convert timer_period and duration to TSC cycles */
	timer_period *= rte_get_timer_hz();
	if (duration_tsc)
		duration_tsc *= rte_get_timer_hz();

	/* Create the mbuf pools for RX */
	for (i = 0; i < nb_lcores; i++) {
		char name[64];
		snprintf(name, sizeof(name), "rx_mbuf_pool%02d", i);
		rx_pktmbuf_pool[i] = rte_pktmbuf_pool_create(name, 4096U,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE,
					rte_socket_id());
		if (rx_pktmbuf_pool[i] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init rx mbuf pool %d\n", i);

		lcore_queue_conf[i].qid = i;
		lcore_queue_conf[i].port_id = 0;  /* Single port setup */
	}

	/* Count the packets in the pcap file */
	if (replicate_pkt) {
		if (pcap_next_ex(pcap_handle, &hdr, &pkt_ptr_pcap) > 0)
			memcpy(pkt_rep, pkt_ptr_pcap, MIN_BUF_LEN);
	} else {
		init_pos = ftell(pcap_file(pcap_handle));
		while (pcap_next_ex(pcap_handle, &hdr, &pkt_ptr_pcap) > 0)
			pcap_pkt_count++;

		printf("PCAP packets: %u  (per-core: %u)\n",
		       pcap_pkt_count, pcap_pkt_count / nb_lcores);

		per_core_pcap_pkt_count = pcap_pkt_count / nb_lcores;
		fseek(pcap_file(pcap_handle), init_pos, SEEK_SET);
	}

	/* Create the pcap mbuf pools */
	unsigned int priv_size = sizeof(struct rte_pktmbuf_pool_private);
	if (timing_mode)
		priv_size += sizeof(struct timing_meta);

	if (use_single_mempool) {
		/* Ensure minimum pool size */
		unsigned int pool_size = pcap_pkt_count > 0 ? pcap_pkt_count : 2048;

		pcap_pool[0] = rte_mempool_create(
			"pcap_mbuf_pool", pool_size,
			RTE_MBUF_DEFAULT_BUF_SIZE, 512,
			priv_size,
			rte_pktmbuf_pool_init, NULL,
			pcap_pktmbuf_ctor, (void *)pcap_handle,
			rte_socket_id(), 0);
		if (pcap_pool[0] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init pcap mbuf pool\n");

		printf("Single mempool mbufs: %d\n",
		       rte_mempool_avail_count(pcap_pool[0]));

		for (i = 0; i < nb_lcores; i++)
			lcore_queue_conf[i].tx_pool = pcap_pool[0];
	} else if (replicate_pkt) {
		for (i = 0; i < nb_lcores; i++) {
			char name[64];
			unsigned flags = RTE_MEMPOOL_F_SP_PUT |
					 RTE_MEMPOOL_F_SC_GET;
			snprintf(name, sizeof(name), "pcap_mbuf_pool%02d", i);
			pcap_pool[i] = rte_mempool_create(
				name, 2048U, RTE_MBUF_DEFAULT_BUF_SIZE, 512,
				priv_size,
				rte_pktmbuf_pool_init, NULL,
				pcap_rep_pktmbuf_ctor, (void *)pkt_rep,
				rte_socket_id(), flags);
			if (pcap_pool[i] == NULL)
				rte_exit(EXIT_FAILURE,
					 "Cannot init pcap mbuf pool %d\n", i);

			lcore_queue_conf[i].tx_pool = pcap_pool[i];
		}
	} else {
		for (i = 0; i < nb_lcores; i++) {
			char name[64];
			unsigned flags = RTE_MEMPOOL_F_SP_PUT |
					 RTE_MEMPOOL_F_SC_GET;
			/* Ensure minimum pool size per core */
			unsigned int pool_size = per_core_pcap_pkt_count > 0 ?
						 per_core_pcap_pkt_count : 2048;

			snprintf(name, sizeof(name), "pcap_mbuf_pool%02d", i);
			pcap_pool[i] = rte_mempool_create(
				name, pool_size,
				RTE_MBUF_DEFAULT_BUF_SIZE, 512,
				priv_size,
				rte_pktmbuf_pool_init, NULL,
				pcap_pktmbuf_ctor, (void *)pcap_handle,
				rte_socket_id(), flags);
			if (pcap_pool[i] == NULL)
				rte_exit(EXIT_FAILURE,
					 "Cannot init pcap mbuf pool %d\n", i);

			lcore_queue_conf[i].tx_pool = pcap_pool[i];
		}
	}

	/*
	 * Drain every preloaded mbuf into an ordered array so the TX loop can
	 * iterate through ALL packets (round-robin) instead of recycling only
	 * the cache-hot front of the mempool. In single-mempool mode all cores
	 * share one pool; otherwise each per-core pool holds a contiguous slice
	 * of the pcap (core 0 = first slice, ...), so draining them in order
	 * reconstructs the full pcap order.
	 */
	{
		struct rte_mempool *pools[MAX_CORES];
		unsigned int npools = 0, cap = 0, total = 0;

		if (use_single_mempool || replicate_pkt) {
			pools[npools++] = lcore_queue_conf[0].tx_pool;
		} else {
			for (i = 0; i < nb_lcores; i++)
				pools[npools++] = lcore_queue_conf[i].tx_pool;
		}
		for (i = 0; i < npools; i++)
			cap += rte_mempool_avail_count(pools[i]);

		preload_pkts = rte_malloc(NULL,
					  cap * sizeof(struct rte_mbuf *), 0);
		if (preload_pkts == NULL)
			rte_exit(EXIT_FAILURE,
				 "Cannot alloc preload array (%u pkts)\n", cap);

		for (i = 0; i < npools; i++) {
			struct rte_mbuf *m;
			while (total < cap &&
			       rte_mempool_get(pools[i], (void **)&m) == 0)
				preload_pkts[total++] = m;
		}
		preload_count = total;
		if (preload_count == 0)
			rte_exit(EXIT_FAILURE, "No packets preloaded from pcap\n");

		printf("Preloaded %u packets for full round-robin replay\n",
		       preload_count);

		/* Spread cores across the array so they don't all start on pkt 0 */
		for (i = 0; i < nb_lcores; i++)
			preload_idx[i] = (preload_count / nb_lcores) * i;
	}

	pcap_close(pcap_handle);

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "Error getting device (port %u) info: %s\n",
				 portid, strerror(-ret));

		/*
		 * MBUF_FAST_FREE must stay OFF: it returns TX'd mbufs straight to
		 * the pool assuming refcnt==1. We keep every preloaded packet in
		 * preload_pkts[] and bump refcnt before each TX, so the driver must
		 * do a real rte_pktmbuf_free (refcnt decrement), not a fast free.
		 */
		/* if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE; */

		ret = rte_eth_dev_configure(portid, nb_lcores, nb_lcores,
					    &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust descriptors: err=%d, port=%u\n",
				 ret, portid);

		/* Setup RX queues */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		for (i = 0; i < nb_lcores; i++) {
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
						     rte_eth_dev_socket_id(portid),
						     &rxq_conf,
						     rx_pktmbuf_pool[i]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "RX queue setup: err=%d, q=%d, port=%u\n",
					 ret, i, portid);
		}

		/* Setup TX queues */
		for (i = 0; i < nb_lcores; i++) {
			txq_conf = dev_info.default_txconf;
			txq_conf.offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
						     rte_eth_dev_socket_id(portid),
						     &txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "TX queue setup: err=%d, port=%u\n",
					 ret, portid);

			char name[64];
			snprintf(name, sizeof(name), "tx_buffer%02d", i);
			tx_buffer[i] = rte_zmalloc_socket(name,
					RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
					0, rte_eth_dev_socket_id(portid));
			if (tx_buffer[i] == NULL)
				rte_exit(EXIT_FAILURE,
					 "Cannot allocate TX buffer for q %u\n", i);

			rte_eth_tx_buffer_init(tx_buffer[i], MAX_PKT_BURST);

			ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[i],
					rte_eth_tx_buffer_count_callback,
					&core_stats[i].dropped);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot set TX err callback, port %u\n",
					 portid);
		}

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN,
					     NULL, 0);
		if (ret < 0)
			printf("Port %u: failed to disable ptype parsing\n",
			       portid);

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_start: err=%d, port=%u\n",
				 ret, portid);

		printf("done\n");

		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					 "promiscuous_enable: err=%s, port=%u\n",
					 rte_strerror(-ret), portid);
		}

		memset(core_stats, 0, sizeof(core_stats));
	}

	/* Verify at least one port was initialized */
	if (tx_buffer[0] == NULL)
		rte_exit(EXIT_FAILURE,
			 "No ethernet ports detected. Check dpdk-devbind.py status.\n");

	/* Launch per-lcore processing */
	rte_eal_mp_remote_launch(pcap_replay_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	/* Print final stats before exiting */
	uint64_t tot_pkt = print_stats();
	printf("FINAL STATS: packets %lu\n",tot_pkt);
	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
	}

	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}

