// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/mutex.h>



#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <net/xdp.h>
#include <linux/skbuff.h>


#include <linux/configfs.h>
#include <linux/idr.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/ktime.h>
#include <asm/fpu/api.h>

#include "linux-regex-module/src/hs_runtime.h"
#include "rex.h"
#include "xdp_regex.h"




MODULE_LICENSE("GPL");
MODULE_AUTHOR("Esempio vectorscan in xdp");
MODULE_DESCRIPTION("Modulo kernel con dummy kfunc");

static ulong max_db_size = 128 << 20;
module_param(max_db_size, ulong, 0644);
MODULE_PARM_DESC(max_db_size, "Maximum size of configfs upload, default=128MB");

static DEFINE_IDR(rex_idr);
static DEFINE_MUTEX(rex_config_mutex);

/* =========================================================
 * Microbenchmark per-fase di bpf_scan_bytes (bench=1)
 *
 * Misura, per ogni scan block-mode:
 *   lookup    = idr_find + rcu_dereference + fetch scratch
 *   fpu_begin = irq_fpu_usable + kernel_fpu_begin (XSAVE)
 *   scan      = hs_scan vero e proprio
 *   fpu_end   = kernel_fpu_end (XRSTOR)
 * Statistiche per-CPU, bucketizzate per lunghezza payload,
 * più istogramma log2 del tempo totale (per vedere outlier).
 * Lettura/reset via /sys/kernel/debug/rex_bench.
 * ========================================================= */
static bool bench;
module_param(bench, bool, 0644);
MODULE_PARM_DESC(bench, "Enable per-phase timing of bpf_scan_bytes (debugfs rex_bench)");

#define REX_BENCH_NBUCKETS 7
#define REX_BENCH_NHIST    32

static const u32 rex_bench_bucket_lo[REX_BENCH_NBUCKETS] = {
	0, 64, 128, 256, 512, 1024, 1536
};

struct rex_bench_bucket {
	u64 count;
	u64 bytes;
	u64 matches;
	u64 sum_lookup;
	u64 sum_fpu_begin;
	u64 sum_scan;
	u64 sum_scan_matched; /* quota di sum_scan degli scan con match */
	u64 sum_fpu_end;
	u64 sum_total;
	u64 min_total;
	u64 max_total;
};

struct rex_bench_stats {
	struct rex_bench_bucket b[REX_BENCH_NBUCKETS];
	u64 hist_total[REX_BENCH_NHIST]; /* indice = fls64(total_ns) */
	u64 busy;                        /* scan rifiutate per FPU non usabile */
};

static struct rex_bench_stats __percpu *rex_bench_stats;
static struct dentry *rex_bench_dentry;
static u64 rex_bench_clock_x1000;    /* ns per 1000 chiamate ktime_get_ns() */

static inline int rex_bench_bucket_idx(u32 len)
{
	if (len < 64)   return 0;
	if (len < 128)  return 1;
	if (len < 256)  return 2;
	if (len < 512)  return 3;
	if (len < 1024) return 4;
	if (len < 1536) return 5;
	return 6;
}

static void rex_bench_record(u32 len, bool matched,
			     u64 t0, u64 t1, u64 t2, u64 t3, u64 t4)
{
	struct rex_bench_stats *s = this_cpu_ptr(rex_bench_stats);
	struct rex_bench_bucket *b = &s->b[rex_bench_bucket_idx(len)];
	u64 total = t4 - t0;

	b->count++;
	b->bytes         += len;
	b->matches       += matched;
	b->sum_lookup    += t1 - t0;
	b->sum_fpu_begin += t2 - t1;
	b->sum_scan      += t3 - t2;
	if (matched)
		b->sum_scan_matched += t3 - t2;
	b->sum_fpu_end   += t4 - t3;
	b->sum_total     += total;
	if (!b->min_total || total < b->min_total)
		b->min_total = total;
	if (total > b->max_total)
		b->max_total = total;
	s->hist_total[min(fls64(total), REX_BENCH_NHIST - 1)]++;
}

static int rex_bench_show(struct seq_file *m, void *v)
{
	int cpu, i, h;

	seq_printf(m, "bench %d\n", bench);
	seq_printf(m, "clock_ns_x1000 %llu\n", rex_bench_clock_x1000);
	for_each_online_cpu(cpu) {
		struct rex_bench_stats *s = per_cpu_ptr(rex_bench_stats, cpu);

		seq_printf(m, "cpu %d busy %llu\n", cpu, s->busy);
		for (i = 0; i < REX_BENCH_NBUCKETS; i++) {
			struct rex_bench_bucket *b = &s->b[i];

			if (!b->count)
				continue;
			seq_printf(m,
				   "cpu %d bucket %u count %llu bytes %llu matches %llu lookup %llu fpu_begin %llu scan %llu scan_matched %llu fpu_end %llu total %llu min %llu max %llu\n",
				   cpu, rex_bench_bucket_lo[i], b->count,
				   b->bytes, b->matches, b->sum_lookup,
				   b->sum_fpu_begin, b->sum_scan,
				   b->sum_scan_matched,
				   b->sum_fpu_end, b->sum_total,
				   b->min_total, b->max_total);
		}
		seq_printf(m, "cpu %d hist", cpu);
		for (h = 0; h < REX_BENCH_NHIST; h++)
			seq_printf(m, " %llu", s->hist_total[h]);
		seq_putc(m, '\n');
	}
	return 0;
}

static int rex_bench_open(struct inode *inode, struct file *file)
{
	return single_open(file, rex_bench_show, NULL);
}

/* Qualsiasi write resetta le statistiche. */
static ssize_t rex_bench_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	int cpu;

	for_each_possible_cpu(cpu)
		memset(per_cpu_ptr(rex_bench_stats, cpu), 0,
		       sizeof(struct rex_bench_stats));
	return count;
}

static const struct file_operations rex_bench_fops = {
	.owner   = THIS_MODULE,
	.open    = rex_bench_open,
	.read    = seq_read,
	.write   = rex_bench_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void rex_bench_calibrate(void)
{
	u64 start, end;
	int i;

	start = ktime_get_ns();
	for (i = 0; i < 999; i++)
		ktime_get_ns();
	end = ktime_get_ns();
	rex_bench_clock_x1000 = end - start;
}

/* =========================================================
 * Per-flow stream table for bpf_xdp_stream_scan_bytes
 * ========================================================= */
#define FLOW_TABLE_BITS 16

struct rex_flow_entry {
	struct hlist_node   node;
	struct rex_flow_key key;
	hs_stream_t        *stream;
	u8                  dirty; /* 1 = flow already matched; skip scan, always pass */
};

static DEFINE_HASHTABLE(rex_flow_table, FLOW_TABLE_BITS);
static DEFINE_SPINLOCK(rex_flow_table_lock);

static u32 flow_key_hash(const struct rex_flow_key *key)
{
	/* Hash only the 5-tuple — exclude close_flag and _pad */
	u32 words[3];

	words[0] = key->src_ip;
	words[1] = key->dst_ip;
	words[2] = ((u32)(__force u16)key->src_port << 16) |
		    (__force u16)key->dst_port;
	return jhash2(words, 3, key->proto);
}

static struct rex_flow_entry *flow_entry_find(const struct rex_flow_key *key,
					      u32 hash)
{
	struct rex_flow_entry *e;

	hash_for_each_possible(rex_flow_table, e, node, hash) {
		if (e->key.src_ip   == key->src_ip   &&
		    e->key.dst_ip   == key->dst_ip   &&
		    e->key.src_port == key->src_port &&
		    e->key.dst_port == key->dst_port &&
		    e->key.proto    == key->proto)
			return e;
	}
	return NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
/* Based on code taken from net/core/filter.c */
static void *my_bpf_xdp_pointer(const struct xdp_buff *xdp, u32 offset, u32 len)
{
	u32 size = xdp->data_end - xdp->data;
	void *addr = xdp->data;

	if (unlikely(offset > 0xffff || len > 0xffff))
	{
		pr_info("offset o len maggiori di ffff\n");
		return ERR_PTR(-EFAULT);
	}
	if (offset + len > size){
		pr_info("la somma maggiore di size\n");
		return ERR_PTR(-EINVAL);
	}
	return addr + offset;
}
#else
/* This code is taken from net/core/filter.c */
static void *my_bpf_xdp_pointer(const struct xdp_buff *xdp, u32 offset, u32 len)
{
	u32 size = xdp->data_end - xdp->data;
	void *addr = xdp->data;
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	int i;
	

	//pr_info("sto eseguendo questa funzione3\n");
	//pr_info("off:%d len:%d size:%d addr:%p\n",offset,len,size,addr);
	
	if (unlikely(offset > 0xffff || len > 0xffff)){
		pr_info("Errore al primo controllo\n");
		return ERR_PTR(-EFAULT);
	}
	if (offset /*+ len*/ > xdp_get_buff_len(xdp)){
		pr_info("Errore dimensione supera quella del buffer\n");
		return ERR_PTR(-EINVAL);
	}
	if (offset < size) /* linear area */
		goto out;
	//pr_info("supero i controlli di routine\n");
	offset -= size;
	for (i = 0; i < sinfo->nr_frags; i++) { /* paged area */
		u32 frag_size = skb_frag_size(&sinfo->frags[i]);

		if (offset < frag_size) {
			addr = skb_frag_address(&sinfo->frags[i]);
			size = frag_size;
			break;
		}
		offset -= frag_size;
	}
out:
	//pr_info("off:%d len:%d size:%d addr:%p\n",offset,len,size,addr);
	//return offset + len <= size ? addr + offset : NULL;
	return offset <= size ? addr + offset : NULL;
}
#endif



/* Helper: restituisce puntatore alla regione lineare dell'sk_buff.
 * Fallisce se [offset, offset+len) non è interamente nella head lineare.
 * Il chiamante BPF può usare bpf_skb_pull_data() per linearizzare prima. */
static void *my_bpf_skb_pointer(const struct sk_buff *skb, u32 offset, u32 len)
{
	if (unlikely((u64)offset + len > skb_headlen(skb)))
		return ERR_PTR(-EINVAL);
	return skb->data + offset;
}

static inline hs_database_t *patterns(struct rex_database *db)
{
	if (!db)
		return NULL;
	return (hs_database_t *)db->bytes;
}
static int rex_scan_cb(unsigned int expression, unsigned long long from,
		       unsigned long long to, unsigned int flags, void *raw_ctx)
{
	struct rex_scan_ctx *ctx = raw_ctx;
	struct rex_scan_attr *attr = ctx->attr;
	u32 features = attr->handler_flags;
	attr->last_event = (struct rex_event){
		.expression = expression,
		.from = from,
		.to = to,
		.flags = flags,
	};
	attr->nr_events += 1;
	return (features & REX_SINGLE_SHOT) ? 1 : 0;
}

int bpf_scan_bytes(const void *buf, __u32 buf__sz, struct rex_scan_attr *attr)
{
	struct rex_scan_ctx ctx = {
		.attr = attr,
		.block = buf,
		.block_len = buf__sz,
	};
	struct rex_policy *rex;
	struct rex_database *db;
	hs_scratch_t *scratch;
	hs_error_t err;
	u64 t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
	bool do_bench = bench && rex_bench_stats;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_bh_held());

	if (unlikely(!buf || !attr)){
		pr_info("Error 1\n");
		return -EINVAL;
	}
	if (do_bench)
		t0 = ktime_get_ns();
	rex = idr_find(&rex_idr, attr->database_id);
	if (unlikely(!rex)){
		pr_info("Error 2 db id:%d\n",attr->database_id);
		return -EBADF;
	}
	db = rcu_dereference(rex->database);
	if (unlikely(!db)){
		pr_info("Error 3\n");
		return -ENODATA;
	}
	scratch = ((hs_scratch_t **)db->scratch)[raw_smp_processor_id()];
	if (do_bench)
		t1 = ktime_get_ns();

	if (!irq_fpu_usable()) {
		if (do_bench)
			this_cpu_inc(rex_bench_stats->busy);
		return -EBUSY;
	}
	kernel_fpu_begin();
	if (do_bench)
		t2 = ktime_get_ns();
	err = hs_scan(patterns(db), buf, buf__sz, 0, scratch, rex_scan_cb, &ctx);
	if (do_bench)
		t3 = ktime_get_ns();
	kernel_fpu_end();
	if (do_bench) {
		t4 = ktime_get_ns();
		rex_bench_record(buf__sz, attr->nr_events > 0,
				 t0, t1, t2, t3, t4);
	}
	switch (err) {
	case HS_DB_MODE_ERROR:
		pr_info("errore HS_DB_MODE_ERROR %d\n",err);
		return -ENOEXEC;
	case HS_SCAN_TERMINATED:
//		pr_info("1?\n");
		return 1;
	case HS_SUCCESS:
//	pr_info("ho trovato %d match\n",attr->nr_events);
		return 0;
	case HS_SCRATCH_IN_USE:
	case HS_INVALID:
	case HS_UNKNOWN_ERROR:
	default:
		WARN(1, "hs_scan() failed with code %d\n", (int)err);
		return -EFAULT;
	}
}
EXPORT_SYMBOL(bpf_scan_bytes);


__bpf_kfunc int bpf_xdp_scan_bytes(const struct xdp_md *xdp_md, u32 offset, u32 len,struct rex_scan_attr *scan_attr,u32 offset2)
{
	struct xdp_buff *xdp = (struct xdp_buff *)xdp_md;
	void *ptr = my_bpf_xdp_pointer(xdp, offset2, len);
		
	if (IS_ERR(ptr)){
		return PTR_ERR(ptr);
	}
	if (likely(ptr))
	{
		return bpf_scan_bytes(ptr, len, scan_attr);
	}
	else{
		return -ENOTSUPP;
	}
}
EXPORT_SYMBOL(bpf_xdp_scan_bytes);

/*
 * bpf_xdp_stream_scan_bytes — streaming Hyperscan kfunc for TCP flows.
 *
 * Maintains one hs_stream_t per 5-tuple in rex_flow_table.
 * Each call feeds the current packet's payload into the stream so that
 * patterns spanning multiple segments are matched correctly.
 *
 * @close_flag: set to 1 on TCP FIN/RST — closes and frees the stream.
 */
__bpf_kfunc int bpf_xdp_stream_scan_bytes(const struct xdp_md *xdp_md,
					   struct rex_scan_attr *scan_attr,
					   struct rex_flow_key *key,
					   u32 payload_offset, u32 len)
{
	struct rex_scan_ctx ctx = { .attr = scan_attr };
	struct xdp_buff *xdp = (struct xdp_buff *)xdp_md;
	struct rex_flow_entry *entry;
	struct rex_policy *rex;
	struct rex_database *db;
	hs_scratch_t *scratch;
	hs_stream_t *stream;
	hs_error_t err;
	void *ptr;
	u32 hash;

	if (unlikely(!scan_attr || !key))
		return -EINVAL;

	rcu_read_lock();
	rex = idr_find(&rex_idr, scan_attr->database_id);
	if (unlikely(!rex)) {
		rcu_read_unlock();
		pr_info_once("bpf_xdp_stream_scan_bytes: db id %d not found\n",
			     scan_attr->database_id);
		return -EBADF;
	}
	db = rcu_dereference(rex->database);
	if (unlikely(!db)) {
		rcu_read_unlock();
		return -ENODATA;
	}
	scratch = ((hs_scratch_t **)db->scratch)[raw_smp_processor_id()];

	hash = flow_key_hash(key);
	spin_lock(&rex_flow_table_lock);
	entry = flow_entry_find(key, hash);

	/* ── FIN / RST: close stream and remove entry ── */
	if (key->close_flag) {
		if (entry) {
			stream = entry->stream;
			hash_del(&entry->node);
			kfree(entry);
			spin_unlock(&rex_flow_table_lock);
			/* NULL callback: skip EOF matching, just free.
			 * If FPU is contested we bypass hs_close_stream and
			 * free the (single-alloc) stream directly to avoid
			 * nested kernel_fpu_begin → kernel corruption. */
			if (irq_fpu_usable()) {
				kernel_fpu_begin();
				hs_close_stream(stream, NULL, NULL, NULL);
				kernel_fpu_end();
			} else {
				kfree(stream);
			}
		} else {
			spin_unlock(&rex_flow_table_lock);
		}
		rcu_read_unlock();
		return 0;
	}

	/* ── New flow: open a stream ── */
	if (!entry) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry) {
			spin_unlock(&rex_flow_table_lock);
			rcu_read_unlock();
			return -ENOMEM;
		}
		if (!irq_fpu_usable()) {
			kfree(entry);
			spin_unlock(&rex_flow_table_lock);
			rcu_read_unlock();
			return -EBUSY;
		}
		kernel_fpu_begin();
		err = hs_open_stream(patterns(db), 0, &entry->stream);
		kernel_fpu_end();
		if (err != HS_SUCCESS) {
			kfree(entry);
			spin_unlock(&rex_flow_table_lock);
			rcu_read_unlock();
			pr_info_once("hs_open_stream failed: %d (DB not stream-mode?)\n",
				     (int)err);
			return -ENOEXEC;
		}
		entry->key = *key;
		hash_add(rex_flow_table, &entry->node, hash);
	}

	/* ── If already matched, skip scan and keep passing to Suricata ── */
	if (entry->dirty) {
		scan_attr->nr_events = 1;
		spin_unlock(&rex_flow_table_lock);
		rcu_read_unlock();
		return 0;
	}

	/* ── Feed packet payload into the stream ── */
	ptr = my_bpf_xdp_pointer(xdp, payload_offset, len);
	if (IS_ERR_OR_NULL(ptr)) {
		spin_unlock(&rex_flow_table_lock);
		rcu_read_unlock();
		return IS_ERR(ptr) ? PTR_ERR(ptr) : -ENOTSUPP;
	}

	ctx.block     = ptr;
	ctx.block_len = len;

	if (!irq_fpu_usable()) {
		spin_unlock(&rex_flow_table_lock);
		rcu_read_unlock();
		return -EBUSY;
	}
	kernel_fpu_begin();
	err = hs_scan_stream(entry->stream, ptr, len, 0, scratch,
			     rex_scan_cb, &ctx);
	kernel_fpu_end();

	/* Mark flow dirty on first match so all subsequent packets bypass scan */
	if (scan_attr->nr_events > 0)
		entry->dirty = 1;

	spin_unlock(&rex_flow_table_lock);
	rcu_read_unlock();

	switch (err) {
	case HS_SUCCESS:
		return 0;
	case HS_SCAN_TERMINATED:
		return 1;
	case HS_DB_MODE_ERROR:
		pr_info_once("bpf_xdp_stream_scan_bytes: DB is not stream-mode\n");
		return -ENOEXEC;
	default:
		WARN(1, "hs_scan_stream() failed with code %d\n", (int)err);
		return -EFAULT;
	}
}
EXPORT_SYMBOL(bpf_xdp_stream_scan_bytes);

/* =========================================================
 * TC (SCHED_CLS) kfuncs — operano su sk_buff
 *
 * payload_offset è relativo a skb->data così come lo vede
 * il programma BPF TC (dopo eth_type_trans il MAC header
 * non è incluso; calcola gli offset di conseguenza).
 * Se i dati non sono completamente lineari chiama prima
 * bpf_skb_pull_data(skb, 0) dal lato BPF.
 * ========================================================= */

__bpf_kfunc int bpf_skb_scan_bytes(struct sk_buff *skb,
				    u32 payload_offset, u32 len,
				    struct rex_scan_attr *scan_attr)
{
	void *ptr;

	if (unlikely(!skb || !scan_attr))
		return -EINVAL;

	ptr = my_bpf_skb_pointer(skb, payload_offset, len);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	return bpf_scan_bytes(ptr, len, scan_attr);
}
EXPORT_SYMBOL(bpf_skb_scan_bytes);

__bpf_kfunc int bpf_skb_stream_scan_bytes(struct sk_buff *skb,
					   struct rex_scan_attr *scan_attr,
					   struct rex_flow_key *key,
					   u32 payload_offset, u32 len)
{
	struct rex_scan_ctx ctx = { .attr = scan_attr };
	struct rex_flow_entry *entry;
	struct rex_policy *rex;
	struct rex_database *db;
	hs_scratch_t *scratch;
	hs_stream_t *stream;
	hs_error_t err;
	void *ptr;
	u32 hash;

	if (unlikely(!skb || !scan_attr || !key))
		return -EINVAL;

	rcu_read_lock();
	rex = idr_find(&rex_idr, scan_attr->database_id);
	if (unlikely(!rex)) {
		rcu_read_unlock();
		pr_info_once("bpf_skb_stream_scan_bytes: db id %d not found\n",
			     scan_attr->database_id);
		return -EBADF;
	}
	db = rcu_dereference(rex->database);
	if (unlikely(!db)) {
		rcu_read_unlock();
		return -ENODATA;
	}
	scratch = ((hs_scratch_t **)db->scratch)[raw_smp_processor_id()];

	hash = flow_key_hash(key);
	spin_lock(&rex_flow_table_lock);
	entry = flow_entry_find(key, hash);

	/* ── FIN / RST: chiude lo stream e rimuove l'entry ── */
	if (key->close_flag) {
		if (entry) {
			stream = entry->stream;
			hash_del(&entry->node);
			kfree(entry);
			spin_unlock(&rex_flow_table_lock);
			if (irq_fpu_usable()) {
				kernel_fpu_begin();
				hs_close_stream(stream, NULL, NULL, NULL);
				kernel_fpu_end();
			} else {
				kfree(stream);
			}
		} else {
			spin_unlock(&rex_flow_table_lock);
		}
		rcu_read_unlock();
		return 0;
	}

	/* ── Nuovo flusso: apre uno stream ── */
	if (!entry) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry) {
			spin_unlock(&rex_flow_table_lock);
			rcu_read_unlock();
			return -ENOMEM;
		}
		if (!irq_fpu_usable()) {
			kfree(entry);
			spin_unlock(&rex_flow_table_lock);
			rcu_read_unlock();
			return -EBUSY;
		}
		kernel_fpu_begin();
		err = hs_open_stream(patterns(db), 0, &entry->stream);
		kernel_fpu_end();
		if (err != HS_SUCCESS) {
			kfree(entry);
			spin_unlock(&rex_flow_table_lock);
			rcu_read_unlock();
			pr_info_once("bpf_skb_stream_scan_bytes: hs_open_stream failed: %d\n",
				     (int)err);
			return -ENOEXEC;
		}
		entry->key = *key;
		hash_add(rex_flow_table, &entry->node, hash);
	}

	/* ── Flusso già matchato: salta la scan ── */
	if (entry->dirty) {
		scan_attr->nr_events = 1;
		spin_unlock(&rex_flow_table_lock);
		rcu_read_unlock();
		return 0;
	}

	/* ── Estrae il puntatore al payload ── */
	ptr = my_bpf_skb_pointer(skb, payload_offset, len);
	if (IS_ERR_OR_NULL(ptr)) {
		spin_unlock(&rex_flow_table_lock);
		rcu_read_unlock();
		return IS_ERR(ptr) ? PTR_ERR(ptr) : -EINVAL;
	}

	ctx.block     = ptr;
	ctx.block_len = len;

	if (!irq_fpu_usable()) {
		spin_unlock(&rex_flow_table_lock);
		rcu_read_unlock();
		return -EBUSY;
	}
	kernel_fpu_begin();
	err = hs_scan_stream(entry->stream, ptr, len, 0, scratch,
			     rex_scan_cb, &ctx);
	kernel_fpu_end();

	if (scan_attr->nr_events > 0)
		entry->dirty = 1;

	spin_unlock(&rex_flow_table_lock);
	rcu_read_unlock();

	switch (err) {
	case HS_SUCCESS:
		return 0;
	case HS_SCAN_TERMINATED:
		return 1;
	case HS_DB_MODE_ERROR:
		pr_info_once("bpf_skb_stream_scan_bytes: DB is not stream-mode\n");
		return -ENOEXEC;
	default:
		WARN(1, "hs_scan_stream() failed with code %d\n", (int)err);
		return -EFAULT;
	}
}
EXPORT_SYMBOL(bpf_skb_stream_scan_bytes);

// Registra la funzione come kfunc accessibile da eBPF

/* XDP kfunc set */
BTF_SET8_START(xdp_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_scan_bytes, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdp_stream_scan_bytes, KF_RET_NULL)
BTF_SET8_END(xdp_kfunc_set)

static const struct btf_kfunc_id_set xdp_kfunc_ids = {
	.owner = THIS_MODULE,
	.set   = &xdp_kfunc_set,
};

/* bpf_skb_scan_raw — kfunc per TC (SCHED_CLS).
 * Prende un puntatore grezzo al payload già estratto dal programma BPF
 * tramite accesso diretto al pacchetto (skb->data + offset).
 * Evita il problema di BTF matching con struct sk_buff * (tipo kernel
 * incompleto vs completo) che causa il reject di libbpf. */
__bpf_kfunc int bpf_skb_scan_raw(const void *buf, u32 buf__sz,
				   struct rex_scan_attr *scan_attr)
{
	return bpf_scan_bytes(buf, buf__sz, scan_attr);
}
EXPORT_SYMBOL(bpf_skb_scan_raw);

/* TC (SCHED_CLS) kfunc set */
BTF_SET8_START(tc_kfunc_set)
BTF_ID_FLAGS(func, bpf_skb_scan_raw, 0)
BTF_SET8_END(tc_kfunc_set)

static const struct btf_kfunc_id_set tc_kfunc_ids = {
	.owner = THIS_MODULE,
	.set   = &tc_kfunc_set,
};


static struct rex_policy *to_policy(struct config_item *item)
{
	return item ? container_of(item, struct rex_policy, item) : NULL;
}

static ssize_t rexcfg_database_read(struct config_item *item, void *outbuf,
				    size_t size)
{
	struct rex_policy *rex = to_policy(item);
	struct rex_database *db;
	char *bytes = outbuf;
	ssize_t ret;

	rcu_read_lock();
	db = rcu_dereference(rex->database);

	if (!bytes) {
		/* In first call return size for te buffer. */
		if (hs_database_size(patterns(db), &ret))
			ret = 0;
	} else if (size > 0) {
		/* In second call fill the buffer with data.
		 * We have to check size again to avoid races.
		 */
		if (hs_database_size(patterns(db), &ret) || ret != size) {
			ret = -ETXTBSY;
			goto out;
		}

		if (hs_serialize_database(patterns(db), &bytes, NULL)) {
			pr_info("XDP_REGEX: Errore serializzazione del database\n");
			WARN(1, "hs_serialize_database() failed\n");
			ret = -EIO;
		}

		/* Check that pointer wasn't overwritten. */
		BUG_ON(bytes != outbuf);
	} else {
		return 0;
	}

out:
	rcu_read_unlock();
	return ret;
}

static void rex_assign_database(struct rex_policy *rex, struct rex_database *db)
{
	db = rcu_replace_pointer(rex->database, db,
				 lockdep_is_held(&rex_config_mutex));
	rex->epoch += 1;

	if (db) {
		int i, ncpus = num_possible_cpus();
		hs_scratch_t **s = (hs_scratch_t **)db->scratch;

		synchronize_rcu();
		if (s) {
			for (i = 0; i < ncpus; i++)
				if (s[i]) hs_free_scratch(s[i]);
			kfree(s);
		}
		vfree(db);
	}
}

static ssize_t rexcfg_database_write(struct config_item *item,
				     const void *bytes, size_t nbytes)
{
	struct rex_policy *rex = to_policy(item);
	struct rex_database *db;
	size_t alloc_size;
	int cpu;
	int ret;
	/* Drop existing database on empty write. */
	if (nbytes == 0) {
		mutex_lock(&rex_config_mutex);
		rex_assign_database(rex, NULL);
		mutex_unlock(&rex_config_mutex);
		return nbytes;
	}
	ret = hs_serialized_database_size(bytes,nbytes,&alloc_size);
	if(ret)
	{	
		pr_info("err:%d / %d %d \n",ret,nbytes,alloc_size);	
		pr_info("Errore: serializzazione database\n");
		return -EIO;
	}
	db = vmalloc(sizeof(*db) + alloc_size);
	if (!db){
		pr_info("Errore: allocazione database\n");
		return -ENOMEM;
	}
	ret=hs_deserialize_database_at(bytes, nbytes, patterns(db));
	if (ret) {
		vfree(db);
		pr_info("Errore:%d deserializzazione  database\n",ret);
		return -EINVAL;
	}

	/* Allocate one hs_scratch_t per CPU via kmalloc — avoids the
	 * per-CPU allocator's 32 KB limit that stream-mode scratches exceed. */
	{
		int ncpus = num_possible_cpus();
		hs_scratch_t **scratches = kcalloc(ncpus, sizeof(hs_scratch_t *),
						   GFP_KERNEL);
		if (!scratches) {
			vfree(db);
			pr_info("Errore: allocazione array scratch\n");
			return -ENOMEM;
		}
		for (cpu = 0; cpu < ncpus; cpu++) {
			if (hs_alloc_scratch(patterns(db), &scratches[cpu])) {
				while (--cpu >= 0)
					hs_free_scratch(scratches[cpu]);
				kfree(scratches);
				vfree(db);
				pr_info("Errore: hs_alloc_scratch cpu %d\n", cpu);
				return -ENOMEM;
			}
		}
		db->scratch = (void **)scratches;
	}

	mutex_lock(&rex_config_mutex);
	rex_assign_database(rex, db);
	mutex_unlock(&rex_config_mutex);
	pr_info("database successful write\n");
	return nbytes;
}

static ssize_t rexcfg_info_show(struct config_item *item, char *str)
{
	struct rex_policy *rex = to_policy(item);
	struct rex_database *db;
	char *info;
	int ret = 0;

	rcu_read_lock();

	db = rcu_dereference(rex->database);
	if (hs_database_info(patterns(db), &info)) {
		ret = -EIO;
		goto out;
	}

	ret += sysfs_emit_at(str, ret, "%s\n", info);
	kfree(info);

out:
	rcu_read_unlock();
	return ret;
}

static ssize_t rexcfg_epoch_show(struct config_item *item, char *str)
{
	return snprintf(str, PAGE_SIZE, "%d\n", to_policy(item)->epoch);
}

static ssize_t rexcfg_id_show(struct config_item *item, char *str)
{
	return snprintf(str, PAGE_SIZE, "%d\n", to_policy(item)->id);
}

static ssize_t rexcfg_id_store(struct config_item *item, const char *str,
			       size_t length)
{
	struct rex_policy *rex = to_policy(item);
	int ret, new_id;


	ret = kstrtoint(str, 0, &new_id);
	if (ret < 0){
		printk("Error 1 to read id\n");
		return -EINVAL;
	}
	printk("new ID = %d\n",new_id);
	mutex_lock(&rex_config_mutex);

	if (rex->id == new_id) {
		//printk("new id ==rex->id\n");
		ret = length;
		goto out;
	}

	ret = idr_alloc(&rex_idr, rex, new_id, new_id + 1, GFP_KERNEL);
	if (ret < 0){
		printk("Error store id: 2\n");
		goto out;
	}
	BUG_ON(idr_remove(&rex_idr, rex->id) != rex);
	rex->id = new_id;
	ret = length;
	//printk("Successfull store id\n");
out:
	mutex_unlock(&rex_config_mutex);
	//printk("store id terminated\n");
	return ret;
}

static ssize_t rexcfg_note_show(struct config_item *item, char *str)
{
	struct rex_policy *rex = to_policy(item);
	int ret;

	mutex_lock(&rex->lock);
	ret = snprintf(str, PAGE_SIZE, "%s", to_policy(item)->note);
	mutex_unlock(&rex->lock);

	return ret;
}

static ssize_t rexcfg_note_store(struct config_item *item, const char *str,
				 size_t length)
{
	struct rex_policy *rex = to_policy(item);

	mutex_lock(&rex->lock);
	strncpy(rex->note, str, length);
	mutex_unlock(&rex->lock);

	return length;
}

/* Our subsystem hierarchy is:
 *
 * /sys/kernel/config/rex/
 *		|
 *		<policy>/
 *		|	id		(rw)
 *		|	database	(rw)
 *		|	epoch		(ro)
 *		|	info		(ro)
 *		|	note		(rw)
 *		|
 *		<policy>/...
 */

CONFIGFS_BIN_ATTR(rexcfg_, database, NULL, 0);
CONFIGFS_ATTR_RO(rexcfg_, epoch);
CONFIGFS_ATTR_RO(rexcfg_, info);
CONFIGFS_ATTR(rexcfg_, id);
CONFIGFS_ATTR(rexcfg_, note);

static void rexcfg_item_release(struct config_item *item)
{
	struct rex_policy *rex = to_policy(item);
	
	pr_info("release call\n");
	mutex_lock(&rex_config_mutex);
	BUG_ON(idr_remove(&rex_idr, rex->id) != rex);
	rex_assign_database(rex, NULL);
	mutex_unlock(&rex_config_mutex);
}

static const struct config_item_type rex_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = (struct configfs_attribute *[]){ &rexcfg_attr_id,
						     &rexcfg_attr_info,
						     &rexcfg_attr_epoch,
						     &rexcfg_attr_note, NULL },
	.ct_bin_attrs =
		(struct configfs_bin_attribute *[]){
			&rexcfg_attr_database,
			NULL,
		},
	.ct_item_ops =
		&(struct configfs_item_operations){
			.release = rexcfg_item_release,
		}
};

static struct config_item *rex_make_item(struct config_group *group,
					 const char *name)
{
	struct rex_policy *rex;
	int id;

	rex = kzalloc(sizeof(*rex), GFP_KERNEL);
	if (!rex)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&rex_config_mutex);

	/* Patch database attribute type */
	rexcfg_attr_database.cb_max_size = max_db_size;
	config_item_init_type_name(&rex->item, name, &rex_type);

	id = idr_alloc(&rex_idr, rex, 0, U32_MAX, GFP_KERNEL);
	pr_info("id assigned at %s: %d\n",name,id);
	if (id < 0) {
		kfree(rex);
		return ERR_PTR(id);
	}
	rex->id = id;

	mutex_unlock(&rex_config_mutex);

	return &rex->item;
}


static const struct config_item_type rex_group_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops =
		&(struct configfs_group_operations){
			.make_item = rex_make_item,
		},
};

static struct configfs_subsystem rex_configfs = {
    .su_mutex = __MUTEX_INITIALIZER(rex_configfs.su_mutex),
    .su_group =
        {
            .cg_item =
                {
                    .ci_namebuf = "rex",
                    .ci_type = &rex_group_type,
                },
        },
};

// Registra il set di kfunc all'inizializzazione del modulo
static int __init dummy_kfunc_init(void)
{
    	pr_info("insmod\n");
	int err;

	rex_bench_stats = alloc_percpu(struct rex_bench_stats);
	if (!rex_bench_stats)
		return -ENOMEM;
	rex_bench_calibrate();
	rex_bench_dentry = debugfs_create_file("rex_bench", 0644, NULL, NULL,
					       &rex_bench_fops);
	pr_info("rex_bench: bench=%d, ktime_get_ns overhead = %llu ns / 1000 call\n",
		bench, rex_bench_clock_x1000);

	config_group_init(&rex_configfs.su_group);
	err = configfs_register_subsystem(&rex_configfs);
	if (err)
		return err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &xdp_kfunc_ids);
	if (err)
		return err;

	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &tc_kfunc_ids);
}

static void __exit dummy_kfunc_exit(void)
{
	struct rex_flow_entry *entry;
	struct hlist_node *tmp;
	int i;

	/* Free all open streams — NULL callback skips EOF matching */
	spin_lock(&rex_flow_table_lock);
	hash_for_each_safe(rex_flow_table, i, tmp, entry, node) {
		hash_del(&entry->node);
		kernel_fpu_begin();
		hs_close_stream(entry->stream, NULL, NULL, NULL);
		kernel_fpu_end();
		kfree(entry);
	}
	spin_unlock(&rex_flow_table_lock);

	pr_info("ciao mondo\n");
	configfs_unregister_subsystem(&rex_configfs);
	debugfs_remove(rex_bench_dentry);
	free_percpu(rex_bench_stats);
}

module_init(dummy_kfunc_init);
module_exit(dummy_kfunc_exit);
