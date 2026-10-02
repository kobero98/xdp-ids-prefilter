// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ac_module.c — Aho-Corasick DFA kfunc per XDP
 *
 * Speculare a xdp_kfunc_mod.c (Hyperscan) ma usa Aho-Corasick:
 *   - Nessun FPU: la scan loop è pura aritmetica intera
 *   - Nessuno scratch per CPU: lo stato è una variabile u32 sullo stack
 *   - Nessuna allocazione per pacchetto
 *
 * Flusso:
 *   1. ac_build produce patterns.acdb (header 64 B + tabella stati)
 *   2. dd if=patterns.acdb of=/sys/kernel/config/ac/<policy>/database
 *   3. Il modulo valida l'header, vmalloc() la tabella, sostituisce via RCU
 *   4. L'XDP program chiama bpf_xdp_ac_scan(xdp_md, db_id, offset, len)
 *
 * Configfs: /sys/kernel/config/ac/<policy>/
 *   database    (rw binary)  — file .acdb
 *   id          (rw)         — ID numerico usato dall'XDP program
 *   epoch       (ro)         — incrementa ad ogni caricamento
 *   state_count (ro)         — stati nel DFA caricato
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/idr.h>
#include <linux/rcupdate.h>
#include <linux/configfs.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <net/xdp.h>
#include <linux/skbuff.h>
#include <asm/unaligned.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("evalNet AC filter");
MODULE_DESCRIPTION("Aho-Corasick DFA kfunc per XDP — confronto con Hyperscan");

static ulong max_db_size = 200 << 20;   /* 200 MB default */
module_param(max_db_size, ulong, 0644);
MODULE_PARM_DESC(max_db_size, "Dimensione massima upload .acdb (default 200 MB)");

/*
 * Rate limiter per-CPU: limita quanti pacchetti al secondo vengono scansionati
 * e potenzialmente droppati da XDP. Quando la finestra è esaurita il kfunc
 * restituisce -EBUSY → il programma XDP ottiene ret<0 → XDP_PASS (Suricata).
 *
 * 0 = illimitato (default).
 * Modificabile a caldo: echo 500000 > /sys/module/xdp_ac_module/parameters/max_scan_pps
 */
static ulong max_scan_pps __read_mostly = 0;
module_param(max_scan_pps, ulong, 0644);
MODULE_PARM_DESC(max_scan_pps, "Max pacchetti/sec scansionati per CPU (0=illimitato)");


struct ac_rate_state {
	u64 window_start_ns;
	u64 count;
};
static DEFINE_PER_CPU(struct ac_rate_state, ac_rate);

/* ── Strutture dati ─────────────────────────────────────────────────────── */

/*
 * Header del file .acdb versione 2: 64 byte (vedi ac_build.c).
 *
 * Layout file: header || class_map[256] u8 || output[N] u8 || pad(8) ||
 *              next[N][stride] u16|u32
 */
struct ac_file_header {
	u8  magic[4];        /* "ACDB"                                */
	u32 version;         /* 2                                     */
	u32 num_states;
	u32 flags;           /* riservato                             */
	u32 state_size;      /* byte per entry di next[]: 2 o 4       */
	u32 num_patterns;
	u32 num_skipped;
	u32 min_len;
	u32 num_classes;     /* classi di equivalenza alfabeto reali  */
	u32 stride;          /* colonne per riga (pow2 ≥ num_classes) */
	u32 shift;           /* log2(stride)                          */
	u32 trunc;           /* troncamento pattern usato in build    */
	u32 pf_bits_long;    /* log2 bit di T1/T2 (0 = no prefiltro)  */
	u32 pf_bits_short;   /* log2 bit di ogni TS4..TS7             */
	u8  pad[8];
} __packed;

/* Costanti hash del prefiltro — devono combaciare con ac_build.c */
#define PF_HASH1  0x9E3779B1u
#define PF_HASH2  0x85EBCA6Bu

/*
 * Database AC in memoria kernel (formato v2 compresso):
 *
 *   data[0..255]      class_map[256]  byte payload → classe (case-fold incluso)
 *   data[256..256+N)  output[N]       u8, 1 = stato terminale
 *   data[next_off..]  next[N][stride] u16 (entry16=1) o u32
 *
 * Working set: N × stride × entry ≈ 16-30 MB con troncamento pattern,
 * contro i 163 MB del vecchio formato denso u32×256. Le righe da 512 B
 * degli stati "caldi" vicino alla radice restano in L1/L2.
 *
 * La scan non fa tolower(): il case-folding è precalcolato nella class_map.
 */
struct ac_db {
	u32 num_states;
	u32 shift;      /* log2(colonne per riga) */
	u32 entry16;    /* 1 = next[] in u16, 0 = u32 */
	u32 next_off;   /* offset byte di next[] dentro data[] */
	u32 pf_off;     /* offset byte di T1 dentro data[] (0 = no prefiltro) */
	u32 pf_shift_l; /* 32 - pf_bits_long  */
	u32 pf_shift_s; /* 32 - pf_bits_short */
	u8  data[];
};

static inline const u8 *ac_db_class(const struct ac_db *db)
{ return db->data; }

static inline const u8 *ac_db_output(const struct ac_db *db)
{ return db->data + 256; }

static inline const void *ac_db_next(const struct ac_db *db)
{ return db->data + db->next_off; }

/* Policy (una entry in /sys/kernel/config/ac/<name>/) */
struct ac_policy {
	u32                  id;
	u32                  epoch;
	struct mutex         lock;
	struct ac_db __rcu  *db;
	struct config_item   item;
};

/* ── IDR per lookup O(1) per database_id ───────────────────────────────── */
static DEFINE_IDR(ac_idr);
static DEFINE_MUTEX(ac_config_mutex);

/* ── Estrazione puntatore dalla xdp_buff ───────────────────────────────── */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
static void *xdp_pointer(const struct xdp_buff *xdp, u32 offset, u32 len)
{
	u32 size = xdp->data_end - xdp->data;

	if (unlikely(offset > 0xffff || len > 0xffff))
		return ERR_PTR(-EFAULT);
	if (offset + len > size)
		return ERR_PTR(-EINVAL);
	return xdp->data + offset;
}
#else
static void *xdp_pointer(const struct xdp_buff *xdp, u32 offset, u32 len)
{
	u32 size = xdp->data_end - xdp->data;
	void *addr = xdp->data;
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	int i;

	if (unlikely(offset > 0xffff || len > 0xffff))
		return ERR_PTR(-EFAULT);
	if (offset > xdp_get_buff_len(xdp))
		return ERR_PTR(-EINVAL);
	if (offset < size)
		goto out;

	offset -= size;
	for (i = 0; i < sinfo->nr_frags; i++) {
		u32 frag_size = skb_frag_size(&sinfo->frags[i]);

		if (offset < frag_size) {
			addr = skb_frag_address(&sinfo->frags[i]);
			size = frag_size;
			break;
		}
		offset -= frag_size;
	}
out:
	return offset <= size ? addr + offset : ERR_PTR(-EINVAL);
}
#endif

/* ── Scan loop ──────────────────────────────────────────────────────────── */

/* Test di un bit in una bitmap bit-packed. */
static inline int pf_bit(const u8 *bm, u32 h)
{
	return bm[h >> 3] & (1u << (h & 7));
}

/*
 * Prefiltro n-gram: ritorna 1 se il payload contiene un candidato
 * (il DFA deve confermare), 0 se sicuramente pulito.
 *
 * A differenza del DFA, il test per posizione non dipende da alcuno stato:
 * la CPU out-of-order tiene in volo decine di lookup contemporaneamente,
 * quindi le latenze dei load si sovrappongono invece di sommarsi.
 * Solo aritmetica intera: niente kernel_fpu_begin/end.
 *
 * Percorso comune (T1 miss, ~99.8% delle posizioni): load32 payload,
 * OR fold, mul, shift, 1 load bitmap, test. Le conferme T2/TS4..TS7
 * girano solo su T1 hit.
 */
static int ac_prefilter(const struct ac_db *db, const u8 *buf, u32 len)
{
	const u8 *t1      = db->data + db->pf_off;
	u32       sz_long = 1u << (32 - db->pf_shift_l - 3);
	u32       sz_shrt = 1u << (32 - db->pf_shift_s - 3);
	const u8 *t2      = t1 + sz_long;
	const u8 *ts      = t2 + sz_long;   /* TS4 || TS5 || TS6 || TS7 */
	u32       i;

	if (len < 4)
		return 0;

	for (i = 0; i + 4 <= len; i++) {
		u32 w = get_unaligned_le32(buf + i) | 0x20202020u;
		u32 v, L;

		if (likely(!pf_bit(t1, (w * PF_HASH1) >> db->pf_shift_l)))
			continue;

		/* T1 hit — conferma pattern lunghi (byte 4..7). */
		if (i + 8 <= len) {
			u32 w2 = get_unaligned_le32(buf + i + 4) | 0x20202020u;

			if (pf_bit(t2, (w2 * PF_HASH2) >> db->pf_shift_l))
				return 1;
		}

		/* Conferma pattern corti: hash dell'intera stringa len 4..7. */
		v = w;
		if (pf_bit(ts, (v * PF_HASH1) >> db->pf_shift_s))
			return 1;
		for (L = 5; L <= 7; L++) {
			if (i + L > len)
				break;
			v = ((v << 5) | (v >> 27)) + (u32)(buf[i + L - 1] | 0x20);
			if (pf_bit(ts + (L - 4) * sz_shrt,
				   (v * PF_HASH1) >> db->pf_shift_s))
				return 1;
		}
	}
	return 0;
}

/*
 * Scansiona len byte contro il DFA compresso (v2).
 * Ritorna 1 se almeno un pattern matcha, 0 altrimenti.
 *
 * Catena critica per byte: class_map[buf[i]] è indipendente dallo stato
 * (l'out-of-order la calcola in anticipo), quindi il percorso dipendente è
 * solo shift + load di next[] — ~5-6 cicli/byte se la riga è in L1.
 */
static int ac_scan(const struct ac_db *db, const u8 *buf, u32 len)
{
	const u8  *cls    = ac_db_class(db);
	const u8  *output = ac_db_output(db);
	u32        shift  = db->shift;
	u32        state  = 0;
	u32        i;

	/* Prefiltro: se nessun n-gramma candidato, il DFA non può matchare. */
	if (db->pf_off && !ac_prefilter(db, buf, len))
		return 0;

	if (db->entry16) {
		const u16 *next = ac_db_next(db);

		for (i = 0; i < len; i++) {
			state = next[(state << shift) + cls[buf[i]]];
			if (unlikely(output[state]))
				return 1;
		}
	} else {
		const u32 *next = ac_db_next(db);

		for (i = 0; i < len; i++) {
			state = next[(state << shift) + cls[buf[i]]];
			if (unlikely(output[state]))
				return 1;
		}
	}
	return 0;
}

/* ── kfunc: bpf_xdp_ac_scan ────────────────────────────────────────────── */

/*
 * Kfunc chiamabile da programmi XDP.
 *
 * @xdp_md  : contesto XDP (cast a xdp_buff internamente)
 * @db_id   : ID del database AC (impostato via configfs /id)
 * @offset  : byte offset dall'inizio del frame XDP al payload da scansionare
 * @len     : numero di byte da scansionare
 *
 * Ritorna:
 *   1   → match trovato
 *   0   → nessun match
 *   <0  → errore (db non trovato, offset fuori range, etc.)
 */
__bpf_kfunc int bpf_xdp_ac_scan(const struct xdp_md *xdp_md,
				  u32 db_id, u32 offset, u32 len)
{
	struct xdp_buff *xdp = (struct xdp_buff *)xdp_md;
	struct ac_policy *pol;
	struct ac_db *db;
	void *ptr;
	int ret;

	if (unlikely(!xdp_md || len == 0))
		return -EINVAL;

	/* ── Rate limiter per-CPU ──────────────────────────────────────────── */
	if (max_scan_pps > 0) {
		struct ac_rate_state *rs = this_cpu_ptr(&ac_rate);
		u64 now = ktime_get_ns();

		if (now - rs->window_start_ns >= NSEC_PER_SEC) {
			/* Nuova finestra: reset contatore */
			rs->window_start_ns = now;
			rs->count = 0;
		}

		if (rs->count >= max_scan_pps)
			return -EBUSY;   /* quota esaurita → XDP_PASS in prog */

		rs->count++;
	}
	/* ─────────────────────────────────────────────────────────────────── */

	rcu_read_lock();

	pol = idr_find(&ac_idr, db_id);
	if (unlikely(!pol)) {
		rcu_read_unlock();
		return -EBADF;
	}

	db = rcu_dereference(pol->db);
	if (unlikely(!db)) {
		rcu_read_unlock();
		return -ENODATA;
	}

	ptr = xdp_pointer(xdp, offset, len);
	if (IS_ERR(ptr)) {
		rcu_read_unlock();
		return PTR_ERR(ptr);
	}

	ret = ac_scan(db, (const u8 *)ptr, len);

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(bpf_xdp_ac_scan);

/* ── Registrazione kfunc BTF ────────────────────────────────────────────── */

BTF_SET8_START(ac_xdp_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_ac_scan, KF_RET_NULL)
BTF_SET8_END(ac_xdp_kfunc_set)

static const struct btf_kfunc_id_set ac_xdp_kfunc_ids = {
	.owner = THIS_MODULE,
	.set   = &ac_xdp_kfunc_set,
};

/* ── Gestione database (caricamento / rilascio) ──────────────────────────── */

static void ac_assign_db(struct ac_policy *pol, struct ac_db *new_db)
{
	struct ac_db *old;

	old = rcu_replace_pointer(pol->db, new_db,
				  lockdep_is_held(&ac_config_mutex));
	pol->epoch++;

	if (old) {
		synchronize_rcu();
		vfree(old);
	}
}

/* ── Configfs: attributi ────────────────────────────────────────────────── */

static struct ac_policy *item_to_pol(struct config_item *item)
{
	return item ? container_of(item, struct ac_policy, item) : NULL;
}

/* --- database (rw binary): carica il file .acdb --- */

static ssize_t accfg_database_write(struct config_item *item,
				    const void *buf, size_t nbytes)
{
	struct ac_policy *pol = item_to_pol(item);
	const struct ac_file_header *hdr;
	struct ac_db *db;
	size_t expected, db_size;

	/* Scrittura vuota = rimuovi il database corrente. */
	if (nbytes == 0) {
		mutex_lock(&ac_config_mutex);
		ac_assign_db(pol, NULL);
		mutex_unlock(&ac_config_mutex);
		pr_info("ac: policy '%s': database rimosso\n",
			config_item_name(&pol->item));
		return 0;
	}

	/* Valida header. */
	if (nbytes < sizeof(*hdr)) {
		pr_err("ac: upload troppo piccolo (%zu byte)\n", nbytes);
		return -EINVAL;
	}
	hdr = (const struct ac_file_header *)buf;

	if (memcmp(hdr->magic, "ACDB", 4) != 0) {
		pr_err("ac: magic non valido (atteso 'ACDB')\n");
		return -EINVAL;
	}
	if (hdr->version != 2) {
		pr_err("ac: versione %u non supportata (serve v2 — rigenera con ac_build aggiornato)\n",
		       hdr->version);
		return -EINVAL;
	}
	if (hdr->state_size != 2 && hdr->state_size != 4) {
		pr_err("ac: state_size=%u, atteso 2 o 4\n", hdr->state_size);
		return -EINVAL;
	}
	if (hdr->num_states == 0 || hdr->num_states > 16000000) {
		pr_err("ac: num_states=%u fuori range\n", hdr->num_states);
		return -EINVAL;
	}
	if (hdr->state_size == 2 && hdr->num_states > 65535) {
		pr_err("ac: %u stati non indirizzabili con entry u16\n",
		       hdr->num_states);
		return -EINVAL;
	}
	if (hdr->stride == 0 || hdr->stride > 256 ||
	    hdr->stride != (1u << hdr->shift) ||
	    hdr->num_classes == 0 || hdr->num_classes > hdr->stride) {
		pr_err("ac: stride/shift/num_classes incoerenti (%u/%u/%u)\n",
		       hdr->stride, hdr->shift, hdr->num_classes);
		return -EINVAL;
	}
	if (hdr->pf_bits_long &&
	    (hdr->pf_bits_long < 10 || hdr->pf_bits_long > 28 ||
	     hdr->pf_bits_short < 10 || hdr->pf_bits_short > 28)) {
		pr_err("ac: pf_bits fuori range (%u/%u)\n",
		       hdr->pf_bits_long, hdr->pf_bits_short);
		return -EINVAL;
	}

	{
		const u32 N        = hdr->num_states;
		const u32 esz      = hdr->state_size;
		size_t    file_pad = (8 - ((sizeof(*hdr) + 256 + (size_t)N) & 7)) & 7;
		size_t    tbl_size = (size_t)N * hdr->stride * esz;
		size_t    pf_size  = 0;
		const u8 *f_class  = (const u8 *)buf + sizeof(*hdr);
		const u8 *f_output = f_class + 256;
		const u8 *f_next   = f_output + N + file_pad;
		u32       next_off, s;

		if (hdr->pf_bits_long)
			pf_size = 2 * (((size_t)1 << hdr->pf_bits_long) / 8) +
				  4 * (((size_t)1 << hdr->pf_bits_short) / 8);

		expected = sizeof(*hdr) + 256 + (size_t)N + file_pad +
			   tbl_size + pf_size;
		if (nbytes != expected) {
			pr_err("ac: dimensione attesa %zu, ricevuta %zu\n",
			       expected, nbytes);
			return -EINVAL;
		}

		/* class_map: ogni valore deve indicizzare una colonna valida. */
		for (s = 0; s < 256; s++) {
			if (f_class[s] >= hdr->num_classes) {
				pr_err("ac: class_map[%u]=%u >= num_classes\n",
				       s, f_class[s]);
				return -EINVAL;
			}
		}

		/* next[] in runtime allineato a 8 dopo class_map+output. */
		next_off = ALIGN(256 + N, 8);
		db_size  = sizeof(struct ac_db) + next_off + tbl_size + pf_size;
		db = vmalloc(db_size);
		if (!db)
			return -ENOMEM;

		db->num_states = N;
		db->shift      = hdr->shift;
		db->entry16    = (esz == 2);
		db->next_off   = next_off;
		if (pf_size) {
			db->pf_off     = next_off + tbl_size;
			db->pf_shift_l = 32 - hdr->pf_bits_long;
			db->pf_shift_s = 32 - hdr->pf_bits_short;
		} else {
			db->pf_off     = 0;
			db->pf_shift_l = 0;
			db->pf_shift_s = 0;
		}

		memcpy(db->data, f_class, 256);
		memcpy(db->data + 256, f_output, N);
		memset(db->data + 256 + N, 0, next_off - 256 - N);
		memcpy(db->data + next_off, f_next, tbl_size);
		if (pf_size)
			memcpy(db->data + db->pf_off, f_next + tbl_size, pf_size);

		/* Valida ogni transizione: la scan non ha bounds check. */
		{
			size_t n_ent = (size_t)N * hdr->stride, e;
			int    bad   = 0;

			if (esz == 2) {
				const u16 *t = (const u16 *)(db->data + next_off);

				for (e = 0; e < n_ent; e++)
					if (t[e] >= N) { bad = 1; break; }
			} else {
				const u32 *t = (const u32 *)(db->data + next_off);

				for (e = 0; e < n_ent; e++)
					if (t[e] >= N) { bad = 1; break; }
			}
			if (bad) {
				pr_err("ac: transizione fuori range nel .acdb\n");
				vfree(db);
				return -EINVAL;
			}
		}

		mutex_lock(&ac_config_mutex);
		ac_assign_db(pol, db);
		mutex_unlock(&ac_config_mutex);

		pr_info("ac: policy '%s': %u stati, %u classi (stride %u, u%u), trunc=%u, tabella %zu KB, prefiltro %zu KB, %u pattern\n",
			config_item_name(&pol->item),
			N, hdr->num_classes, hdr->stride, esz * 8,
			hdr->trunc, tbl_size >> 10, pf_size >> 10,
			hdr->num_patterns);
	}
	return (ssize_t)nbytes;
}

static ssize_t accfg_database_read(struct config_item *item,
				   void *outbuf, size_t size)
{
	/* Lettura non supportata: il file .acdb viene tenuto solo in userspace. */
	return 0;
}

/* --- id (rw) --- */
static ssize_t accfg_id_show(struct config_item *item, char *str)
{
	return snprintf(str, PAGE_SIZE, "%u\n", item_to_pol(item)->id);
}

static ssize_t accfg_id_store(struct config_item *item,
			      const char *str, size_t len)
{
	struct ac_policy *pol = item_to_pol(item);
	u32 new_id;
	int ret;

	ret = kstrtou32(str, 0, &new_id);
	if (ret)
		return -EINVAL;

	mutex_lock(&ac_config_mutex);
	if (pol->id != new_id) {
		ret = idr_alloc(&ac_idr, pol, new_id, new_id + 1, GFP_KERNEL);
		if (ret < 0)
			goto out;
		idr_remove(&ac_idr, pol->id);
		pol->id = new_id;
	}
	ret = (int)len;
out:
	mutex_unlock(&ac_config_mutex);
	return ret;
}

/* --- epoch (ro) --- */
static ssize_t accfg_epoch_show(struct config_item *item, char *str)
{
	return snprintf(str, PAGE_SIZE, "%u\n", item_to_pol(item)->epoch);
}

/* --- state_count (ro) --- */
static ssize_t accfg_state_count_show(struct config_item *item, char *str)
{
	struct ac_policy *pol = item_to_pol(item);
	struct ac_db *db;
	u32 n = 0;

	rcu_read_lock();
	db = rcu_dereference(pol->db);
	if (db)
		n = db->num_states;
	rcu_read_unlock();

	return snprintf(str, PAGE_SIZE, "%u\n", n);
}

/* --- stat (ro): dimensioni DB caricato --- */
static ssize_t accfg_stat_show(struct config_item *item, char *str)
{
	struct ac_policy *pol = item_to_pol(item);
	struct ac_db *db;
	ssize_t ret;

	rcu_read_lock();
	db = rcu_dereference(pol->db);
	if (!db) {
		ret = snprintf(str, PAGE_SIZE, "nessun database caricato\n");
	} else {
		u32 stride = 1u << db->shift;
		u32 esz    = db->entry16 ? 2 : 4;
		u64 tbl_kb = ((u64)db->num_states * stride * esz) / 1024;
		u64 pf_kb  = 0;

		if (db->pf_off)
			pf_kb = (2 * (1ULL << (32 - db->pf_shift_l)) +
				 4 * (1ULL << (32 - db->pf_shift_s))) / 8 / 1024;

		ret = snprintf(str, PAGE_SIZE,
			       "stati=%u stride=%u entry=u%u riga=%u B tabella=%llu KB prefiltro=%llu KB\n",
			       db->num_states, stride, esz * 8,
			       stride * esz, tbl_kb, pf_kb);
	}
	rcu_read_unlock();
	return ret;
}

/* ── Configfs: dichiarazione attributi ─────────────────────────────────── */

CONFIGFS_BIN_ATTR(accfg_, database, NULL, 0);   /* max size impostato in make_item */
CONFIGFS_ATTR(accfg_, id);
CONFIGFS_ATTR_RO(accfg_, epoch);
CONFIGFS_ATTR_RO(accfg_, state_count);
CONFIGFS_ATTR_RO(accfg_, stat);

static struct configfs_attribute *ac_attrs[] = {
	&accfg_attr_id,
	&accfg_attr_epoch,
	&accfg_attr_state_count,
	&accfg_attr_stat,
	NULL,
};

static struct configfs_bin_attribute *ac_bin_attrs[] = {
	&accfg_attr_database,
	NULL,
};

/* ── Configfs: lifecycle policy ─────────────────────────────────────────── */

static void accfg_item_release(struct config_item *item)
{
	struct ac_policy *pol = item_to_pol(item);

	mutex_lock(&ac_config_mutex);
	idr_remove(&ac_idr, pol->id);
	ac_assign_db(pol, NULL);
	mutex_unlock(&ac_config_mutex);
	kfree(pol);
}

static const struct configfs_item_operations ac_item_ops = {
	.release = accfg_item_release,
};

static const struct config_item_type ac_item_type = {
	.ct_owner    = THIS_MODULE,
	.ct_attrs    = ac_attrs,
	.ct_bin_attrs= ac_bin_attrs,
	.ct_item_ops = &ac_item_ops,
};

static struct config_item *ac_make_item(struct config_group *group,
					const char *name)
{
	struct ac_policy *pol;
	int id;

	pol = kzalloc(sizeof(*pol), GFP_KERNEL);
	if (!pol)
		return ERR_PTR(-ENOMEM);

	mutex_init(&pol->lock);

	mutex_lock(&ac_config_mutex);
	accfg_attr_database.cb_max_size = max_db_size;
	config_item_init_type_name(&pol->item, name, &ac_item_type);
	id = idr_alloc(&ac_idr, pol, 0, U32_MAX, GFP_KERNEL);
	if (id < 0) {
		mutex_unlock(&ac_config_mutex);
		kfree(pol);
		return ERR_PTR(id);
	}
	pol->id = id;
	mutex_unlock(&ac_config_mutex);

	pr_info("ac: nuova policy '%s' id=%d\n", name, id);
	return &pol->item;
}

static const struct configfs_group_operations ac_group_ops = {
	.make_item = ac_make_item,
};

static const struct config_item_type ac_group_type = {
	.ct_owner     = THIS_MODULE,
	.ct_group_ops = &ac_group_ops,
};

static struct configfs_subsystem ac_configfs = {
	.su_mutex = __MUTEX_INITIALIZER(ac_configfs.su_mutex),
	.su_group = {
		.cg_item = {
			.ci_namebuf = "ac",
			.ci_type    = &ac_group_type,
		},
	},
};

/* ── Init / Exit ────────────────────────────────────────────────────────── */

static int __init ac_module_init(void)
{
	int err;

	config_group_init(&ac_configfs.su_group);
	err = configfs_register_subsystem(&ac_configfs);
	if (err) {
		pr_err("ac: configfs_register_subsystem failed: %d\n", err);
		return err;
	}

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &ac_xdp_kfunc_ids);
	if (err) {
		configfs_unregister_subsystem(&ac_configfs);
		pr_err("ac: register_btf_kfunc_id_set failed: %d\n", err);
		return err;
	}

	pr_info("ac: modulo caricato — configfs su /sys/kernel/config/ac/\n");
	pr_info("ac: kfunc bpf_xdp_ac_scan() registrato per BPF_PROG_TYPE_XDP\n");
	return 0;
}

static void __exit ac_module_exit(void)
{
	configfs_unregister_subsystem(&ac_configfs);
	pr_info("ac: modulo rimosso\n");
}

module_init(ac_module_init);
module_exit(ac_module_exit);
