
/** A wrapper around hs_database_t where we may store additional fields. */
struct rex_database {
	void **scratch;  /* array[num_possible_cpus()] of kmalloc'd hs_scratch_t* */
	u8 bytes[] __aligned(8);
};
/**
 * Represent a configurable hyperscan database.
 * @id:		Handle used by BPF programs from rex_scan_bytes() kfunc (rw).
 * @epoch:	Sequential number which may be used to detect changes (ro).
 * @note:	An arbitrary user string (rw).
 * @database:	Compiled database binary (rw).
 *
 * Contains other derived read-only parameters:
 * /info:	Brief database description.
 *
 */
struct rex_policy {
	u32 id;
	u32 epoch;
	struct mutex lock;
	struct rex_database __rcu *database;
	struct config_item item;
	char note[PAGE_SIZE];
};

struct rex_scan_ctx {
	struct rex_scan_attr *attr;
	const void *block;
	size_t block_len;
};

