/*
 * libFuzzer harness for FEMU's KV-SSD LSM-tree index (hw/femu/kvssd/kv-lsm.c).
 * The input is the tree geometry and the free-page budget, then a stream of put / delete / get / scan /
 * compact / value-GC / meta-page-GC operations. Every answer is checked against a plain-array model of
 * the newest state of each key, and the page callbacks are checked for double allocation and double free.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayhem/femu_fuzz_input.h"
#include "hw/femu/kvssd/kv-lsm.h"

#define MAX_KEYS  512
#define MAX_OPS   4096
#define MAX_PAGES 4096

typedef struct { uint8_t key[KV_LSM_KEY_MAX]; uint8_t kl; uint32_t slot; } MKey;

static MKey model[MAX_KEYS];
static uint32_t mnr;
static uint32_t next_slot;

static uint64_t held[MAX_PAGES];      /* meta pages the tree owns, as alloc/free_page saw them */
static uint32_t nheld;
static uint64_t next_page;
static int64_t budget;                /* free pages left; < 0 = unlimited */

static bool cb_room(void *o, uint64_t pages)
{
    (void)o;
    return budget < 0 || (uint64_t)budget >= pages;
}

static bool cb_alloc(void *o, int level, uint64_t *id)
{
    (void)o;
    if (level < 1 || level > KV_LSM_MAX_LEVELS || nheld == MAX_PAGES || !budget) {
        return false;
    }
    if (budget > 0) {
        budget--;
    }
    *id = held[nheld++] = next_page++;
    return true;
}

static void cb_free(void *o, uint64_t id)
{
    (void)o;
    for (uint32_t i = 0; i < nheld; i++) {
        if (held[i] == id) {
            held[i] = held[--nheld];
            if (budget >= 0) {
                budget++;
            }
            return;
        }
    }
    abort();                          /* freed a page the tree never held */
}

static void cb_io(void *o, uint64_t id, KvLsmIo io, int level)
{
    (void)o;
    if ((int)io < 0 || io >= KV_LSM_IO_NR || level < 1 || level > KV_LSM_MAX_LEVELS) {
        abort();
    }
    (void)id;
}

static void cb_drop(void *o, uint32_t slot) { (void)o; (void)slot; }

static int kcmp(const uint8_t *a, uint8_t al, const uint8_t *b, uint8_t bl)
{
    int c = memcmp(a, b, al < bl ? al : bl);

    return c ? c : (al > bl) - (al < bl);
}

static int mfind(const uint8_t *k, uint8_t kl)
{
    for (uint32_t i = 0; i < mnr; i++) {
        if (model[i].kl == kl && !memcmp(model[i].key, k, kl)) {
            return (int)i;
        }
    }
    return -1;
}

static void mset(const uint8_t *k, uint8_t kl, uint32_t slot)
{
    int i = mfind(k, kl);

    if (i < 0) {
        i = (int)mnr++;
        memcpy(model[i].key, k, kl);
        model[i].kl = kl;
    }
    model[i].slot = slot;
}

/* a key: an existing one, or kl raw bytes from the input */
static uint8_t read_key(FuzzIn *in, uint8_t *k)
{
    uint8_t sel = fi_u8(in);
    uint8_t kl;

    if ((sel & 1) && mnr) {
        MKey *m = &model[fi_u16(in) % mnr];

        memcpy(k, m->key, m->kl);
        return m->kl;
    }
    kl = 1 + (sel >> 1) % KV_LSM_KEY_MAX;
    for (uint8_t i = 0; i < kl; i++) {
        k[i] = fi_u8(in);
    }
    return kl;
}

typedef struct { uint32_t n, limit; int phase; uint8_t prev[KV_LSM_KEY_MAX]; uint8_t pl;
                 const uint8_t *start; uint8_t sl; } Scan;

static bool scan_fn(void *o, const uint8_t *k, uint8_t kl, uint32_t slot)
{
    Scan *s = o;
    int i = mfind(k, kl);
    bool ge = kcmp(k, kl, s->start, s->sl) >= 0;

    if (i < 0 || model[i].slot == KV_LSM_NO_SLOT || model[i].slot != slot) {
        abort();                      /* a key the model does not hold live */
    }
    if (s->n) {
        if (s->phase == 0 && !ge) {
            s->phase = 1;             /* wrapped to the keys below the start */
        } else if ((s->phase == 1 && ge) || kcmp(k, kl, s->prev, s->pl) <= 0) {
            abort();                  /* out of byte order */
        }
    } else if (!ge) {
        s->phase = 1;
    }
    memcpy(s->prev, k, kl);
    s->pl = kl;
    return ++s->n < s->limit;
}

static void check_get(KvLsm *l, const uint8_t *k, uint8_t kl, bool charge)
{
    uint32_t slot = 0;
    int i = mfind(k, kl);
    bool want = i >= 0 && model[i].slot != KV_LSM_NO_SLOT;

    if (kv_lsm_get(l, k, kl, &slot, charge) != want || (want && slot != model[i].slot)) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzIn in = { data, size };
    KvLsmOps ops = { .io = cb_io, .room = cb_room, .alloc = cb_alloc, .free_page = cb_free, .drop = cb_drop };
    uint32_t mem_cap = 1 + fi_u8(&in) % 64;
    uint32_t ratio = 2 + fi_u8(&in) % 6;
    uint32_t pinned = fi_u8(&in) % (KV_LSM_MAX_LEVELS + 1);
    uint32_t per_page = 1 + fi_u8(&in) % 32;
    uint8_t b = fi_u8(&in);
    KvLsm l;

    budget = b < 64 ? -1 : b - 64;
    mnr = nheld = 0;
    next_slot = 1;
    next_page = 1;
    if (kv_lsm_init(&l, mem_cap, ratio, pinned, per_page, &ops, NULL)) {
        return 0;
    }
    for (int n = 0; n < MAX_OPS && !fi_eof(&in); n++) {
        uint8_t k[KV_LSM_KEY_MAX], k2[KV_LSM_KEY_MAX];
        uint8_t op = fi_u8(&in) % 10, kl;

        if (mnr + 1 >= MAX_KEYS && op <= 3) {
            op = 4;
        }
        switch (op) {
        case 0: case 1:               /* put: on failure the tree is as it was */
            kl = read_key(&in, k);
            if (kv_lsm_put(&l, k, kl, next_slot) == 0) {
                mset(k, kl, next_slot);
            }
            next_slot++;
            break;
        case 2: case 3:               /* delete: the memtable keeps a tombstone even when the flush fails */
            kl = read_key(&in, k);
            if (kv_lsm_put_tombstone(&l, k, kl)) {
                abort();
            }
            if (mfind(k, kl) >= 0) {
                mset(k, kl, KV_LSM_NO_SLOT);
            }
            break;
        case 4:
            kl = read_key(&in, k);
            check_get(&l, k, kl, fi_u8(&in) & 1);
            break;
        case 5: {                     /* scan from a start key, optionally stopping early */
            Scan s = { .limit = fi_u8(&in) ? 1 + fi_u8(&in) : UINT32_MAX };
            uint32_t live = 0;

            s.sl = read_key(&in, k2);
            s.start = k2;
            if (kv_lsm_scan(&l, k2, s.sl, scan_fn, &s)) {
                break;
            }
            for (uint32_t i = 0; i < mnr; i++) {
                live += model[i].slot != KV_LSM_NO_SLOT;
            }
            if (s.limit == UINT32_MAX ? s.n != live : s.n > live || s.n > s.limit) {
                abort();
            }
            break;
        }
        case 6:
            (void)kv_lsm_compact_all(&l);
            break;
        case 7: {                     /* value GC: check up to three keys, then move the ones in flash back */
            uint8_t cnt = 1 + fi_u8(&in) % 3;
            uint8_t ks[3][KV_LSM_KEY_MAX], kls[3];
            bool back[3];
            uint32_t slot, slots[3];

            if (kv_lsm_gc_begin(&l)) {
                break;
            }
            for (uint8_t i = 0; i < cnt; i++) {
                int m;

                kls[i] = read_key(&in, ks[i]);
                back[i] = kv_lsm_gc_check(&l, ks[i], kls[i], &slot);
                slots[i] = slot;
                m = mfind(ks[i], kls[i]);
                if (slot != (m >= 0 ? model[m].slot : KV_LSM_NO_SLOT)) {
                    abort();
                }
            }
            kv_lsm_gc_check_done(&l);
            for (uint8_t i = 0; i < cnt; i++) {
                if (back[i] && slots[i] != KV_LSM_NO_SLOT && mfind(ks[i], kls[i]) >= 0 &&
                    kv_lsm_reinsert(&l, ks[i], kls[i], slots[i]) == 0) {
                    mset(ks[i], kls[i], slots[i]);
                }
            }
            break;
        }
        case 8:                       /* meta page GC moves a page */
            if (nheld) {
                uint32_t i = fi_u16(&in) % nheld;

                if (!kv_lsm_relocate(&l, held[i], next_page)) {
                    abort();          /* a page the tree holds must be named by a level list */
                }
                held[i] = next_page++;
            } else if (kv_lsm_relocate(&l, next_page + 100, next_page)) {
                abort();
            }
            break;
        case 9:
            if (fi_u8(&in) & 1) {     /* reset the tree and the flash under it */
                kv_lsm_clear(&l);
                mnr = nheld = 0;
                budget = b < 64 ? -1 : b - 64;
            } else {
                (void)kv_lsm_records(&l);
                (void)kv_lsm_dram_bytes(&l);
                (void)kv_lsm_depth(&l);
                (void)kv_lsm_level_cap(&l, 1 + fi_u8(&in) % KV_LSM_MAX_LEVELS);
            }
            break;
        }
    }
    for (uint32_t i = 0; i < mnr; i++) {
        check_get(&l, model[i].key, model[i].kl, false);
    }
    kv_lsm_destroy(&l);
    return 0;
}
