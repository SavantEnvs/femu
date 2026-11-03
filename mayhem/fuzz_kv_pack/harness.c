/*
 * libFuzzer harness for FEMU's KV-SSD packed page header (hw/femu/kvssd/kv-pack.c).
 * The input is a page size followed by a stream of append/drop/find/compact operations; every step is
 * checked against a plain-array model of the page.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayhem/femu_fuzz_input.h"
#include "hw/femu/kvssd/kv-pack.h"

#define MAX_ITEMS 512
#define MAX_OPS   2048

typedef struct { uint64_t owner; uint32_t off, len; bool live; } M;

static M model[MAX_ITEMS];
static uint32_t mnr, mfill;

static struct { uint64_t owner; uint32_t off; } moved_log[MAX_ITEMS];
static uint32_t moved_nr;

static void moved(void *opaque, uint64_t owner, uint32_t off)
{
    (void)opaque;
    if (moved_nr >= MAX_ITEMS) {
        abort();
    }
    moved_log[moved_nr].owner = owner;
    moved_log[moved_nr].off = off;
    moved_nr++;
}

static void check(const KvPackPage *pg)
{
    uint32_t live = 0;
    uint64_t bytes = 0;

    if (pg->nr != mnr || pg->fill != mfill) {
        abort();
    }
    for (uint32_t i = 0; i < mnr; i++) {
        const KvPackItem *it = &pg->item[i];

        if (it->owner != model[i].owner || it->off != model[i].off ||
            it->len != model[i].len || it->live != model[i].live) {
            abort();
        }
        if (model[i].live) {
            live++;
            bytes += kv_pack_rec(model[i].len);
        }
    }
    if (pg->live != live || pg->live_bytes != bytes) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzIn in = { data, size };
    uint32_t pgsz = 64 + fi_u16(&in) % 16384;
    KvPackPage *pg = kv_pack_new();
    uint64_t owner = 0;

    if (!pg) {
        return 0;
    }
    mnr = 0;
    mfill = 0;
    for (int ops = 0; ops < MAX_OPS && !fi_eof(&in); ops++) {
        uint8_t op = fi_u8(&in) % 6;

        switch (op) {
        case 0: {                       /* append, only when the record fits, as the FTL checks */
            uint32_t len = fi_u16(&in) % (pgsz + 1);
            uint32_t off = 0;
            bool fits = kv_pack_fits(pg, len, pgsz);

            if (fits != (mfill <= pgsz && kv_pack_rec(len) <= pgsz - mfill)) {
                abort();
            }
            if (!fits || mnr == MAX_ITEMS) {
                break;
            }
            if (kv_pack_append(pg, owner, len, &off) || off != mfill) {
                abort();
            }
            model[mnr++] = (M){ owner++, off, len, true };
            mfill += kv_pack_rec(len);
            break;
        }
        case 1: {                       /* drop */
            uint32_t i;
            uint32_t want;

            if (!mnr) {
                break;
            }
            i = fi_u16(&in) % mnr;
            want = model[i].live ? kv_pack_rec(model[i].len) : 0;
            if (kv_pack_drop(pg, (int)i) != want) {
                abort();
            }
            model[i].live = false;
            break;
        }
        case 2: {                       /* find an offset: a record start, or any byte */
            uint32_t off = fi_u8(&in) & 1 && mnr ? model[fi_u16(&in) % mnr].off
                                                 : fi_u32(&in) % (pgsz + 64);
            int want = -1;

            for (uint32_t i = 0; i < mnr; i++) {
                if (model[i].off == off) {
                    want = (int)i;
                }
            }
            if (kv_pack_find(pg, off) != want) {
                abort();
            }
            break;
        }
        case 3: {                       /* compact: gaps close, moved owners are reported */
            uint32_t nr = 0, fill = 0, nmoved = 0;

            moved_nr = 0;
            kv_pack_compact(pg, fi_u8(&in) & 1 ? moved : NULL, NULL);
            for (uint32_t i = 0; i < mnr; i++) {
                if (!model[i].live) {
                    continue;
                }
                if (model[i].off != fill) {
                    nmoved++;
                }
                model[i].off = fill;
                fill += kv_pack_rec(model[i].len);
                model[nr++] = model[i];
            }
            mnr = nr;
            mfill = fill;
            if (moved_nr && moved_nr != nmoved) {
                abort();
            }
            break;
        }
        case 4: {                       /* reserve */
            uint32_t n = fi_u16(&in) % (MAX_ITEMS + 1);

            if (kv_pack_reserve(pg, n) || pg->cap < n) {
                abort();
            }
            break;
        }
        case 5:                         /* the page-level predicates agree with the live-byte count */
            if (kv_pack_full(pg, pgsz) !=
                (!kv_pack_fits(pg, 1, pgsz) && pg->live_bytes == pg->fill)) {
                abort();
            }
            break;
        }
        check(pg);
    }
    kv_pack_free(pg);
    return 0;
}
