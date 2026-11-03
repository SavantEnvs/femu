/*
 * libFuzzer harness for FEMU's NAND media timing layer (hw/femu/nand/nand-media.c).
 * The input chooses a geometry, timing table and policy (staged bus, ONFI order, SCA, read cache, suspend,
 * unbounded bus windows), then a stream of read/program/erase/copyback/multi-plane/cache-sequence operations
 * on in-range locations, as the controllers issue them. The harness holds the busy timelines, as bbssd does.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayhem/femu_fuzz_input.h"
#include "hw/femu/nand/nand-media.h"

#define DIM 4
#define MAX_OPS 1024

static uint64_t ch_avail[DIM];
static uint64_t lun_avail[DIM * DIM];
static uint64_t pl_avail[DIM * DIM * DIM];

static uint64_t *t_ch(void *o, uint32_t ch) { (void)o; return &ch_avail[ch]; }
static uint64_t *t_lun(void *o, const NandLoc *l) { (void)o; return &lun_avail[l->ch * DIM + l->lun]; }
static uint64_t *t_pl(void *o, const NandLoc *l)
{
    (void)o;
    return &pl_avail[(l->ch * DIM + l->lun) * DIM + l->pl];
}

static void t_bus(void *o, uint32_t ch, uint64_t s, uint64_t e)
{
    (void)o;
    if (ch >= DIM || e < s) {
        abort();                      /* a phase on a channel that does not exist, or one that ends before it starts */
    }
}

static const NandTimelineOps timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun, .plane_avail = t_pl, .bus_phase = t_bus, .ca_phase = t_bus,
};

static int64_t ns(FuzzIn *in) { return (int64_t)fi_u16(in) * 8; }

static void rd_config(FuzzIn *in, NandMediaConfig *c)
{
    uint8_t f = fi_u8(in), g = fi_u8(in);

    memset(c, 0, sizeof(*c));
    c->nchs = 1 + fi_u8(in) % DIM;
    c->luns_per_ch = 1 + fi_u8(in) % DIM;
    c->planes_per_lun = 1 + fi_u8(in) % DIM;
    c->secs_per_page = fi_u8(in) % 9;
    c->timeline = &timeline;
    c->policy.array_contend = (NandArrayContend)(fi_u8(in) % 3);
    c->policy.channel_mode = (NandChannelMode)(fi_u8(in) % 3);
    c->policy.pe_suspend = f & 1;
    c->policy.ecc_on_read = f & 2;
    c->policy.use_flat_timing = f & 4;
    c->policy.bus_res_unbounded = f & 8;
    c->policy.onfi_order = f & 16;
    c->policy.page_reg_hold = f & 32;
    c->policy.mp_status_per_plane = f & 64;
    c->policy.ca_separate = f & 128;
    c->policy.cache_read = g & 1;
    c->timing.pgtype_lat = g & 2;

    c->timing.rd_ns = ns(in);
    c->timing.wr_ns = ns(in);
    c->timing.er_ns = ns(in);
    for (int t = 0; t < NAND_MEDIA_MAX_FLASH; t++) {
        for (int p = 0; p < NAND_MEDIA_MAX_PGTYPE; p++) {
            c->timing.rd_table_ns[t][p] = ns(in);
            c->timing.wr_table_ns[t][p] = ns(in);
        }
        c->timing.er_table_ns[t] = ns(in);
    }
    for (int p = 0; p < NAND_MEDIA_MAX_PGTYPE; p++) {
        c->timing.pgtype_mult[p] = fi_u16(in) % 8000;
    }
    c->timing.cmd_addr_ns = ns(in);
    c->timing.page_xfer_ns = ns(in);
    c->timing.status_ns = ns(in);
    c->timing.rd_cmd_ns = ns(in);
    c->timing.wr_cmd_ns = ns(in);
    c->timing.er_cmd_ns = ns(in);
    c->timing.cb_rd_cmd_ns = ns(in);
    c->timing.cb_wr_cmd_ns = ns(in);
    c->timing.din_burst_ns = ns(in);
    c->timing.wr_post_ns = ns(in);
    c->timing.dout_pre_ns = ns(in);
    c->timing.dout_post_ns = ns(in);
    c->timing.dout_mp_pre_ns = ns(in);
    c->timing.din_gap_ns = ns(in);
    c->timing.dout_edge_ns = ns(in);
    c->timing.ccs_ns = ns(in);
    c->timing.sca_packet_ns = ns(in);
    c->timing.sca_tail_ns = ns(in);
    {   /* the SCT packet and its hold sit inside the burst they close (onfi_derive guarantees it) */
        int64_t burst = c->timing.din_burst_ns < c->timing.dout_edge_ns ? c->timing.din_burst_ns
                                                                       : c->timing.dout_edge_ns;

        c->timing.sca_tail_ns %= burst + 1;
    }
    c->timing.trcbsy_ns = ns(in);
    c->timing.rc_step_ns = ns(in);
    c->timing.rc_sel_ns = ns(in);
    c->timing.tplpbsy_ns = ns(in);
    c->timing.tplrbsy_ns = ns(in);
    c->timing.tplebsy_ns = ns(in);
    c->timing.ecc_step_ns = ns(in);
    c->timing.ecc_pe_per_tier = 1 + fi_u16(in) % 2000;
    c->timing.ecc_max_tiers = fi_u8(in) % 16;
    c->timing.ecc_retention_per_tier_sec = fi_u16(in);
    c->timing.tsusp_ns = ns(in);
}

static void rd_loc(FuzzIn *in, const NandMediaConfig *c, NandLoc *l)
{
    memset(l, 0, sizeof(*l));
    l->ch = fi_u8(in) % c->nchs;
    l->lun = fi_u8(in) % c->luns_per_ch;
    l->pl = fi_u8(in) % c->planes_per_lun;
    l->blk = fi_u16(in);
    l->pg = fi_u16(in);
    l->flash_type = fi_u8(in) % NAND_MEDIA_MAX_FLASH;
    l->page_type = fi_u8(in) % NAND_MEDIA_MAX_PGTYPE;
    l->pe_cycles = fi_u16(in) * 4;
    l->age_sec = fi_u16(in) * 64;
    l->extra_tiers = fi_u8(in) % 4;
    l->xfer_secs = c->secs_per_page ? fi_u8(in) % (c->secs_per_page + 1) : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzIn in = { data, size };
    NandMediaConfig cfg;
    NandMedia m;
    uint64_t now = 0;

    rd_config(&in, &cfg);
    memset(ch_avail, 0, sizeof(ch_avail));
    memset(lun_avail, 0, sizeof(lun_avail));
    memset(pl_avail, 0, sizeof(pl_avail));
    nand_media_init(&m, &cfg);
    for (int n = 0; n < MAX_OPS && !fi_eof(&in); n++) {
        NandLoc locs[8];
        NandOpCompletion cmp[8], r;
        uint8_t kind = fi_u8(&in) % 7;
        int cnt = 1 + fi_u8(&in) % 8;

        now += fi_u16(&in);
        rd_loc(&in, &cfg, &locs[0]);
        switch (kind) {
        case 0: case 1: case 2:       /* read, program, erase */
            r = nand_media_op(&m, &locs[0], (NandMediaOp)kind, now);
            break;
        case 3: {                     /* copyback: source and destination share a die and a plane */
            NandLoc dst = locs[0];

            dst.blk = fi_u16(&in);
            dst.pg = fi_u16(&in);
            r = nand_media_copyback(&m, &locs[0], &dst, now);
            break;
        }
        case 4: {                     /* a multi-plane group: one location per plane of one LUN */
            NandMediaOp op = (NandMediaOp)(fi_u8(&in) % 3);

            cnt = 1 + (cnt - 1) % cfg.planes_per_lun;
            for (int i = 0; i < cnt; i++) {
                locs[i] = locs[0];
                locs[i].pl = i;
                locs[i].blk = fi_u16(&in);
                locs[i].pg = fi_u16(&in);
            }
            r = nand_media_multiplane(&m, locs, cnt, op, now);
            break;
        }
        default:                      /* a read sequence on one LUN */
            for (int i = 1; i < cnt; i++) {
                locs[i] = locs[0];
                locs[i].pl = fi_u8(&in) % cfg.planes_per_lun;
                locs[i].blk = fi_u8(&in) & 1 ? locs[i - 1].blk : fi_u16(&in);
                locs[i].pg = fi_u8(&in) & 1 ? locs[i - 1].pg + 1 : fi_u16(&in);
            }
            if (kind == 5) {
                uint64_t plain, seq;

                nand_media_read_seq_cost(&m, locs, cnt, &plain, &seq);
                r = nand_media_read_seq(&m, locs, cnt, now, cmp);
            } else {
                r = nand_media_read_cache_seq(&m, locs, cnt, now, cmp);
            }
            for (int i = 0; i < cnt; i++) {
                if (cmp[i].done_ns < now || cmp[i].latency_ns != cmp[i].done_ns - now) {
                    abort();
                }
            }
            break;
        }
        if (r.done_ns < now || r.latency_ns != r.done_ns - now) {
            abort();                  /* a completion before its start, or a latency that is not done - start */
        }
        (void)nand_media_read_ecc_ns(&m, &locs[0]);
    }
    {
        NandMediaPhases ph;

        nand_media_phases(&m, &ph);
    }
    nand_media_destroy(&m);
    return 0;
}
