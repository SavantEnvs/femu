/*
 * libFuzzer harness for FEMU's ONFI profile (hw/femu/nand/onfi.c).
 * The input is 64 bytes of numeric fields, then the bytes of a parameter-page file. The file goes through
 * onfi_param_parse() as is: its CRC is checked, not repaired, so seeds carry good copies. The numeric fields
 * also build an OnfiInput and an OnfiParamPage directly, so the timing derivation and the consistency check
 * run whether or not the file parses.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayhem/femu_fuzz_input.h"
#include "hw/femu/nand/onfi.h"

#define NUMERIC_BYTES 64

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzIn in = { data, size < NUMERIC_BYTES ? size : NUMERIC_BYTES };
    OnfiInput oi;
    OnfiTiming ot;
    OnfiParamPage pp, parsed;
    OnfiGeometry g;
    const char *why = NULL;
    char msg[160];

    oi.mode = (int)(fi_u8(&in) % 40) - 5;
    oi.mts = fi_u8(&in) & 1 ? 0 : (int)(fi_u32(&in) % (ONFI_MAX_MTS + 1000));
    oi.page_bytes = fi_u32(&in) % (1u << 20);
    oi.col_cycles = fi_u8(&in) % 8;
    oi.row_cycles = fi_u8(&in) % 8;
    oi.multi_lun = fi_u8(&in) & 1;
    oi.tccs_ns = fi_u16(&in);
    oi.sca = fi_u8(&in) & 1;
    if (onfi_derive(&oi, &ot) == 0 && ot.page_xfer_ns < 0) {
        abort();
    }
    (void)onfi_tdsc_ps(oi.mode);

    memset(&pp, 0, sizeof(pp));
    pp.revision = fi_u16(&in);
    pp.features = fi_u16(&in);
    pp.opt_cmds = fi_u16(&in);
    pp.data_bytes = fi_u32(&in);
    pp.spare_bytes = fi_u16(&in);
    pp.pages_per_block = fi_u32(&in);
    pp.blocks_per_lun = fi_u32(&in);
    pp.luns = fi_u8(&in);
    pp.plane_bits = fi_u8(&in) & 0xf;
    pp.bits_per_entry = fi_u8(&in);
    pp.modes = fi_u32(&in) & 0xffffff;
    memset(&g, 0, sizeof(g));
    g.data_bytes = fi_u32(&in);
    g.spare_bytes = fi_u16(&in);
    g.pages_per_block = fi_u32(&in);
    g.blocks_per_lun = fi_u32(&in);
    g.luns_per_ch = fi_u8(&in);
    g.planes_per_lun = fi_u8(&in) % 9;
    g.bits_per_entry = fi_u8(&in) % 6;
    g.mode = (int)(fi_u8(&in) % 40) - 5;
    {
        uint8_t f = fi_u8(&in);

        g.mp_program = f & 1;
        g.mp_read = f & 2;
        g.copyback = f & 4;
        g.sca = f & 8;
        g.cache_read = f & 16;
    }
    if (fi_u8(&in) & 1) {             /* a plausible page, so the later fields of the check run too */
        pp.revision |= ONFI_REV_6_0;
        pp.features = (pp.features | ONFI_FEAT_NV_LPDDR4) & ~ONFI_FEAT_X16;
        pp.data_bytes = 512u << (pp.data_bytes % 6);
        pp.pages_per_block = 32 * (1 + pp.pages_per_block % 64);
        pp.blocks_per_lun = 1 + pp.blocks_per_lun % 65536;
    }
    (void)onfi_param_max_mode(&pp);
    (void)onfi_param_has_mode(&pp, g.mode);
    if (onfi_param_check(&pp, &g, msg, sizeof(msg)) && !msg[0]) {
        abort();                      /* a failed check names the field */
    }

    if (size > NUMERIC_BYTES &&
        onfi_param_parse(data + NUMERIC_BYTES, size - NUMERIC_BYTES, &parsed, &why) == 0) {
        (void)onfi_param_max_mode(&parsed);
        (void)onfi_param_has_mode(&parsed, g.mode);
        (void)onfi_param_check(&parsed, &g, msg, sizeof(msg));
        if (parsed.copy < 0 || (size_t)(parsed.copy + 1) * ONFI_PARAM_PAGE_BYTES > size - NUMERIC_BYTES) {
            abort();
        }
    } else if (size > NUMERIC_BYTES && !why) {
        abort();                      /* parse failed without a reason */
    }
    return 0;
}
