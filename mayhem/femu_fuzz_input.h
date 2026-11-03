/* Byte reader that turns a fuzz input into the parameters and operation stream of a FEMU harness. */
#ifndef FEMU_FUZZ_INPUT_H
#define FEMU_FUZZ_INPUT_H
#include <stddef.h>
#include <stdint.h>

typedef struct FuzzIn {
    const uint8_t *p;
    size_t n;
} FuzzIn;

static inline int fi_eof(const FuzzIn *in) { return in->n == 0; }

static inline uint8_t fi_u8(FuzzIn *in)
{
    if (!in->n) {
        return 0;
    }
    in->n--;
    return *in->p++;
}

static inline uint32_t fi_u16(FuzzIn *in)
{
    uint32_t v = fi_u8(in);
    return v | (uint32_t)fi_u8(in) << 8;
}

static inline uint32_t fi_u32(FuzzIn *in)
{
    uint32_t v = fi_u16(in);
    return v | fi_u16(in) << 16;
}

static inline uint64_t fi_u64(FuzzIn *in)
{
    uint64_t v = fi_u32(in);
    return v | (uint64_t)fi_u32(in) << 32;
}
#endif
