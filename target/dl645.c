/*
 * DL/T 645-2007 / 645-1997 frame parser used as the fuzzing target.
 *
 * Scope: the subset a 集抄终端 (data concentrator) exercises on its
 * downstream 485 / TCP link -- address decoding, checksum verification,
 * control code dispatch, data item decoding and a small retransmission
 * cache for damaged frames.
 *
 * The code is intentionally NOT hardened.  Each planted defect is marked
 * "DEFECT Dxx" and described in docs/defects.md.  -DDL645_FIXED compiles
 * the repaired variant used by the regression workflow.
 */
#include "dl645.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static uint8_t checksum(const uint8_t *p, size_t n)
{
    uint8_t sum = 0;
    size_t i;
    for (i = 0; i < n; i++)
        sum = (uint8_t)(sum + p[i]);
    return sum;
}

/* ------------------------------------------------------------------ */
/* DEFECT D04 (BCD): address nibbles 0xA..0xF index a 10 entry table  */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
static void addr_decode(const uint8_t a[6], dl645_addr_t *out)
{
    static const char bcd_char[10] = { '0', '1', '2', '3', '4',
                                       '5', '6', '7', '8', '9' };
    int i;
    out->valid = 1;
    for (i = 0; i < 6; i++) {
        unsigned hi = (unsigned)(a[i] >> 4) & 0x0Fu;
        unsigned lo = (unsigned)(a[i] & 0x0Fu);
        if (hi > 9u || lo > 9u)
            out->valid = 0;
#ifndef DL645_FIXED
        /* DEFECT D04: table has 10 entries but the index runs 0..15. */
        out->bcd[i * 2 + 0] = (uint8_t)bcd_char[hi];
        out->bcd[i * 2 + 1] = (uint8_t)bcd_char[lo];
#else
        /* clamp first: a ternary on both sides of the load lets the
         * optimiser keep the out of range address */
        out->bcd[i * 2 + 0] = (uint8_t)bcd_char[hi > 9u ? 0u : hi];
        out->bcd[i * 2 + 1] = (uint8_t)bcd_char[lo > 9u ? 0u : lo];
        if (hi > 9u)
            out->bcd[i * 2 + 0] = '?';
        if (lo > 9u)
            out->bcd[i * 2 + 1] = '?';
#endif
        if (hi > 9u || lo > 9u)
            out->valid = 0;
    }
    out->ascii_sum = 0;                       /* keep the result observable */
    for (i = 0; i < 12; i++)
        out->ascii_sum += (int)out->bcd[i];
}

/* ------------------------------------------------------------------ */
/* DEFECT D06 (control dispatch): 24 entry table, index is ctrl&0x1F  */
/* ------------------------------------------------------------------ */
enum { CLASS_READ_DATA = 1, CLASS_WRITE_DATA = 2, CLASS_OTHER = 3 };

__attribute__((noinline))
static int dispatch_item(dl645_stream_t *st, const dl645_frame_t *f);

__attribute__((noinline))
static int dispatch(dl645_stream_t *st, const dl645_frame_t *f)
{
    static const uint8_t ctrl_class[24] = {
        CLASS_OTHER, CLASS_READ_DATA, CLASS_READ_DATA, CLASS_READ_DATA,
        CLASS_WRITE_DATA, CLASS_OTHER, CLASS_OTHER, CLASS_WRITE_DATA,
        CLASS_OTHER, CLASS_OTHER, CLASS_READ_DATA, CLASS_READ_DATA,
        CLASS_OTHER, CLASS_OTHER, CLASS_OTHER, CLASS_OTHER,
        CLASS_OTHER, CLASS_READ_DATA, CLASS_OTHER, CLASS_OTHER,
        CLASS_OTHER, CLASS_OTHER, CLASS_OTHER, CLASS_OTHER
    };
    unsigned idx = (unsigned)(f->ctrl & 0x1Fu);
    uint8_t cls;
#ifndef DL645_FIXED
    /* DEFECT D06: idx runs 0..31 while the table holds 24 entries. */
    cls = ctrl_class[idx];
#else
    cls = ctrl_class[idx % 24u];
#endif
    st->diag.ctrl_class = cls;
    if (cls == CLASS_READ_DATA || cls == CLASS_WRITE_DATA)
        return dispatch_item(st, f);
    return DL645_OK;
}

/* ------------------------------------------------------------------ */
/* DEFECT D05 (BCD): decimals nibble indexes an 8 entry scale table   */
/* ------------------------------------------------------------------ */
static int dispatch_item(dl645_stream_t *st, const dl645_frame_t *f)
{
    static const int32_t dec_scale[8] = { 1, 10, 100, 1000,
                                          10000, 100000, 1000000, 10000000 };
    st->diag.items++;
    if (f->len < 2)
        return DL645_OK;
    if (f->data[0] == 0x10 && f->data[1] == 0x90) {     /* DI 0x9010 电能量 */
        unsigned dec;
        int32_t scale;
        if (f->len < 4)
            return DL645_E_DATA;
        dec = (unsigned)(f->data[2] >> 4) & 0x0Fu;
#ifndef DL645_FIXED
        /* DEFECT D05: dec runs 0..15 while the table holds 8 entries. */
        scale = dec_scale[dec];
#else
        scale = dec_scale[dec & 7u];
#endif
        st->diag.last_value = (int32_t)f->data[3] * scale;
        st->diag.digit_count++;
        return DL645_OK;
    }
    st->diag.unknown_items++;
    return DL645_OK;
}

/* ------------------------------------------------------------------ */
/* DEFECT D03 (checksum): 16 entry retry table indexed with calc&0x1F */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
static uint8_t checksum_retry(dl645_stream_t *st, uint8_t calc)
{
    static const uint8_t retry_policy[16] = {
        0, 1, 1, 2, 1, 0, 2, 1, 1, 0, 1, 1, 2, 1, 0, 1
    };
    uint8_t pol;
    st->diag.errors++;
#ifndef DL645_FIXED
    /* DEFECT D03: calc & 0x1F runs 0..31 while the table holds 16. */
    pol = retry_policy[(unsigned)calc & 0x1Fu];
#else
    pol = retry_policy[(unsigned)calc & 0x0Fu];
#endif
    st->diag.retry_policy = pol;
    return pol;
}

/* ------------------------------------------------------------------ */
/* DEFECT D01 (length): 2007 data copy ignores DL645_MAX_DATA         */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
static int parse_frame_2007(const uint8_t *b, size_t n, dl645_frame_t *f)
{
    uint8_t data_copy[DL645_MAX_DATA];
    uint8_t L;
    uint8_t cs_calc;
    uint8_t cs_frame;

    if (n < 12)
        return DL645_E_SHORT;
    L = b[9];
    if (10u + (size_t)L > n)
        return DL645_E_SHORT;
#ifndef DL645_FIXED
    /* DEFECT D01: L may be 201..255 while data_copy holds 200 bytes. */
    memcpy(data_copy, b + 10, L);
#else
    if (L > DL645_MAX_DATA)
        return DL645_E_LENGTH;
    memcpy(data_copy, b + 10, L);
#endif
    if (12u + (size_t)L > n)
        return DL645_E_SHORT;
    if (b[11 + L] != DL645_END_BYTE)
        return DL645_E_END;

    /* checksum is recomputed over the working copy, like the firmware does */
    cs_calc = checksum(data_copy, L);
    cs_calc = (uint8_t)(cs_calc + checksum(b, 10u));
    cs_frame = b[10 + L];

    f->len = L;
    f->ctrl = b[8];
    memcpy(f->addr, b + 1, 6);
    f->data = b + 10;
    f->cs_calc = cs_calc;
    f->cs_frame = cs_frame;
    f->total_len = 12u + L;

    if (cs_calc != cs_frame)
        return DL645_E_CHECKSUM;
    return DL645_OK;
}

/* ------------------------------------------------------------------ */
/* DEFECT D02 (length): 1997 two byte length copied without bounds    */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
static int parse_frame_1997(const uint8_t *b, size_t n, dl645_frame_t *f)
{
    uint16_t L2;
    uint8_t *copy;
    uint8_t cs_calc;
    uint8_t cs_frame;

    if (n < 13)
        return DL645_E_SHORT;
    L2 = (uint16_t)((uint16_t)b[9] | ((uint16_t)b[10] << 8));
    if (L2 > DL645_MAX_DATA)
        return DL645_E_LENGTH;
#ifndef DL645_FIXED
    /* DEFECT D02: no check that n >= 11 + L2 before the copy. */
    copy = (uint8_t *)malloc(L2 ? L2 : 1u);
    if (!copy)
        return DL645_E_DATA;
    memcpy(copy, b + 11, L2);
#else
    if (11u + (size_t)L2 > n)
        return DL645_E_SHORT;
    copy = (uint8_t *)malloc(L2 ? L2 : 1u);
    if (!copy)
        return DL645_E_DATA;
    memcpy(copy, b + 11, L2);
#endif
    if (12u + (size_t)L2 > n) {
        free(copy);
        return DL645_E_SHORT;
    }
    if (b[12 + L2] != DL645_END_BYTE) {
        free(copy);
        return DL645_E_END;
    }

    cs_calc = checksum(b, 11u + L2);
    cs_frame = b[11 + L2];
    f->len = (uint8_t)L2;
    f->ctrl = b[8];
    memcpy(f->addr, b + 1, 6);
    f->data = copy;               /* caller frees */
    f->cs_calc = cs_calc;
    f->cs_frame = cs_frame;
    f->total_len = 13u + L2;

    if (cs_calc != cs_frame)
        return DL645_E_CHECKSUM;
    return DL645_OK;
}

__attribute__((noinline))
static int parse_any_frame(const uint8_t *b, size_t n, dl645_frame_t *f)
{
    dl645_addr_t addr;
    int r;

    if (n < 1)
        return DL645_E_SHORT;
    if (b[0] != DL645_START_BYTE)
        return DL645_E_START;
    if (n < 8 || b[7] != DL645_START_BYTE)
        return DL645_E_START;

    memcpy(f->addr, b + 1, 6);
    addr_decode(f->addr, &addr);       /* D04 */
    f->addr_valid = addr.valid;
    f->addr_digest = addr.ascii_sum;

    r = parse_frame_2007(b, n, f);
    if (r == DL645_OK)
        return r;
    /* A well formed 2007 frame whose checksum fails must not be retried as
     * a 1997 frame: the length fields mean different things. */
    if (r == DL645_E_CHECKSUM)
        return r;
    return parse_frame_1997(b, n, f);  /* 97 兼容路径, D02 */
}

/* ------------------------------------------------------------------ */
/* DEFECT D07 (retransmission cache): free then reuse                  */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
static void remember_last(dl645_stream_t *st, const uint8_t *b, size_t total)
{
    if (total == 0)
        return;
    free(st->last);
    st->last = (uint8_t *)malloc(total);
    if (!st->last) {
        st->last_len = 0;
        return;
    }
    memcpy(st->last, b, total);
    st->last_len = total;
}

__attribute__((noinline))
static void retransmit_cache(dl645_stream_t *st, const uint8_t *b, size_t n)
{
    size_t total;
    if (!st->last)
        return;
    total = st->last_len < n ? st->last_len : n;
#ifndef DL645_FIXED
    /* DEFECT D07: the cached frame is released, then written through. */
    free(st->last);
    memcpy(st->last, b, total);
#else
    free(st->last);
    st->last = NULL;
    st->last_len = 0;
#endif
}

/* ------------------------------------------------------------------ */
/* DEFECT D08 (batch bookkeeping): batch window off by one            */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
static void record_batch(dl645_stream_t *st, size_t total)
{
#ifndef DL645_FIXED
    /* DEFECT D08: the 4 slot batch window is addressed with the 1 based
     * frame counter, so the 5th frame writes one past the allocation. */
    st->batch[st->frames] = (uint32_t)total;
#else
    st->batch[st->frames % DL645_MAX_BATCH] = (uint32_t)total;
#endif
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */
void dl645_stream_init(dl645_stream_t *st)
{
    if (!st)
        return;
    memset(st, 0, sizeof(*st));
}

void dl645_stream_free(dl645_stream_t *st)
{
    if (!st)
        return;
    free(st->last);
    st->last = NULL;
}

int dl645_process(const uint8_t *buf, size_t n, dl645_stream_t *st)
{
    size_t off = 0;
    int rc = DL645_OK;

    if (!buf || !st)
        return DL645_E_DATA;

    while (off + 8 <= n) {
        dl645_frame_t f;
        int r;

        memset(&f, 0, sizeof(f));
        r = parse_any_frame(buf + off, n - off, &f);
        if (r != DL645_OK) {
            if (r == DL645_E_CHECKSUM) {
                checksum_retry(st, f.cs_calc);              /* D03 */
                retransmit_cache(st, buf + off, n - off);   /* D07 */
            }
            st->seq[st->seq_w & (DL645_SEQ_SLOTS - 1u)] = (uint32_t)r;
            st->seq_w++;
            rc = r;
            break;
        }

        st->frames++;
        st->addr.valid = f.addr_valid;
        st->addr.ascii_sum = f.addr_digest;
        st->diag.addr_digest = f.addr_digest;
        dispatch(st, &f);                                   /* D06 / D05 */
        record_batch(st, f.total_len);                      /* D08 */
        remember_last(st, buf + off, f.total_len);
        if (f.data && f.data != buf + off + 10)
            free((void *)f.data);   /* 97 path copies the data */
        off += f.total_len;
    }
    return rc;
}

int dl645_fuzz_one(const uint8_t *buf, size_t n)
{
    dl645_stream_t *st = (dl645_stream_t *)malloc(sizeof(*st));
    int rc;
    if (!st)
        return 0;
    memset(st, 0, sizeof(*st));
    st->batch = (uint32_t *)malloc(DL645_MAX_BATCH * sizeof(uint32_t));
    if (!st->batch) {
        free(st);
        return 0;
    }
    rc = dl645_process(buf, n, st);
    dl645_stream_free(st);
    free(st->batch);
    free(st);
    return rc;
}
