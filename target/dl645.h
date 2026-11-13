/*
 * DL/T 645-2007 frame parser -- fuzzing target.
 *
 * Implements the subset of the protocol a concentrator (电表集抄终端)
 * exercises on its 485 / TCP uplink: framing, address decoding, checksum
 * verification, data item dispatch and a retransmission cache used when a
 * slave answers with a damaged frame.
 *
 * The code is deliberately NOT hardened.  Every planted defect is marked
 * "DEFECT Dxx" in dl645.c and documented in docs/defects.md.  Build with
 * -DDL645_FIXED to compile the repaired variant used by the regression
 * workflow.
 */
#ifndef DL645_H
#define DL645_H

#include <stddef.h>
#include <stdint.h>

#define DL645_START_BYTE     0x68u
#define DL645_END_BYTE       0x16u
#define DL645_MAX_DATA       200u
#define DL645_FRAME_OVERHEAD 12u
#define DL645_SEQ_SLOTS      4u
#define DL645_MAX_BATCH      4u

typedef enum {
    DL645_OK = 0,
    DL645_E_SHORT = 1,
    DL645_E_START = 2,
    DL645_E_LENGTH = 3,
    DL645_E_CHECKSUM = 4,
    DL645_E_END = 5,
    DL645_E_DATA = 6
} dl645_status_t;

typedef struct {
    uint8_t bcd[12];   /* A0..A5 BCD expanded to ASCII, low byte first */
    int valid;
    int ascii_sum;     /* digest used by the address change tracker */
} dl645_addr_t;

typedef struct {
    int32_t  last_value;
    uint32_t digit_count;
    uint32_t items;
    uint32_t unknown_items;
    uint32_t errors;
    uint8_t  retry_policy;
    uint8_t  ctrl_class;
    int      addr_digest;
} dl645_diag_t;

typedef struct {
    uint8_t        addr[6];
    uint8_t        ctrl;
    uint8_t        len;
    const uint8_t *data;      /* points into the caller supplied buffer */
    uint8_t        cs_frame;
    uint8_t        cs_calc;
    int            addr_valid;
    int            addr_digest;
    size_t         total_len;
} dl645_frame_t;

typedef struct {
    /* 上一帧原始报文缓存, 用于从站异常时快速重传 */
    uint8_t        *last;
    size_t          last_len;
    unsigned long   frames;
    uint32_t       *batch;   /* 4 slot batch window, heap allocated */
    uint32_t        seq[DL645_SEQ_SLOTS];
    unsigned long   seq_w;
    dl645_addr_t    addr;
    dl645_diag_t    diag;
} dl645_stream_t;

void dl645_stream_init(dl645_stream_t *st);
void dl645_stream_free(dl645_stream_t *st);

/* Parse one received byte stream (may hold several concatenated frames). */
int dl645_process(const uint8_t *buf, size_t n, dl645_stream_t *st);

/* One-shot entry point used by the coverage guided engine. */
int dl645_fuzz_one(const uint8_t *buf, size_t n);

#endif /* DL645_H */
