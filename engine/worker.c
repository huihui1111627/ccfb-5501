/*
 * Persistent fuzzing worker.
 *
 * The ASan runtime on macOS reports at most one error per process, and a
 * fresh process costs ~60 ms because of sanitizer startup.  So the worker
 * keeps the target in memory and executes one input at a time; when ASan
 * finds a fault the process dies (report already flushed to disk) and the
 * driver restarts it.  Non-crashing inputs never pay process startup.
 *
 * Protocol (stdin -> worker -> stdout), all little endian:
 *   hello:  u32 magic 'D645', u32 proto version, u32 guard count
 *   case :  u32 len (0xFFFFFFFF = quit), len bytes
 *   reply:  u32 edge_count, edge ids (u32 each)
 *
 * argv[1] = path of the ASan report spool file (truncated per start).
 */
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../target/dl645.h"

/* ---- ASan hooks (declared here: clang ships the prototypes in a header
 *      that is only present on some installations) ---------------------- */
void __asan_set_error_report_callback(void (*cb)(const char *));
void __asan_set_death_callback(void (*cb)(void));
void __asan_on_error(void);

#define WORKER_MAGIC 0x35363444u /* 'D645' little endian */
#define WORKER_PROTO 1u
#define EXIT_SANITIZER 97
#define EXIT_DEATH 98
#define EXIT_FATAL_SIGNAL 96

static int g_report_fd = -1;
static volatile int g_in_error;

void __asan_on_error(void)
{
    g_in_error = 1;
}

static void report_sink(const char *report)
{
    if (g_report_fd >= 0) {
        const char *p = report;
        size_t left = strlen(report);
        while (left > 0) {
            ssize_t w = write(g_report_fd, p, left);
            if (w <= 0)
                break;
            p += (size_t)w;
            left -= (size_t)w;
        }
        (void)fsync(g_report_fd);
    }
    _exit(EXIT_SANITIZER);
}

static void death_sink(void)
{
    if (g_report_fd >= 0) {
        static const char msg[] = "@@DEATH\n";
        ssize_t w = write(g_report_fd, msg, sizeof(msg) - 1);
        (void)w;
        (void)fsync(g_report_fd);
    }
    _exit(EXIT_DEATH);
}

/* ASan's death callback is not reached for signals it does not own (SIGTRAP
 * from __builtin_trap, SIGILL, ...), so those would show up as "worker died
 * without a report".  Capture those ourselves and write a small report with
 * the faulting call chain so a trap still buckets by location.
 *
 * Only signals ASan does NOT handle are intercepted: overriding SIGSEGV
 * here would suppress the much better ASan report. */
static void fatal_signal_handler(int sig)
{
    if (g_report_fd >= 0) {
        char buf[256];
        int n;
        void *trace[32];
        int frames = backtrace(trace, 32);
        n = snprintf(buf, sizeof(buf),
                     "@@FATAL signal=%d\n"
                     "ERROR: AddressSanitizer: fatal-signal-%d in %s\n",
                     sig, sig, "worker");
        if (n > 0) {
            ssize_t w = write(g_report_fd, buf,
                              (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1);
            (void)w;
        }
        backtrace_symbols_fd(trace, frames, g_report_fd);
        (void)fsync(g_report_fd);
    }
    _exit(EXIT_FATAL_SIGNAL);
}

static void install_fatal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fatal_signal_handler;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

/* ---- coverage -------------------------------------------------------- */
#define MAX_GUARDS (1u << 20)

static uint8_t g_seen[MAX_GUARDS];
static uint32_t g_touched[MAX_GUARDS];
static uint32_t g_touched_n;
static uint32_t g_guard_total;

/* This TU is built without -fsanitize-coverage, so these run uninstrumented. */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
    static uint32_t next_id = 1;
    uint32_t *p;
    if (start == stop || *start)
        return;
    for (p = start; p < stop; p++) {
        if (next_id >= MAX_GUARDS)
            break;
        *p = next_id++;
    }
    g_guard_total = next_id - 1;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
    uint32_t id = *guard;
    if (id == 0 || id >= MAX_GUARDS)
        return;
    if (g_seen[id])
        return;
    g_seen[id] = 1;
    if (g_touched_n < MAX_GUARDS)
        g_touched[g_touched_n++] = id;
}

/* ---- I/O ------------------------------------------------------------- */
static int read_full(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n > 0) {
        ssize_t r = read(STDIN_FILENO, p, n);
        if (r == 0)
            return -1;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    return 0;
}

static int write_full(const void *src, size_t n)
{
    const uint8_t *p = (const uint8_t *)src;
    while (n > 0) {
        ssize_t w = write(STDOUT_FILENO, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint32_t hello[3];
    uint32_t len;

    if (argc < 2)
        return 2;
    g_report_fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (g_report_fd < 0)
        return 2;
    __asan_set_error_report_callback(report_sink);
    __asan_set_death_callback(death_sink);
    install_fatal_handlers();

    hello[0] = WORKER_MAGIC;
    hello[1] = WORKER_PROTO;
    hello[2] = g_guard_total;
    if (write_full(hello, sizeof(hello)) != 0)
        return 2;

    for (;;) {
        uint8_t *buf;
        uint32_t n_edges;
        if (read_full(&len, sizeof(len)) != 0)
            break;
        if (len == 0xFFFFFFFFu)
            break;
        if (len > (1u << 24))
            break;

        /* Exact-size heap object: reads past the end hit the ASan redzone. */
        buf = (uint8_t *)malloc(len ? len : 1u);
        if (!buf)
            break;
        if (len && read_full(buf, len) != 0) {
            free(buf);
            break;
        }

        g_touched_n = 0;
        (void)dl645_fuzz_one(buf, len);
        free(buf);

        n_edges = g_touched_n;
        if (write_full(&n_edges, sizeof(n_edges)) != 0)
            break;
        if (n_edges && write_full(g_touched, (size_t)n_edges * sizeof(uint32_t)) != 0)
            break;
    }

    if (g_report_fd >= 0)
        close(g_report_fd);
    return 0;
}
