/*
 * hello-buffer-config.c（ユーザ空間側 / libbpf）
 *
 * 直前のエラーの原因:
 *   あなたの環境の libbpf は「新しい perf_buffer__new() API」になっている。
 *
 *     perf_buffer__new(int map_fd, size_t page_cnt,
 *                      const struct perf_buffer_opts *opts);
 *
 *   つまり、昔のように
 *     perf_buffer__new(map_fd, page_cnt, sample_cb, lost_cb, ctx, opts)
 *   とは呼べない。
 *
 * 修正方針:
 *   struct perf_buffer_opts にコールバック等を詰めて、
 *   perf_buffer__new(map_fd, page_cnt, &opts) で作る。
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>

#include <bpf/libbpf.h>

#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"

/* libbpf のログ出力フック（DEBUG を抑制） */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    if (level >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

/*
 * sample_cb の型（libbpf が期待する型）:
 *   typedef void (*perf_buffer_sample_fn)(void *ctx, int cpu, void *data, __u32 size);
 *
 * あなたの warning は「この型自体は合ってる」のに、
 * 旧APIの引数位置に入れてしまっていたせいで関数ポインタ扱いになっていた。
 * 新APIでは opts.sample_cb に入れる。
 */
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    (void)ctx;
    (void)cpu;
    (void)data_sz;

    const struct data_t *m = (const struct data_t *)data;

    printf("%-6d %-6d %-16s %-16s %s\n",
           m->pid, m->uid, m->command, m->path, m->message);
}

/*
 * lost_cb の型（libbpf が期待する型）:
 *   typedef void (*perf_buffer_lost_fn)(void *ctx, int cpu, __u64 lost_cnt);
 *
 * ※昔のシグネチャと違う環境があるので、ここは libbpf.h の typedef に合わせるのが重要。
 */
static void lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
    (void)ctx;
    (void)cpu;
    fprintf(stderr, "lost event: %llu\n", (unsigned long long)lost_cnt);
}

int main(void)
{
    struct hello_buffer_config_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    /* (1) open & load */
    skel = hello_buffer_config_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF object\n");
        return 1;
    }

    /* (2) attach */
    err = hello_buffer_config_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        hello_buffer_config_bpf__destroy(skel);
        return 1;
    }

    /* (3) perf buffer 作成（新API: opts 経由） */
    {
        struct perf_buffer_opts opts;

        /*
         * libbpf はバージョン差で opts の初期化マクロがある場合/ない場合がある。
         * 一番互換性が高いのはゼロ初期化。
         */
        opts = (struct perf_buffer_opts){};

        opts.sample_cb = handle_event; /* ここに入れる */
        opts.lost_cb   = lost_event;   /* ここに入れる */
        opts.ctx       = NULL;         /* handle_event / lost_event の ctx 引数に渡る */

        pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8 /* page_cnt */, &opts);
        if (!pb) {
            err = -errno;
            fprintf(stderr, "Failed to create perf buffer: %d (%s)\n", -err, strerror(-err));
            hello_buffer_config_bpf__destroy(skel);
            return 1;
        }
    }

    /* (4) poll ループ */
    while (true) {
        err = perf_buffer__poll(pb, 100 /* timeout ms */);
        if (err == -EINTR) { /* Ctrl-C */
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
    hello_buffer_config_bpf__destroy(skel);
    return (err < 0) ? -err : 0;
}
