/*
 * hello-verifier.c（ユーザ空間側 / libbpf skeleton + verifier log 表示）
 *
 * 目的:
 *   1) CO-RE 前提でビルドされた eBPF オブジェクト（hello-verifier.bpf.o）を
 *      libbpf skeleton（hello-verifier.skel.h）経由で open/load/attach する。
 *   2) ロード時に kernel verifier が吐くログ（BPF verifier log）を取得して表示する。
 *   3) eBPF 側が perf_event_array + bpf_perf_event_output() で送信するイベントを
 *      perf buffer API で受信し、整形して表示する。
 *   4) hash map（my_config）にユーザ空間から値を書き込み、eBPF 側の挙動を変える。
 *
 * 背景（全体像）:
 *   eBPF を学ぶときの最大の壁が「verifier に落とされる理由が分からない」である。
 *   そこで本コードは、ロード時に verifier log を kernel から回収できるようにし、
 *   “なぜその eBPF が受理/拒否されたか” を観察できるようにしている。
 *
 * 大まかなアルゴリズム（フロー）:
 *
 *   ┌──────────────────────────────────────────┐
 *   │ (1) libbpf を strict モードにする        │ libbpf_set_strict_mode()
 *   └──────────────────────────┬───────────────┘
 *                              │
 *                              v
 *   ┌──────────────────────────────────────────┐
 *   │ (2) libbpf のログ出力先を設定            │ libbpf_set_print()
 *   └──────────────────────────┬───────────────┘
 *                              │
 *                              v
 *   ┌──────────────────────────────────────────┐
 *   │ (3) open_opts に verifier log バッファを  │ bpf_object_open_opts
 *   │     設定して skeleton を open             │ hello_verifier_bpf__open_opts()
 *   └──────────────────────────┬───────────────┘
 *                              │
 *                              v
 *   ┌──────────────────────────────────────────┐
 *   │ (4) skeleton を load（verifier 実行）     │ hello_verifier_bpf__load()
 *   │     → log_buf に verifier log が入る      │
 *   └──────────────────────────┬───────────────┘
 *                              │
 *                              v
 *   ┌──────────────────────────────────────────┐
 *   │ (5) map にユーザ設定を書き込む            │ bpf_map__update_elem()
 *   │     my_config[uid] = msg                  │
 *   └──────────────────────────┬───────────────┘
 *                              │
 *                              v
 *   ┌──────────────────────────────────────────┐
 *   │ (6) attach（kprobe/tracepoint 等へ紐付け）│ hello_verifier_bpf__attach()
 *   └──────────────────────────┬───────────────┘
 *                              │
 *                              v
 *   ┌──────────────────────────────────────────┐
 *   │ (7) perf buffer を作って poll ループ      │ perf_buffer__new/poll()
 *   │     → handle_event/lost_event が呼ばれる  │
 *   └──────────────────────────────────────────┘
 *
 * 注意（よくあるハマりどころ）:
 *   - perf buffer と ring buffer は別物で API も別。
 *     ここは perf buffer（BPF_MAP_TYPE_PERF_EVENT_ARRAY）なので perf_buffer__new を使う。
 *   - libbpf のバージョンによって perf_buffer__new のシグネチャが変わることがある。
 *     （あなたの環境で「引数が多すぎる」エラーが出たのはその典型）
 *     本コードは “新しいシグネチャ” 側（opts あり）を想定している。
 *     もし古い libbpf なら opts 引数を省いた呼び出しに変える必要がある。
 *
 *   - verifier log の取得は kernel 側の設定/権限にも依存する。
 *     root 実行、かつ libbpf が kernel log を有効化している必要がある。
 */

#include <stdio.h>          // printf, fprintf
#include <unistd.h>         // (必須ではないが慣習的に入ることが多い)
#include <errno.h>          // errno, EINTR など
#include <string.h>         // strncpy
#include <stdarg.h>         // va_list（libbpf_print_fn に必要）
#include <stdbool.h>        // true/false（while(true) に必要）
#include <stdint.h>         // uint32_t
#include <bpf/libbpf.h>     // libbpf API（skeleton, map操作, perf buffer など）

#include "hello-verifier.h"       // eBPF と共有する struct data_t / struct msg_t
#include "hello-verifier.skel.h"  // bpftool gen skeleton で生成された API 群

/*
 * libbpf が内部で出すログ（INFO/WARN/ERROR 等）をどこへ出すかを決める関数。
 *
 * libbpf_set_print(libbpf_print_fn) を呼ぶと、
 * libbpf 内部ログがこの関数経由で流れてくる。
 *
 * 実装方針:
 *   - DEBUG はノイズになりがちなので抑制
 *   - それ以外は stderr に出す
 *
 * NOTE:
 *   デバッグが必要なら if 条件を緩めて DEBUG も出すとよい。
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

/*
 * perf buffer にイベントが到着したときに呼ばれるコールバック。
 *
 * eBPF 側が bpf_perf_event_output(ctx, &output, ...) で送った
 * struct data_t が、そのまま data として届く想定である。
 *
 * 引数:
 *   ctx     : perf_buffer__new で渡した任意ポインタ（今回は NULL）
 *   cpu     : イベントが来た CPU
 *   data    : 受信した生データ（data_t のはず）
 *   data_sz : 受信データのサイズ
 *
 * 重要:
 *   - data_t のレイアウトが eBPF 側と一致していることが必須。
 *     ずれると表示が壊れたり、未定義動作になり得る。
 */
static void handle_event(void *ctx,
                         int cpu,
                         void *data,
                         unsigned int data_sz)
{
    (void)ctx;
    (void)cpu;
    (void)data_sz;

    struct data_t *m = (struct data_t *)data;

    /*
     * 表示:
     *   pid, uid, counter, comm, message
     *
     * NOTE:
     *   command/message が必ず NUL 終端される前提で %s を使っている。
     *   eBPF 側が *_str 系 helper を使っていれば終端されやすいが、
     *   万全にするならユーザ空間側で終端ガードを入れるのが堅い。
     */
    printf("%-6d %-6d %-4d %-16s %s\n",
           m->pid, m->uid, m->counter, m->command, m->message);
}

/*
 * perf buffer が詰まり、イベントを取りこぼした場合に呼ばれるコールバック。
 *
 * eBPF は高速でイベントを生成できる一方、ユーザ空間の処理（printf 等）は遅い。
 * poll が追いつかないと lost event が発生する。
 */
static void lost_event(void *ctx,
                       int cpu,
                       long long unsigned int data_sz)
{
    (void)ctx;
    (void)cpu;
    (void)data_sz;

    printf("lost event\n");
}

int main(void)
{
    /*
     * skeleton ハンドル:
     *   bpftool gen skeleton が生成した型（hello_verifier_bpf）。
     *   これが eBPF object 全体（maps, progs, links など）への入口になる。
     */
    struct hello_verifier_bpf *skel = NULL;

    /* libbpf は慣習的に err を int で扱う */
    int err = 0;

    /* perf buffer のハンドル */
    struct perf_buffer *pb = NULL;

    /*
     * (1) strict mode:
     *   libbpf の API 利用を厳密にし、曖昧な挙動や非推奨を早めに検出する。
     *   学習・検証用途では付けておくと “変な成功” を減らせる。
     */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* (2) libbpf ログの出力先を設定 */
    libbpf_set_print(libbpf_print_fn);

    /*
     * (3) verifier log を受け取るバッファを準備
     *
     * kernel_log_buf / kernel_log_size / kernel_log_level は
     * “BPF ロード時に verifier が吐くログ” を kernel から回収するための設定。
     *
     * - kernel_log_level = 1:
     *     ある程度詳細な verifier log を取る（レベルを上げるともっと出る場合がある）
     * - バッファサイズは 64KB
     *
     * NOTE:
     *   この log_buf に入るのは “ロード時（verifier 実行時）” のログであり、
     *   実行時の bpf_printk ログとは別である。
     */
    char log_buf[64 * 1024];

    /*
     * LIBBPF_OPTS:
     *   libbpf が提供する “構造体初期化ヘルパ”。
     *   余計なフィールド初期化漏れを避けつつ、
     *   指定したいものだけを書くのが定石。
     */
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf   = log_buf,
        .kernel_log_size  = sizeof(log_buf),
        .kernel_log_level = 1,
    );

    /*
     * (3') open（opts 付き）
     *   - hello_verifier_bpf__open_opts() は skeleton 側が提供する open API。
     *   - ここで opts を渡すことで、ロード時ログの回収設定が有効になる。
     *
     * 失敗すると NULL。
     */
    skel = hello_verifier_bpf__open_opts(&opts);
    if (!skel) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    /*
     * (4) load（verifier 実行）
     *
     * ここで
     *   - BPF bytecode がカーネルへロードされ
     *   - verifier が安全性を証明できるか検査し
     *   - OK ならプログラムがロードされる
     *
     * verifier log は log_buf に書き込まれる（設定が効いていれば）。
     */
    err = hello_verifier_bpf__load(skel);

    /*
     * verifier log を表示する
     *
     * このループは log_buf を 1文字ずつ出している。
     * “どこで終わるか” の検出は少し雑で、
     *   log_buf[i]==0 && log_buf[i+1]==0
     * を終端の目安としている（安全のため i+1 の境界に注意が要る）。
     *
     * 改善案:
     *   - memchr で '\0' を探す
     *   - printf("%s", log_buf) のように NUL 終端前提で出す（ただし確実性は落ちる）
     */
    for (size_t i = 0; i + 1 < sizeof(log_buf); i++) {
        if (log_buf[i] == 0 && log_buf[i + 1] == 0)
            break;
        putchar(log_buf[i]);
    }

    if (err) {
        /*
         * load 失敗 = verifier に拒否された/権限不足/依存不足など。
         * 直前に verifier log を出しているので、原因特定に役立つ。
         */
        fprintf(stderr, "Failed to load BPF object (err=%d)\n", err);
        hello_verifier_bpf__destroy(skel);
        return 1;
    }

    /*
     * (5) eBPF 側の map（my_config）にユーザ空間から設定を書き込む
     *
     * 想定:
     *   eBPF 側で
     *     p = bpf_map_lookup_elem(&my_config, &uid);
     *     if (p) data.message = p->message;
     *     else data.message = default;
     * のような分岐をしている。
     *
     * ここでは “UID=501 のときだけ message を差し替える” 設定を入れる。
     *
     * NOTE:
     *   - map update を attach 前にやっているので、最初のイベントから反映される。
     *   - UID は環境に依存する（Ubuntu だと 1000 が一般ユーザ等）。
     */
    uint32_t key = 501;
    struct msg_t msg;
    const char *m = "hello Liz";

    /*
     * strncpy:
     *   固定長配列へコピーするときの定番。
     *   ただし strncpy は NUL 埋め/終端保証の挙動が直感的でないので注意。
     *
     * より堅い書き方:
     *   snprintf(msg.message, sizeof(msg.message), "%s", m);
     * など（ただし msg.message の型次第）
     */
    strncpy((char *)&msg.message, m, sizeof(msg.message));

    /*
     * bpf_map__update_elem:
     *   skeleton が持つ map オブジェクト（skel->maps.my_config）に対して
     *   key/value を書き込む。
     *
     * 引数:
     *   map    : skel->maps.my_config
     *   key    : &key, key_size
     *   value  : &msg, value_size
     *   flags  : 0（BPF_ANY 相当）
     *
     * 失敗時は負の errno が返ることが多い（libbpf のバージョン依存あり）。
     */
    err = bpf_map__update_elem(skel->maps.my_config,
                              &key, sizeof(key),
                              &msg, sizeof(msg),
                              0);
    if (err) {
        fprintf(stderr, "Failed to update my_config map (err=%d)\n", err);
        hello_verifier_bpf__destroy(skel);
        return 1;
    }

    /*
     * (6) attach
     *
     * eBPF 側の SEC("ksyscall/execve") や SEC("xdp") などで定義されたプログラムを
     * それぞれ対応するフックポイントへアタッチする。
     *
     * 失敗すると err != 0
     */
    err = hello_verifier_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        hello_verifier_bpf__destroy(skel);
        return 1;
    }

    /*
     * (7) perf buffer 作成
     *
     * perf buffer は
     *   - eBPF 側: BPF_MAP_TYPE_PERF_EVENT_ARRAY（map: output）
     *   - user 側: perf_buffer__new + perf_buffer__poll
     * の組み合わせでイベントを受け取る。
     *
     * IMPORTANT:
     *   あなたの環境で「perf_buffer__new の引数が多い」エラーが出る場合、
     *   /usr/include/bpf/libbpf.h の宣言に合わせる必要がある。
     *
     * 新しめの libbpf では概ね:
     *   perf_buffer__new(int map_fd, size_t page_cnt,
     *                    perf_buffer_sample_fn sample_cb,
     *                    perf_buffer_lost_fn lost_cb,
     *                    void *ctx,
     *                    const struct perf_buffer_opts *opts);
     *
     * という形。
     */
    pb = perf_buffer__new(
            bpf_map__fd(skel->maps.output),
            8,              /* page_cnt: バッファページ数（増やすと lost 減） */
            handle_event,    /* sample_cb */
            lost_event,      /* lost_cb */
            NULL,            /* ctx: コールバックに渡す任意ポインタ */
            NULL             /* opts: 拡張オプション（未使用） */
    );
    if (!pb) {
        /*
         * NOTE:
         *   ここは perf buffer なのにメッセージが ring buffer になっていたので修正推奨。
         *   失敗原因は errno を出すと早い。
         */
        fprintf(stderr, "Failed to create perf buffer (errno=%d)\n", errno);
        hello_verifier_bpf__destroy(skel);
        return 1;
    }

    /*
     * poll ループ:
     *   perf_buffer__poll(pb, timeout_ms) が
     *     - イベントが来ると handle_event を呼び
     *     - 取りこぼしがあると lost_event を呼ぶ
     *
     * Ctrl-C などで割り込みが入ると -EINTR で戻るので、それは正常終了扱い。
     */
    while (true) {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);

        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    /* 後始末 */
    perf_buffer__free(pb);
    hello_verifier_bpf__destroy(skel);

    /*
     * 慣習:
     *   err==0 なら 0
     *   err<0 なら -err（負 errno を正にして返す）
     */
    return -err;
}
