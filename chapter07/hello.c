/*
 * hello.c（ユーザ空間側 / libbpf skeleton + perf buffer）
 *
 * 目的:
 *   bpftool gen skeleton で生成された hello.skel.h（= skeleton）を使って
 *   eBPFプログラムを
 *     - open（オブジェクトを開く）
 *     - load（カーネルへロードして verifier を通す）
 *     - attach（指定したフックポイントへ接続）
 *   まで行い、
 *   eBPF側が BPF_MAP_TYPE_PERF_EVENT_ARRAY + bpf_perf_event_output() で投げるイベントを
 *   perf buffer 経由で受信して表示する。
 *
 * 全体のアルゴリズム（処理フロー）:
 *
 *   ┌──────────────────────────────────────┐
 *   │ (1) libbpf ログ出力のフック設定       │  libbpf_set_print()
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (2) open_opts を用意（verifierログ用）│  LIBBPF_OPTS(...)
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (3) skeleton open                     │  hello_bpf__open_opts()
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (4) skeleton load（verifier通過）     │  hello_bpf__load()
 *   │     + verifier log を表示             │
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (5) skeleton attach（フックへ接続）   │  hello_bpf__attach()
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (6) perf buffer 作成                  │  perf_buffer__new()
 *   │     - skel->maps.output の fd を渡す  │  bpf_map__fd()
 *   │     - sample/lost コールバックを登録 │
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (7) poll ループで受信                 │  perf_buffer__poll()
 *   │     - 受信時 handle_event が呼ばれる  │
 *   │     - 取りこぼし時 lost_event が呼ばれる
 *   │     - Ctrl-C(-EINTR) で終了           │
 *   └───────────────────┬──────────────────┘
 *                       │
 *                       v
 *   ┌──────────────────────────────────────┐
 *   │ (8) 後始末                           │  perf_buffer__free()
 *   │                                      │  hello_bpf__destroy()
 *   └──────────────────────────────────────┘
 *
 * 重要な前提:
 *   - eBPF側に "output" という BPF_MAP_TYPE_PERF_EVENT_ARRAY が存在する
 *   - eBPF側が bpf_perf_event_output(ctx, &output, ...) を呼ぶ
 *   - ユーザ空間側は perf_buffer__new / perf_buffer__poll を使う（ringbufとは別物）
 *
 * 注意:
 *   - このコードは while(true) を使っているが <stdbool.h> を include していない。
 *     もしコンパイルエラーになる場合は #include <stdbool.h> を追加する。
 *   - perf_buffer__new のシグネチャは libbpf のバージョンで変わることがある。
 *     （あなたの環境で “引数が多い” エラーが出た場合は opts 方式に合わせる必要がある）
 *     ※ここでは「提示されたコード」をそのままにしつつ、コメントで意味を明確化する。
 */

#include <stdio.h>          // printf, fprintf
#include <unistd.h>         // （現状では未使用だが、サンプルで入れがち）
#include <errno.h>          // EINTR など（poll のエラー判定に使うことが多い）
#include <string.h>         // strncpy など（現状では未使用）
#include <stdarg.h>         // va_list（libbpf_print_fn が使う）
/* while(true) を使うなら本来必要（環境によってはコンパイルエラーになる） */
// #include <stdbool.h>

#include <bpf/libbpf.h>     // libbpf API（skeleton/perf buffer/opts など）
#include "hello.h"          // eBPF と共有する構造体 data_t などが入っている想定
#include "hello.skel.h"     // bpftool gen skeleton で生成された skeleton API

/*
 * libbpf のログ出力先を差し替えるコールバック。
 *
 * libbpf_set_print() に渡すと、libbpf内部のログがこの関数経由で流れてくる。
 *
 * 引数:
 *   level  : ログレベル（DEBUG/INFO/WARN/ERROR...）
 *   format : printf 形式文字列
 *   args   : 可変引数
 *
 * 実装方針:
 *   - DEBUG レベル以上は黙らせる（必要なら条件を変えて詳細ログを出せる）
 *   - それ以外は stderr へ vfprintf で出す
 *
 * NOTE:
 *   verifier のエラー調査をするなら、DEBUGも出したい場合がある。
 *   そのときは if (level >= LIBBPF_DEBUG) return 0; を外す/条件を緩める。
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    /* DEBUG 以上を抑制（ノイズを減らす） */
    if (level >= LIBBPF_DEBUG)
        return 0;

    /* stderr に出す（libbpf は基本 stderr に流すことが多い） */
    return vfprintf(stderr, format, args);
}

/*
 * perf buffer に「イベントが届いた」時に呼ばれるコールバック（sample_cb）。
 *
 * perf_buffer__poll() が内部でイベントを読み、
 * その payload をこの関数の data に渡してくる。
 *
 * 引数:
 *   ctx     : perf_buffer__new の引数で渡した任意ポインタ（今回は NULL）
 *   cpu     : イベントを出した CPU
 *   data    : eBPF側が bpf_perf_event_output で送ったデータへのポインタ
 *   data_sz : data のサイズ
 *
 * 重要:
 *   - data の解釈は “eBPF側の struct data_t と完全一致” が必須。
 *   - ここで struct data_t *m = data; とキャストしているので、
 *     hello.h 側の data_t 定義が eBPF 側と一致していないと崩れる。
 */
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    (void)ctx;      // 未使用警告抑制
    (void)cpu;      // 未使用警告抑制
    (void)data_sz;  // 現状はサイズチェックしていない

    /* payload を共有構造体として解釈 */
    struct data_t *m = (struct data_t *)data;

    /*
     * %-6d  : PID/UID を幅6で左寄せ
     * %-16s : command/path を幅16で左寄せ
     * %s    : message は可変長表示
     *
     * NOTE（安全性）:
     *   m->command / m->path / m->message が NUL終端されている前提で %s を使っている。
     *   eBPF側が bpf_probe_read_*_str を使っていれば終端されやすい。
     *   もし bpf_probe_read_* を使っているなら、ここで終端保証を入れると堅い。
     */
    printf("%-6d %-6d %-16s %-16s %s\n",
           m->pid, m->uid, m->command, m->path, m->message);
}

/*
 * perf buffer で “イベント取りこぼし” が発生した時に呼ばれるコールバック（lost_cb）。
 *
 * 高頻度でイベントが出るのにユーザ空間が捌けない場合、
 * perf buffer のキューが溢れて lost event が発生する。
 *
 * 引数:
 *   ctx     : 任意ポインタ（今回は NULL）
 *   cpu     : どのCPUで取りこぼしたか
 *   data_sz : 取りこぼしたデータ量に関する情報（libbpf実装/バージョン依存）
 *
 * NOTE:
 *   本格的に観測するなら “何回 lost したか” をカウントして表示すると良い。
 */
void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
    (void)ctx;
    (void)cpu;
    (void)data_sz;

    printf("lost event\n");
}

/*
 * main:
 *   - skeleton を open/load/attach
 *   - perf buffer を作って poll する
 */
int main()
{
    /*
     * skeleton ハンドル:
     *   bpftool gen skeleton が生成した型（hello_bpf）
     *   eBPFオブジェクト全体（maps/programs/links）をまとめて扱う。
     */
    struct hello_bpf *skel;

    /* libbpf の関数は慣習的に int err を返すことが多い */
    int err;

    /* perf buffer ハンドル */
    struct perf_buffer *pb = NULL;

    /* libbpf のログを自分の関数へ流す */
    libbpf_set_print(libbpf_print_fn);

    /*
     * verifier ログ（kernel verifier log）を受け取るためのバッファ。
     * .kernel_log_* を open_opts に渡すと、
     * load 時に verifier のログがここへ書き込まれる（設定次第）。
     */
    char log_buf[64 * 1024];

    /*
     * bpf_object_open_opts:
     *   skeleton open 時のオプション。
     *   - kernel_log_buf  : verifier ログの格納先
     *   - kernel_log_size : バッファサイズ
     *   - kernel_log_level: ログ詳細度（1 以上で出ることが多い）
     *
     * NOTE:
     *   libbpf の “strict mode” を使う例も多い。
     *   例: libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
     */
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf = log_buf,
        .kernel_log_size = sizeof(log_buf),
        .kernel_log_level = 1,
    );

    /*
     * (1) skeleton を open（ただしまだ load していない）
     * hello_bpf__open_opts:
     *   - 内部的に BPFオブジェクト（ELF）を開いて解析する
     *   - opts を反映して verifier log 設定などを行う
     */
    skel = hello_bpf__open_opts(&opts);
    if (!skel) {
        printf("Failed to open BPF object\n");
        return 1;
    }

    /*
     * (2) skeleton を load
     * hello_bpf__load:
     *   - eBPFプログラムをカーネルにロードする
     *   - verifier を通過する必要がある（失敗すると err != 0）
     *
     * ここが通らない場合:
     *   - helper の使い方が悪い
     *   - ポインタ/境界チェック不足
     *   - ループが verifier に通らない
     *   - セクション/attach種別が合っていない
     * などが原因になる。
     */
    err = hello_bpf__load(skel);

    /*
     * verifier log を表示:
     *   log_buf は 0 で終端されるとは限らないので、
     *   “0 が2連続” を終端っぽい判定として表示を止めている。
     *
     * NOTE:
     *   sizeof(log_buf) は size_t（大きい環境だと警告が出る可能性）なので、
     *   for (size_t i=0; i<sizeof(log_buf)-1; i++) にする方が安全。
     */
    for (int i = 0; i < (int)sizeof(log_buf); i++) {
        if (log_buf[i] == 0 && log_buf[i + 1] == 0) {
            break;
        }
        printf("%c", log_buf[i]);
    }

    /*
     * load 失敗時:
     *   verifier に弾かれている可能性が高いので、
     *   直前に出した verifier log を見て原因を追う。
     */
    if (err) {
        printf("Failed to load BPF object\n");
        hello_bpf__destroy(skel);
        return 1;
    }

    /*
     * (3) attach
     * hello_bpf__attach:
     *   - eBPF 側の SEC(...)（例: kprobe, tracepoint, fentry など）に従い、
     *     適切なフックへ接続する。
     *
     * 失敗しやすい例:
     *   - カーネルがその attach 種別をサポートしていない
     *   - root権限/ケーパビリティ不足
     *   - セクション名がカーネル側に存在しない
     */
    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        hello_bpf__destroy(skel);
        return 1;
    }

    /*
     * (4) perf buffer を作成
     *
     * perf_buffer__new(map_fd, page_cnt, sample_cb, lost_cb, ctx, opts)
     *
     * - map_fd:
     *     eBPF側の PERF_EVENT_ARRAY マップの fd。
     *     skel->maps.output で map オブジェクトにアクセスし、
     *     bpf_map__fd(...) で fd を取り出す。
     *
     * - page_cnt:
     *     バッファのページ数（2の累乗が推奨）。
     *     大きいほど取りこぼしに強いが、メモリは増える。
     *
     * - sample_cb / lost_cb:
     *     受信イベント/取りこぼしのコールバック。
     *
     * NOTE:
     *   あなたの環境で “perf_buffer__new の引数が多い” と怒られる場合がある。
     *   その場合は libbpf のAPIが新しい/古い差分で、
     *   perf_buffer__new のシグネチャが
     *     perf_buffer__new(map_fd, page_cnt, const struct perf_buffer_opts *opts)
     *   形式になっている可能性がある（= opts 経由で cb を渡す方式）。
     *
     *   そのときは「LIBBPF_OPTS(perf_buffer_opts, pb_opts, .sample_cb=..., .lost_cb=...)」
     *   の形へ合わせる必要がある。
     */
    pb = perf_buffer__new(
        bpf_map__fd(skel->maps.output),
        8,
        handle_event,
        lost_event,
        NULL,
        NULL
    );

    if (!pb) {
        err = -1;

        /*
         * ここは perf buffer なのに “ring buffer” と書いてあるので誤解を生む。
         * perf buffer を使っているなら文言は perf buffer が正しい。
         *
         * また、失敗原因は errno がヒントになることが多いので表示すると良い。
         */
        fprintf(stderr, "Failed to create perf buffer (errno=%d)\n", errno);

        hello_bpf__destroy(skel);
        return 1;
    }

    /*
     * (5) poll ループ
     *
     * perf_buffer__poll(pb, timeout_ms):
     *   - timeout_ms の間、イベント到着を待ち、来たら sample_cb を呼ぶ
     *   - lost があれば lost_cb を呼ぶ
     *
     * 戻り値:
     *   >=0: 処理したイベント数（実装差あり）
     *   <0 : エラー（-EINTR は Ctrl-C など）
     *
     * NOTE:
     *   while(true) を使うなら <stdbool.h> が必要な環境がある。
     */
    while (true) {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);

        /* Ctrl-C で割り込み -> -EINTR なら正常終了扱い */
        if (err == -EINTR) {
            err = 0;
            break;
        }

        /* その他の負値は本当のエラー */
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    /* (6) 後始末 */
    perf_buffer__free(pb);
    hello_bpf__destroy(skel);

    /*
     * 慣習として -err を返す流儀がある（err<0 を正の errno にする）。
     * ここは “学習用” なら 0/1 でも良いが、libbpf サンプルに寄せた形。
     */
    return -err;
}
