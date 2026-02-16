/*
 * このファイルは eBPF プログラム（Raw Tracepoint）であり、
 * raw_tp（raw tracepoint）にアタッチしてカーネル内イベントを観測する目的の最小例である。
 *
 * ざっくり何をしているか（アルゴリズム）:
 *  1) raw tracepoint ハンドラ hello() が呼ばれる
 *  2) ctx（bpf_raw_tracepoint_args）から「引数配列 args[]」を参照する
 *  3) args[1] を “opcode” として取り出して bpf_printk でログ出力する
 *  4) 0 を返して終了する（raw tracepoint プログラムでは「通す/落とす」等の制御は基本しない）
 *
 * 注意:
 * - raw tracepoint の ctx->args[] の「意味」は、アタッチ先の tracepoint によって変わる。
 *   つまり “args[1] が syscall 番号（opcode）” だと決め打ちしてよいかは、
 *   SEC("raw_tp/<イベント名>") の <イベント名> が何かに依存する。
 * - 今の SEC("raw_tp/") はイベント名が空で、一般的にはロード/アタッチが成立しない。
 *   通常は SEC("raw_tp/sys_enter") や SEC("raw_tp/sys_exit") のように具体名が必要である。
 * - bpf_printk はデバッグ用で、出力は /sys/kernel/debug/tracing/trace_pipe 等から読む。
 *
 * 依存:
 * - <linux/bpf.h>             : BPF の型・定数
 * - <bpf/bpf_helpers.h>       : SEC マクロ、bpf_printk などの helper 呼び出し定義
 */

#include <linux/bpf.h>          // eBPF プログラムで使う基本の型・定数定義
#include <bpf/bpf_helpers.h>    // SEC マクロ、bpf_printk 等の BPF helper ラッパ

/*
 * noinline を付ける理由:
 * - ここでは「関数呼び出しを残す」ことで、学習/デバッグ時に
 *   “hello() -> get_opcode()” の構造が分かりやすくなる。
 * - eBPF は検証器（verifier）により厳密に解析されるため、
 *   関数分割が常に有利とは限らないが、最近の clang/libbpf 環境では一般に問題なく通る。
 *
 * static にする理由:
 * - この翻訳単位（この .c）内だけで使う補助関数にしておき、
 *   シンボル衝突や外部公開を避ける。
 */
static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    /*
     * bpf_raw_tracepoint_args:
     * - raw tracepoint のコンテキスト構造体。
     * - ctx->args は “unsigned long args[]” 的な可変引数配列として渡される。
     *
     * ctx->args[n] の意味:
     * - アタッチ先の raw tracepoint の仕様次第で変わる。
     * - 例）sys_enter 系なら「syscall 番号」や「レジスタ/引数」などが入ることが多い。
     *
     * ここでは「args[1] が opcode」と仮定して返している。
     * - ただしこの仮定が正しいかは、SEC で指定するイベント名で必ず確認が必要。
     */
    return ctx->args[1];
}

/*
 * SEC("raw_tp/<name>") について:
 * - この関数を「raw tracepoint プログラム」として扱い、
 *   <name> の raw tracepoint にアタッチするためのセクション指定である。
 *
 * 重要:
 * - 現状の "raw_tp/" は <name> が空で、通常は意図通り動かない。
 * - 例として syscall を見たいなら "raw_tp/sys_enter" のように具体名が必要になる。
 */
SEC("raw_tp/")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    /*
     * アルゴリズム（処理の流れ）:
     * 1) ctx から opcode を取得する（補助関数 get_opcode）
     * 2) printk 相当の bpf_printk でカーネルログへ出力
     * 3) 0 を返して終了
     */

    // ctx の args 配列から “opcode（と仮定した値）” を取り出す
    int opcode = get_opcode(ctx);

    /*
     * bpf_printk:
     * - カーネル側の tracing バッファへ文字列を出すデバッグ用 helper。
     * - ユーザ空間からは trace_pipe 等で確認する。
     *
     * 書式:
     * - 通常の printf 風だが、使えるフォーマットや引数数に制限がある。
     * - 短いログに留めるのが無難。
     */
    bpf_printk("Syscall: %d", opcode);

    /*
     * raw tracepoint の戻り値:
     * - XDP のように “PASS/DROP” を返すタイプではない。
     * - 通常は 0 を返す（エラーを表現する用途は限定的）。
     */
    return 0;
}

/*
 * ライセンス表明:
 * - eBPF では LICENSE セクションでライセンス文字列を提供する慣習がある。
 * - GPL 互換でないと使えない helper があるため、一般に "GPL" や "Dual BSD/GPL" が使われる。
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
