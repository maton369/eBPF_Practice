/*
 * eBPF / XDP の最小サンプル（Hello World + カウンタ）
 *
 * このプログラムは XDP (eXpress Data Path) フックにアタッチされ、
 * 受信パケットごとにカーネル側で実行される eBPF プログラムである。
 *
 * 何をしているか（ざっくり）
 * 1) XDP に入ってきたパケットごとに hello() が呼ばれる
 * 2) bpf_printk() で "Hello World <counter>" をログに出す
 * 3) counter を 1 増やす
 * 4) XDP_PASS を返し、パケットを通常のネットワークスタックへ通す
 *
 * 注意点（重要）
 * - eBPF は「複数 CPU 上で並列実行」され得るため、グローバル変数 counter の更新は
 *   競合（レース）しやすい。ログの値は飛んだり重複したりし得る。
 * - また、eBPF のグローバル変数は “BPF グローバルデータ” として扱われるが、
 *   永続化・共有の意味合いを明示したい場合は BPF_MAP を使うのが定石である。
 * - bpf_printk() はデバッグ用途であり、高頻度パス（XDP）で多用すると重い。
 */

#include <linux/bpf.h>        // eBPF プログラムの基本型（struct xdp_md など）や定数の定義
#include <bpf/bpf_helpers.h>  // SEC マクロ、bpf_printk などの BPF helper 定義

/*
 * グローバル変数カウンタ
 *
 * eBPF プログラム内のグローバル変数は BPF 側の .bss/.data に置かれる。
 * ただし XDP は非常に高頻度で呼ばれ、さらに並列実行され得るので、
 * この「単純な counter++」は競合する（原子性がない）点に注意。
 *
 * 正しく “パケット数” を数えたいなら、BPF_MAP（per-cpu map や array/map）を使うのが一般的。
 */
int counter = 0;

/*
 * SEC("xdp") により、この関数は XDP プログラムとして扱われる。
 *
 * XDP プログラムは NIC ドライバ直後〜ネットワークスタック前の非常に早い段階で動作し、
 * 返り値でパケットの扱い（DROP / PASS / TX / REDIRECT など）を決める。
 *
 * 引数 ctx (struct xdp_md *):
 * - XDP に渡されるコンテキストで、パケットデータ位置などが含まれる。
 * - このサンプルでは ctx を参照していない（単に “フックされる” ことの確認用）。
 */
SEC("xdp")
int hello(struct xdp_md *ctx) {
    /*
     * bpf_printk():
     * - カーネルのトレースバッファに文字列を出力するための BPF helper。
     * - 典型的には /sys/kernel/debug/tracing/trace_pipe 等で確認する。
     *
     * ここでは counter の値を埋め込んで "Hello World <counter>" を出している。
     * ※ XDP はパケットごとに呼ばれるので、ログが大量に出てパフォーマンスが落ちやすい。
     */
    bpf_printk("Hello World %d", counter);

    /*
     * counter のインクリメント
     * - 競合する可能性が高い（同時に複数のパケット処理が走る）。
     * - 正確なカウントや整合性が必要なら、atomic 操作や per-cpu map を検討する。
     */
    counter++;

    /*
     * XDP_PASS:
     * - パケットを “通常通り” カーネルのネットワークスタックへ渡す。
     * - つまり、このプログラムは観測（ログ出力）だけで、通信動作は変えない。
     */
    return XDP_PASS;
}

/*
 * ライセンス宣言
 *
 * eBPF プログラムはライセンス文字列を持つ必要がある。
 * "Dual BSD/GPL" は libbpf サンプルでもよく使われる形式で、
 * GPL-only のシンボル（helper/機能）を使う場合に許可される扱いになりやすい。
 *
 * SEC("license") により、この文字列が eBPF オブジェクトのライセンスとして埋め込まれる。
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
