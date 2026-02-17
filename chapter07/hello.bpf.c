/*
 * hello.bpf.c（CO-RE + libbpf 想定 / execve を複数のフック方式で観測するデモ）
 *
 * 目的:
 *   「execve を観測する」と言っても、eBPF には複数のアタッチ方式がある。
 *   このファイルは、同じ “execve 相当のイベント” を以下の複数手段で拾い、
 *   それぞれ「どの方式で拾ったか」を message に刻んでユーザ空間へ送信する。
 *
 *   収集する情報（data_t に詰める想定）:
 *     - pid (TGID)
 *     - uid
 *     - comm（プロセス名）
 *     - path（execve に渡された pathname / filename 等）
 *     - message（どの hook で拾ったか：kprobe / fentry / tracepoint / raw_tp など）
 *
 * 全体像（アルゴリズム）:
 *
 *   execve 発生
 *      |
 *      +--> [A] ksyscall/execve（ksyscall フック：syscall 入口付近）
 *      |
 *      +--> [B] kprobe/do_execve（関数 kprobe：do_execve を叩く）
 *      |
 *      +--> [C] fentry/do_execve（fentry：関数入口を BTF で安定的に叩く）
 *      |
 *      +--> [D] tp/syscalls/sys_enter_execve（tracepoint：sys_enter_execve）
 *      |
 *      +--> [E] tp_btf/sched_process_exec（BTF tracepoint：sched_process_exec）
 *      |
 *      +--> [F] raw_tp/sched_process_exec（raw tracepoint：sched_process_exec）
 *              |
 *              v
 *       data_t を構築して perf buffer へ転送
 *              |
 *              v
 *       user-space collector が perf_buffer__poll() で受信
 *
 * 重要ポイント（CO-RE 観点）:
 *   - vmlinux.h と BPF_CORE_READ() を使うと、
 *     カーネルの構造体（例: struct filename）のフィールド参照が
 *     バージョン差に比較的強くなる（= CO-RE らしさ）。
 *   - 一方、tracepoint の “生のフォーマット” を自前で struct 定義して読む手法は、
 *     カーネルの tracepoint format の変更に弱い（CO-RE というより “固定 ABI 依存”）。
 *
 * 取りこぼし・性能:
 *   - bpf_printk は高コストなので、実運用の検出器では最小化が基本。
 *     学習・デバッグ用途なら OK。
 */

#include "vmlinux.h"               // CO-RE 用: BTF 由来のカーネル型定義
#include <bpf/bpf_helpers.h>       // SEC, helper 宣言, map 定義補助
#include <bpf/bpf_tracing.h>       // BPF_KPROBE / BPF_PROG 等のマクロ
#include <bpf/bpf_core_read.h>     // BPF_CORE_READ（CO-RE フィールド参照）
#include "hello.h"                 // data_t, msg_t など共有定義（ユーザ空間と一致必須）

/*
 * “どの hook で拾ったか” を data.message に入れるための識別文字列。
 * 固定長 char[] にするのは verifier に優しい（ポインタより扱いやすい）。
 *
 * NOTE:
 *   - サイズ 16 の中に NUL 終端込みで収める設計。
 *   - bpf_probe_read_kernel() で data.message にコピーして使う。
 */
const char kprobe_sys_msg[16]   = "sys_execve";
const char kprobe_msg[16]       = "do_execve";
const char fentry_msg[16]       = "fentry_execve";
const char tp_msg[16]           = "tp_execve";
const char tp_btf_exec_msg[16]  = "tp_btf_exec";
const char raw_tp_exec_msg[16]  = "raw_tp_exec";

/*
 * output: PERF_EVENT_ARRAY
 *  - eBPF -> user-space へイベントを流す “出口” の map。
 *  - user-space 側はこの map fd を perf_buffer__new に渡して受信開始する。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));      // CPU id
    __uint(value_size, sizeof(u32));    // perf event の紐づけ（libbpf が面倒を見る）
} output SEC(".maps");

/*
 * my_config: HASH MAP（UID -> msg_t）
 *  - UID に応じたメッセージ差し替えなどに使える。
 *  - このファイルでは map 自体は定義されているが、
 *    いまの各 probe では “実際には参照していない” 箇所もある（将来拡張用に見える）。
 *
 * NOTE:
 *   - msg_t の layout は hello.h の定義に依存。
 *   - ユーザ空間で bpf_map__update_elem() して設定する運用が典型。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");

/* --------------------------------------------------------------------------
 * [A] ksyscall/execve（syscall フック）
 * --------------------------------------------------------------------------
 *
 * SEC("ksyscall/execve") は “syscall 入口付近” を狙う attach。
 * BPF_KPROBE_SYSCALL マクロを使うと syscall の第1引数（pathname）を直接受け取れる。
 *
 * pathname はユーザ空間ポインタなので読むときは bpf_probe_read_user / _str を使う。
 *
 * 注意（超重要）:
 *   この関数内で bpf_perf_event_output(ctx, ...) を使っているが、
 *   ctx はこのマクロの展開により暗黙に利用できる想定になっている。
 *   ただし、マクロ/セクションの組み合わせ次第で “ctx が見えない/型が合わない”
 *   というコンパイルエラーになりがちなので、環境差には注意。
 */
SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(kprobe_sys_execve, const char *pathname)
{
   /* user-space へ送る payload（hello.h の struct data_t と一致が必須） */
   struct data_t data = {};

   /*
    * message に “どの hook か” を格納。
    * kprobe_sys_msg は BPF プログラムの rodata（カーネル側）なので kernel 読みでOK。
    *
    * NOTE:
    *   文字列は *_str 系を使う方が NUL 終端が保証されやすいが、
    *   ここでは固定配列同士のコピーなので bpf_probe_read_kernel でも動きやすい。
    */
   bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_sys_msg);

   /*
    * bpf_printk:
    *   デバッグ用途のログ。高コストなので検出器では抑制推奨。
    *
    * 注意:
    *   pathname はユーザ空間ポインタなので “そのまま %s” で出すのは危険になり得る。
    *   実運用では data.path にコピーしてから data.path を出す方が安全。
    */
   bpf_printk("%s: pathname: %s", kprobe_sys_msg, pathname);

   /* pid/uid/comm を収集 */
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));

   /*
    * pathname を data.path にコピー。
    * - pathname はユーザ空間ポインタ
    * - bpf_probe_read_user は “NUL 終端を保証しない”
    *
    * 改善案:
    *   パス文字列を扱うなら bpf_probe_read_user_str の方が安全。
    */
   bpf_probe_read_user(&data.path, sizeof(data.path), pathname);

   /*
    * perf buffer へ送信。
    * - BPF_F_CURRENT_CPU: 現在の CPU のバッファへ
    */
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

/* --------------------------------------------------------------------------
 * [B] kprobe/do_execve（関数 kprobe）
 * --------------------------------------------------------------------------
 *
 * do_execve は “execve の実処理” 側に近い関数。
 * syscall 入口より内部のため、見える情報が変わったり、アーキ差が出やすい。
 *
 * CO-RE 的には:
 *   - struct filename のフィールド参照は BPF_CORE_READ を使うことで
 *     バージョン差耐性を上げられる（ここは CO-RE の良い例）。
 *
 * ARM64 ではシンボル/実装差の都合で動かないことがあるため ifdef で除外している。
 */
#ifndef __TARGET_ARCH_arm64
SEC("kprobe/do_execve")
int BPF_KPROBE(kprobe_do_execve, struct filename *filename)
{
   struct data_t data = {};

   /* message に hook 種別を格納 */
   bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_msg);

   /* pid/uid/comm を収集 */
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));

   /*
    * struct filename *filename の中の name フィールドを読む。
    * BPF_CORE_READ(filename, name) は CO-RE の核心：
    *   - BTF に基づき、カーネルの layout 差を吸収する relocation を生成する。
    */
   const char *name = BPF_CORE_READ(filename, name);

   /*
    * name はカーネルメモリ上の文字列ポインタなので kernel 読みでコピー。
    * 改善案:
    *   文字列なら bpf_probe_read_kernel_str の方が終端保証が得られやすい。
    */
   bpf_probe_read_kernel(&data.path, sizeof(data.path), name);

   /* デバッグログ */
   bpf_printk("%s: filename->name: %s", kprobe_msg, name);

   /* perf buffer へ送信 */
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}
#endif /* !__TARGET_ARCH_arm64 */

/* --------------------------------------------------------------------------
 * [C] fentry/do_execve（fentry）
 * --------------------------------------------------------------------------
 *
 * fentry は “関数の入口に BTF で安定的にアタッチ” できる方式。
 * 従来の kprobe よりもオーバーヘッドが小さく、シンボル解決が安定しやすいことが多い。
 *
 * ただし:
 *   - カーネル設定（CONFIG_BPF_TRAMPOLINE 等）やバージョンで可否が変わる。
 *   - コメントにある通り ARM では 6.0 以降で対応が進んだ背景がある。
 */
#ifndef __TARGET_ARCH_arm64
SEC("fentry/do_execve")
int BPF_PROG(fentry_execve, struct filename *filename)
{
   struct data_t data = {};

   /* message に hook 種別 */
   bpf_probe_read_kernel(&data.message, sizeof(data.message), fentry_msg);

   /* pid/uid/comm */
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));

   /* CO-RE で filename->name を参照 */
   const char *name = BPF_CORE_READ(filename, name);

   /* name は kernel pointer */
   bpf_probe_read_kernel(&data.path, sizeof(data.path), name);

   bpf_printk("%s: filename->name: %s", fentry_msg, name);

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}
#endif /* !__TARGET_ARCH_arm64 */

/* --------------------------------------------------------------------------
 * [D] tracepoint: syscalls/sys_enter_execve
 * --------------------------------------------------------------------------
 *
 * tracepoint は “トレース用に定義された安定したイベント” を購読する方式。
 * ただし、ここでやっているのは「tracepoint の format を見て自前 struct を作る」方式で、
 * CO-RE というより “tracepoint format 依存” の実装。
 *
 * より堅くするなら:
 *   - vmlinux.h に tracepoint の型が入るケース（tp_btf）を使う
 *   - もしくは libbpf の CO-RE 寄りの仕組みで BTF type を使う（環境依存）
 */

/*
 * tracepoint format の説明コメントに基づいて定義した構造体。
 *
 * 注意:
 *   - tracepoint の field offset/size はカーネルの定義に依存する。
 *   - 少しでもズレると ctx の解釈が壊れる。
 *   - 実運用で “長期安定” を狙うなら tp_btf を優先しがち。
 */
struct my_syscalls_enter_execve {
	unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

	long syscall_nr;
	void *filename_ptr;   /* const char * filename; のつもり */
	long argv_ptr;
	long envp_ptr;
};

SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct my_syscalls_enter_execve *ctx)
{
   struct data_t data = {};

   /* message に hook 種別 */
   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg);

   /*
    * デバッグログ:
    *   ctx->filename_ptr はユーザ空間ポインタの想定。
    *   それを %s で直接出すのは危険なので、本来はコピーした data.path を出すのが安全。
    */
   bpf_printk("%s: ctx->filename_ptr: %s", tp_msg, ctx->filename_ptr);

   /* pid/uid/comm */
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));

   /*
    * filename_ptr はユーザ空間 pointer なので user 読みでコピー。
    * 改善案:
    *   bpf_probe_read_user_str を使うと終端保証が強くなる。
    */
   bpf_probe_read_user(&data.path, sizeof(data.path), ctx->filename_ptr);

   /* perf buffer へ */
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

/* --------------------------------------------------------------------------
 * [E] tp_btf: sched_process_exec（BTF tracepoint）
 * --------------------------------------------------------------------------
 *
 * BTF tracepoint は “tracepoint だけど ctx の型が BTF で提供される” 方式。
 * ここでは vmlinux.h に定義されている trace_event_raw_sched_process_exec を使う。
 *
 * CO-RE 的に強い点:
 *   - ctx の型が BTF 由来なので、手書き struct より安全になりやすい。
 *
 * 注意:
 *   - ただし、フィールドが 8-byte 境界に揃っていない等で verifier に嫌われることがある。
 *     コメントにも “8-byte boundary” 問題が書かれている。
 */
SEC("tp_btf/sched_process_exec")
int tp_btf_exec(struct trace_event_raw_sched_process_exec *ctx)
{
   struct data_t data = {};

   /* message */
   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_btf_exec_msg);

   /* pid/uid */
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   /*
    * TODO 部分:
    *   ctx から追加情報（実行ファイル名等）を取りたいが、
    *   アラインメントや verifier 制約で読み方に工夫が必要。
    *
    * よくある回避策:
    *   - bpf_core_read / bpf_probe_read_kernel を 4/8 byte 単位で分ける
    *   - BPF_CORE_READ_STR_INTO を使う（環境による）
    *   - いったん pointer を取り、その先を *_str で読む
    */

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

/* --------------------------------------------------------------------------
 * [F] raw tracepoint: sched_process_exec
 * --------------------------------------------------------------------------
 *
 * raw_tp は “最も低レベルで汎用” だが、ctx の解釈が難しくなりがち。
 * ここでは bpf_raw_tracepoint_args を受けているだけで、
 * exec 情報（filename など）は読んでいない。
 *
 * 学習用途としては:
 *   - “raw_tp でもイベントは拾える”
 *   - “ただし中身を解釈するのは面倒”
 * を体感できる良いサンプル。
 */
SEC("raw_tp/sched_process_exec")
int raw_tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
   struct data_t data = {};

   /* message */
   bpf_probe_read_kernel(&data.message, sizeof(data.message), raw_tp_exec_msg);

   /* pid/uid */
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   /* perf output */
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

/*
 * ライセンス宣言:
 *   GPL 互換でないと使えない helper があるため、
 *   学習でも “必ず license を入れる” のが基本。
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
