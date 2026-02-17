/*
 * hello-buffer-config.bpf.c（eBPF 側 / CO-RE + libbpf 想定）
 *
 * 直前のコンパイルエラーの原因:
 *   あなたの環境の <bpf/bpf_tracing.h> には BPF_KSYSCALL マクロが存在しない（または互換がない）。
 *   そのため BPF_KSYSCALL(...) の行で「expected identifier」になり、
 *   以降の pathname / argv / envp / ctx も全て未定義扱いになっていた。
 *
 * 修正方針:
 *   もっと互換性が高い「生の kprobe 形式」に落とす。
 *
 *     SEC("kprobe/__x64_sys_execve")
 *     int hello(struct pt_regs *ctx) {
 *         const char *pathname = (const char *)PT_REGS_PARM1(ctx);
 *         ...
 *         bpf_perf_event_output(ctx, &output, ...)
 *     }
 *
 * これなら
 *   - ctx が明示的に引数として存在する
 *   - syscall 引数 pathname も PT_REGS_PARM1(ctx) で確実に取り出せる
 *   - argv/envp を使わないなら一切宣言しなくて良い
 *
 * 注意:
 *   - "__x64_sys_execve" は x86_64 カーネルで一般的なシンボル名。
 *     もし attach に失敗する場合は、環境により "sys_execve" や "__x64_sys_execveat" 等があり得る。
 *     その場合は `sudo cat /proc/kallsyms | grep execve` などで存在するシンボル名に合わせる。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>   /* struct pt_regs, PT_REGS_PARM1 など */
#include <bpf/bpf_core_read.h>

#include "hello-buffer-config.h"

/* GPL 互換ライセンス宣言（helper 利用制限に影響） */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* デフォルトメッセージ（固定長 12 bytes） */
static const char default_message[12] = "Hello World";

/*
 * perf event array map（perf buffer 用）
 * - ユーザ空間側は perf_buffer__new(map_fd, ...) で購読する
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} output SEC(".maps");

/* UID ごとのメッセージ設定用 */
struct user_msg_t {
    char message[12];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

/*
 * kprobe で execve のカーネル関数にアタッチする。
 * - ctx は pt_regs（レジスタ保存領域）
 * - pathname は第1引数なので PT_REGS_PARM1(ctx) で取得できる
 */
SEC("kprobe/__x64_sys_execve")
int hello(struct pt_regs *ctx)
{
    struct data_t data = {}; /* 送るデータ（ゼロ初期化で verifier に優しい） */

    /* PID/TGID と UID を取得 */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    data.pid = (int)(pid_tgid >> 32); /* TGID */
    data.uid = (int)uid;

    /* comm（TASK_COMM_LEN=16） */
    bpf_get_current_comm(&data.command, sizeof(data.command));

    /*
     * execve の第1引数 pathname を取り出す（ユーザ空間ポインタ）
     * - kprobe の pt_regs から syscall 引数を読む
     */
    const char *pathname = (const char *)PT_REGS_PARM1(ctx);

    /* ユーザ空間の文字列を安全にコピー（NUL終端を考慮） */
    bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

    /*
     * UID に応じた message を決定
     * - map value / BPF .rodata はカーネル側メモリなので *_kernel_str を使う
     */
    {
        struct user_msg_t *p = bpf_map_lookup_elem(&my_config, &uid);
        if (p) {
            bpf_probe_read_kernel_str(&data.message, sizeof(data.message), p->message);
        } else {
            bpf_probe_read_kernel_str(&data.message, sizeof(data.message), default_message);
        }
    }

    /*
     * perf buffer へ送信
     * - ctx を第1引数に渡せるので、ここが「生 kprobe 形式」の強み
     */
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}
