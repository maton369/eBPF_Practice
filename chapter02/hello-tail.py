#!/usr/bin/python3
# =============================================================================
# BCC を用いた eBPF サンプル（詳細コメント付き）
#   - raw tracepoint "sys_enter"（全 syscalls 入口）に 1 本だけフックする
#   - そこで「syscall番号(opcode)」を取り出し、
#     BPF_PROG_ARRAY（プログラム配列）を使って “指定した syscall 番号だけ”
#     別の eBPF 関数へジャンプ（tail call）させる
#
# 何が嬉しいか（アルゴリズムの狙い）
#   - 全 syscalls は非常に頻繁に起きるため、毎回 if/switch で分岐すると重い。
#   - BPF_PROG_ARRAY + tail call を使うと、
#       「syscall番号 → 対応する eBPF 関数へ O(1) で分岐」
#     ができ、分岐処理が高速でスケールしやすい。
#
# 重要な注意（あなたの環境での落とし穴）
#   - あなたの環境では raw tracepoint の引数解釈が合わず、
#     ctx->args[0] が syscall番号にならない等の問題が出ていた。
#   - このサンプルは ctx->args[1] を syscall番号として扱っているが、
#     環境によっては 0/1 の位置が違う、あるいは raw tracepoint 自体が不安定な場合がある。
#   - もし “期待した syscall番号で動かない/何も出ない” 場合は、
#     syscalls tracepoint（sys_enter_execve 等）方式へ寄せるのが確実。
#
# 実行方法（通常 root が必要）
#   sudo -E /usr/bin/python3 -u tailcall-sysenter.py
#
# =============================================================================

from bcc import BPF
import ctypes as ct  # BPF map の key/value に ctypes を使う（BCC のテーブルAPIの都合）

# -----------------------------------------------------------------------------
# eBPF プログラム（C 風コード）
# -----------------------------------------------------------------------------
program = r"""
// ---------------------------------------------------------------------------
// BPF_PROG_ARRAY(syscall, 500);
//   - “プログラム配列（tail call 用のジャンプテーブル）” を 1 つ定義する。
//   - 名前: syscall
//   - サイズ: 500
//
// これは「インデックス = syscall 番号」と見なして使う設計。
// 例: 59(execve) なら syscall[59] に “execve専用処理” を登録しておく。
// すると dispatcher 側で syscall.call(ctx, 59) と呼ぶだけでその処理へ飛べる。
//
// tail call の特徴:
//   - いま実行中の eBPF プログラムから別の eBPF プログラムへ “ジャンプ” する。
//   - 成功すれば、呼び出し元には戻らない（関数呼び出しではなくジャンプ）。
//   - 失敗すると、呼び出し元の次の命令に続く（そのまま実行継続）。
BPF_PROG_ARRAY(syscall, 500);

// ---------------------------------------------------------------------------
// dispatcher: raw tracepoint "sys_enter" から呼ばれる入口
// ---------------------------------------------------------------------------
// raw tracepoint のコンテキストは struct bpf_raw_tracepoint_args *ctx。
// ctx->args[] に tracepoint の引数が入るが、配列のどこに何が入るかは
// “hookする tracepoint の仕様” と “環境” で変わり得る点に注意。
//
// このサンプルは ctx->args[1] を syscall番号(opcode) として扱っている。
int hello(struct bpf_raw_tracepoint_args *ctx) {
    // opcode = syscall番号（例: execve=59）
    //
    // 注意:
    //   - 本来は u64 で受けて下位32bitを使う等、型の扱いを丁寧にする方が安全。
    //   - ただし学習用として int に落としている。
    int opcode = ctx->args[1];

    // syscall.call(ctx, opcode);
    //   - tail call を試みる。
    //   - もし syscall[opcode] に有効なプログラムFDが登録されていれば、
    //     そのプログラムへジャンプする（戻ってこない）。
    //   - 登録が無い、あるいは tail call 失敗ならここから下が実行される。
    syscall.call(ctx, opcode);

    // ここに来るのは「tail call が失敗した場合」。
    // つまり:
    //   - opcode が未登録
    //   - prog_array のサイズ外
    //   - tail call 制限（回数上限等）に引っかかった
    // などが考えられる。
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

// ---------------------------------------------------------------------------
// execve 用の処理（opcode=59 を想定）
// ---------------------------------------------------------------------------
// ここは “tail call で飛んできた先” の1つ。
// syscall[59] に登録されていれば、execve時はこの関数が走る。
int hello_exec(void *ctx) {
    // execve の発火確認用のログ
    bpf_trace_printk("Executing a program");
    return 0;
}

// ---------------------------------------------------------------------------
// timer 系 syscall 用の処理
// ---------------------------------------------------------------------------
// このサンプルは 222, 226 などを “タイマー操作” とみなしてログを分けている。
// ただし、どの番号が何かはアーキやカーネルで違う可能性があるため、
// あなたが ausyscall で確認した番号を使うのが正しい。
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    // dispatcher と同様に opcode を取り出す
    int opcode = ctx->args[1];

    // opcode で分岐してメッセージを変える（タイマー操作の分類の例）
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// ignore 用の処理
// ---------------------------------------------------------------------------
// 多くの syscall は興味がないので、何もしない “ダミー” を用意する。
// dispatcher 側で tail call 先としてこれを入れておけば、
// ほぼノーコストで “無視” できる（ログも出さない）。
int ignore_opcode(void *ctx) {
    return 0;
}
"""

# -----------------------------------------------------------------------------
# ユーザ空間側: eBPF をコンパイル/ロード
# -----------------------------------------------------------------------------
# BPF(text=program) により eBPF C コードをコンパイルし、カーネルへロードする。
b = BPF(text=program)

# -----------------------------------------------------------------------------
# raw tracepoint "sys_enter" に dispatcher(hello) を attach
# -----------------------------------------------------------------------------
# sys_enter:
#   - “全 syscalls の入口” で発火する。
#   - 非常に高頻度になり得るため、ログ出力はすぐに大量になる。
#
# そのため、このサンプルでは
#   - 基本は ignore（何もしない）へ飛ばす
#   - 興味のある syscall番号だけ専用処理へ飛ばす
# という設計にしている。
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# -----------------------------------------------------------------------------
# tail call 先（各 eBPF 関数）をロードして FD を得る
# -----------------------------------------------------------------------------
# b.load_func(name, prog_type):
#   - eBPF プログラム内の関数を「独立した BPF プログラム」としてロードし、
#     その FD（ファイルディスクリプタ）を返す。
#
# ここが重要:
#   - BPF_PROG_ARRAY に登録するのは「BPFプログラム FD」なので、
#     まず load_func で FD を得る必要がある。
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn   = b.load_func("hello_exec",     BPF.RAW_TRACEPOINT)
timer_fn  = b.load_func("hello_timer",    BPF.RAW_TRACEPOINT)

# -----------------------------------------------------------------------------
# プログラム配列（BPF_PROG_ARRAY）のテーブルを取得
# -----------------------------------------------------------------------------
prog_array = b.get_table("syscall")

# -----------------------------------------------------------------------------
# 初期化: まず全部 ignore にする
# -----------------------------------------------------------------------------
# “全syscalls” が対象なので、最初から全部ログ出すと地獄になる。
# そこで syscall[0..N) を ignore_fn.fd で埋めておき、
# 後から興味のある番号だけ上書きする。
#
# len(prog_array) は “配列サイズ” に相当する（ここでは 500）。
for i in range(len(prog_array)):
    # key: ctypes の int
    # val: “登録したい BPF プログラムの FD” を int として渡す
    prog_array[ct.c_int(i)] = ct.c_int(ignore_fn.fd)

# -----------------------------------------------------------------------------
# 有効化したい syscall番号だけ、専用処理へ差し替える
# -----------------------------------------------------------------------------
# ここで “syscall番号” は、あなたの環境の番号表に合わせる必要がある。
# 例: execve は x86_64 なら 59（あなたも ausyscall で 59 を確認済み）
#
# execve（59）: hello_exec へ
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)

# timer 系として扱いたい番号（サンプルでは 222-226 を例にしている）
# 実際に何の syscall かは ausyscall で確認して調整するのが正しい。
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# -----------------------------------------------------------------------------
# 出力: trace_pipe を読み続ける（bpf_trace_printk の出力を表示）
# -----------------------------------------------------------------------------
# b.trace_print():
#   - /sys/kernel/tracing/trace_pipe 相当を読み続け、
#     bpf_trace_printk の出力をユーザ空間に表示する。
#
# 注意:
#   - bpf_trace_printk はデバッグ用途で遅い＆出力制限がある。
#   - 本格的には perf buffer / ring buffer / map による収集にする。
b.trace_print()

# =============================================================================
# 動作のイメージ（図解）
# =============================================================================
#
# (1) sys_enter（全 syscalls）で dispatcher が必ず動く
#     ┌──────────────┐
#     │ sys_enter     │  ← 全 syscalls の入口で毎回発火
#     └──────┬───────┘
#            v
# (2) dispatcher(hello) が opcode を取り出す
#     opcode = ctx->args[1]   （環境で違う可能性あり）
#            |
#            v
# (3) prog array で tail call（O(1) 分岐）
#     syscall.call(ctx, opcode)
#        |
#        +-- opcode=59   → hello_exec へジャンプ → "Executing a program"
#        |
#        +-- opcode=222..226 → hello_timer へジャンプ → "Creating/Deleting..."
#        |
#        +-- それ以外     → ignore_opcode へジャンプ（何もしない）
#
# (4) tail call 失敗時だけ dispatcher に戻り、"Another syscall: %d" が出る
#     （通常は ignore に飛ぶので戻らない設計）
#
# =============================================================================
#
# 追加メモ（あなたの環境でハマったとき）
#   - もし execve を叩いても "Executing a program" が出ない場合、
#     ctx->args[1] が syscall番号ではない可能性が高い。
#   - その場合は “どの args に syscall番号が入っているか” を調べて修正するか、
#     既にあなたの環境で安定した syscalls tracepoint 方式へ寄せるのが確実。
#
# =============================================================================
