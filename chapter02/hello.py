#!/usr/bin/python3
# このスクリプトは BCC (BPF Compiler Collection) を使って eBPF プログラムをロードし、
# Linux カーネル内の特定の関数（ここでは execve 系のシステムコール実装）に kprobe を仕掛けて、
# その関数が呼ばれるたびに "Hello World!" を trace_pipe に出力する最小例である。
#
# 何が学べるか
# - BCC での eBPF プログラムの「埋め込み（C文字列）→コンパイル→ロード」
# - kprobe で「カーネル関数の入口」にフックする方法
# - bpf_trace_printk でデバッグ出力し、ユーザ空間で trace_print() で読む流れ
#
# 注意:
# - bpf_trace_printk はデバッグ用途で遅い / 出力サイズ制限が強い / 本番用途には向かない。
#   本格的には perf buffer / ring buffer / map 経由でユーザ空間に渡す。
# - kprobe の対象関数名はカーネルやアーキテクチャで変わり得るため、
#   BCC の get_syscall_fnname("execve") で「その環境で正しい関数名」を引くのが重要。
# - カーネル側の eBPF C コードは verifier（安全性検証）を通る必要があり、
#   禁止されている操作（任意メモリアクセス、無限ループ等）をするとロードに失敗する。

from bcc import BPF
import sys

# eBPF 側のプログラム（C言語風のサブセット）を文字列として埋め込む。
# BCC はこれを clang/LLVM を使って BPF バイトコードにコンパイルし、カーネルへロードする。
#
# このプログラムは「hello」という関数を1つ定義している。
# attach_kprobe() でこの関数が kprobe から呼ばれるようにするため、関数シグネチャは
#   int fn(void *ctx)
# の形を取るのが BCC の典型。
program = r"""
int hello(void *ctx) {
    // bpf_trace_printk はカーネル空間から trace_pipe に文字列を出すための helper。
    // いわゆる「デバッグプリント」で、頻繁に呼ぶと性能に影響する。
    //
    // さらに実装上の制約として:
    // - 文字列長の制限がある
    // - フォーマット指定子の扱いも限定される
    // - 大量出力すると trace_pipe が詰まる / ロスする可能性がある
    //
    // ここでは最小例として固定文字列を出す。
    bpf_trace_printk("Hello World!");
    return 0; // 0 を返すのが慣例（kprobe の実行を止めたりはしない）
}
"""

# BPF(text=program):
# - program をコンパイルして eBPF バイトコード化
# - カーネルにロード
# - その後 attach_* でフックポイントに紐づけ可能な状態にする
#
# ここで失敗する典型例:
# - カーネルヘッダが無い/合ってない（BCC の環境依存）
# - verifier に弾かれる（危険な操作、スタック使いすぎ等）
b = BPF(text=program)

# get_syscall_fnname("execve"):
# execve は「プログラム実行」のシステムコール。
# ただし kprobe で刺すべきカーネル関数名は環境で変わる（例: __x64_sys_execve, sys_execve 等）。
#
# BCC が実行環境のカーネルに合わせて「正しい関数名」を推定し、返してくれる。
syscall = b.get_syscall_fnname("execve")

# attach_kprobe(event=..., fn_name=...):
# - event: kprobe を仕掛ける対象の「カーネル関数名」
# - fn_name: その kprobe が発火したときに実行する「eBPF 関数名」（program 内の hello）
#
# つまりここで「execve 系関数が呼ばれた瞬間に hello(ctx) を実行する」ように設定している。
#
# kprobe の意味:
# - カーネル関数の入口（または kretprobe なら出口）に動的にフックできる仕組み。
# - トレース/観測用途に強いが、対象関数のインライン化や最適化、カーネルバージョン差の影響を受けうる。
b.attach_kprobe(event=syscall, fn_name="hello")

# trace_print():
# bpf_trace_printk の出力先は trace_pipe（/sys/kernel/debug/tracing/trace_pipe）相当。
# BCC の trace_print() はそれを読み続けて標準出力に流す便利関数。
#
# 実行すると、execve が発生するたびに "Hello World!" が表示される。
# 例えば別ターミナルで `ls` を打つだけでも execve が呼ばれるので出る。
try:
    b.trace_print()
except KeyboardInterrupt:
    # Ctrl+C で終了したときに綺麗に抜ける
    sys.exit(0)
