#!/usr/bin/python3
# =============================================================================
# 【あなたの環境で動く版】BCC + eBPF: UID ごとの execve/execveat 回数をカウント
# =============================================================================
#
# 背景（今回の環境差のポイント）
#   あなたの Ubuntu(guest, VirtualBox) 環境では、
#     - kprobe で __x64_sys_execve 等に刺しても「刺さるが発火しない」ケースがあった
#     - raw tracepoint sys_enter も ctx の解釈が合わず、syscall番号フィルタが機能しなかった
#   ため、最も安定して動いた
#     - syscalls:sys_enter_execve / syscalls:sys_enter_execveat の tracepoint
#   を正面から使う方式（TRACEPOINT_PROBE マクロ）に寄せる。
#
# このスクリプトの目的
#   - execve / execveat（プロセス生成＝実行）イベントが発生するたびに
#     “実効 UID” ごとのカウントを 1 増やす
#   - カウントは eBPF map（counter_table）に保持し、ユーザ空間(Python)で定期表示する
#
# 実行方法（重要: 権限）
#   sudo -E /usr/bin/python3 -u hello-map.py
#
# 動作確認（同じゲストUbuntu内の別ターミナルで）
#   /bin/echo hello
#   /usr/bin/ls >/dev/null
#   を何回か叩くと、UID=1000 などのカウントが増える
#
# =============================================================================

from bcc import BPF
from time import sleep

# -----------------------------------------------------------------------------
# eBPF プログラム（C 風コード）
# -----------------------------------------------------------------------------
program = r"""
#include <uapi/linux/ptrace.h>

// BPF_HASH(counter_table, u32, u64);
//   - eBPF map（ハッシュ）を 1 個定義する
//   - key: u32 = UID（通常 32bit）
//   - val: u64 = カウンタ（増え続けるので 64bit）
//
// ※元サンプルは型省略（BPF_HASH(counter_table);）だが、型を明示すると
//   ユーザ空間側の key/value 解釈が安定し、環境差で事故りにくい。
BPF_HASH(counter_table, u32, u64);

// ----------------------------------------------------------------------------
// 共通処理: その時点の UID のカウンタを 1 増やす
// ----------------------------------------------------------------------------
static __always_inline int count_up(void) {
    // bpf_get_current_uid_gid():
    //   64bit の戻り値に (gid<<32 | uid) が詰まっている
    //   下位32bitが UID なので取り出して u32 として扱う
    u32 uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    // 初回挿入用 0
    u64 zero = 0;

    // lookup_or_init:
    //   - すでに uid のエントリがあれば、その値へのポインタが返る
    //   - なければ zero で初期化して挿入し、その値へのポインタが返る
    //
    // 元サンプルの
    //   lookup -> NULL判定 -> counter取り出し -> counter++ -> update
    // を、より短く安全にしたもの。
    u64 *p = counter_table.lookup_or_init(&uid, &zero);

    // verifier 観点で NULL チェックは必須（NULL の可能性は 0 ではない）
    if (p) {
        // 注意（並行性）:
        //   同一 UID のイベントが高頻度で多CPU同時に発生すると、
        //   ここは read-modify-write なので取りこぼしが起き得る。
        //   学習用としては十分だが、厳密な集計では PERCPU map を検討する。
        (*p)++;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 【あなたの環境で安定】tracepoint: syscalls:sys_enter_execve
// ----------------------------------------------------------------------------
// TRACEPOINT_PROBE(syscalls, sys_enter_execve)
//   - “syscalls” カテゴリの “sys_enter_execve” tracepoint に対応する。
//   - BCC が定番として用意している書き方で、環境差に強い。
//   - 引数（ctx）は今回使わないので参照しない。
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    return count_up();
}

// ----------------------------------------------------------------------------
// tracepoint: syscalls:sys_enter_execveat
// ----------------------------------------------------------------------------
// execve だけでなく execveat 経由もあるため、両方カウントして取りこぼしを減らす。
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    return count_up();
}
"""

# -----------------------------------------------------------------------------
# ユーザ空間側: eBPF をコンパイル/ロード
# -----------------------------------------------------------------------------
print("[1] building BPF (compile+load)...", flush=True)
b = BPF(text=program)
print("[2] BPF built.", flush=True)

# -----------------------------------------------------------------------------
# ここが “元サンプルからの重要な変更点”
# -----------------------------------------------------------------------------
# 元サンプル:
#   syscall = b.get_syscall_fnname("execve")
#   b.attach_kprobe(event=syscall, fn_name="hello")
#
# あなたの環境では kprobe が「刺さるが発火しない」ことがあったので、
# syscalls tracepoint に寄せる（TRACEPOINT_PROBE を使う）構成に変更した。
#
# そのため Python 側で attach_kprobe / attach_tracepoint を明示しない。
# BPF(text=...) でプログラムをロードした時点で、
# TRACEPOINT_PROBE が対応する tracepoint に結び付く形になりやすく、安定する。

print("[3] entering user loop (printing every 2s)...", flush=True)

# -----------------------------------------------------------------------------
# 2 秒ごとに map を読み出して UID ごとのカウントを表示
# -----------------------------------------------------------------------------
while True:
    sleep(2)

    # 表示の “無反応” を減らすため、tick を出す
    print("[tick] dump counter_table", flush=True)

    s = ""
    for k, v in b["counter_table"].items():
        # k.value: UID（u32）
        # v.value: execve/execveat 回数（u64）
        s += f"ID {k.value}: {v.value}\t"

    # map が空なら空だと分かる表示にする
    print(s if s else "(no entries yet)", flush=True)

# =============================================================================
# 動作イメージ（図解）
# =============================================================================
#
#      execve/execveat 発生（/bin/echo, ls などが実行される）
#  ┌──────────────────────────────────────────────────────────────┐
#  │ ユーザ空間プロセス                                           │
#  │   /bin/echo hello                                            │
#  │   /usr/bin/ls                                                │
#  └───────────────┬──────────────────────────────────────────────┘
#                  │
#                  ▼
#        tracepoint: syscalls:sys_enter_execve / sys_enter_execveat
#                  │
#                  ▼
#        eBPF: TRACEPOINT_PROBE(...) → count_up()
#                  │
#                  ▼
#        counter_table[uid]++  （カーネル内 map 更新）
#                  │
#                  ▼
#  ┌──────────────────────────────────────────────────────────────┐
#  │ Python ループ（2秒ごと）                                     │
#  │   b["counter_table"].items() で map を読み出して表示          │
#  └──────────────────────────────────────────────────────────────┘
#
# =============================================================================
