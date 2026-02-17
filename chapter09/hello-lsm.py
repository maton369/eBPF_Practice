#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
このスクリプトは BCC（BPF Compiler Collection）を使って、
LSM（Linux Security Modules）のフックポイント
security_file_permission() を eBPF で監視し、
特定 UID（ここでは 1001）のプロセスがファイルへアクセスしようとした瞬間を
trace_pipe へログ出力するサンプルである。

ポイント
- 「パケット」ではなく「カーネルのセキュリティ判定関数」をフックする。
- 対象は file permission チェックなので、open/read/write/exec などの前後で呼ばれ得る。
- BCC の trace_print() は /sys/kernel/debug/tracing/trace_pipe を読み続けて表示する。

前提
- root 権限で実行すること（eBPF ロードと trace_pipe 読み取りに必要）
- カーネルが BTF / BPF / LSM hook を扱える構成であること
- BCC が KFUNC_PROBE を使えるビルド/バージョンであること（環境差あり）
"""

from bcc import BPF

# eBPF C プログラム本体（BCC が clang でコンパイルしてカーネルへロードする）
program = r"""
#include <linux/fs.h>      // struct file, file->f_path などの定義
#include <linux/dcache.h>  // dentry->d_iname などを参照する場合に関係（環境により不要/必要）
#include <linux/path.h>    // struct path（f_path）など

/*
 * 監視対象（LSM フック）
 *
 * security_file_permission(struct file *file, int mask)
 * - ファイルアクセスの権限チェックをする際に呼ばれる LSM hook。
 * - mask は「どの操作をしようとしているか」を表すビット集合（例: MAY_READ/MAY_WRITE/MAY_EXEC 等）。
 *
 * ここでは BCC の KFUNC_PROBE を使って「カーネル関数（kfunc）」としてフックしている。
 * （注意: 環境によっては kprobe/kfunc/lsm の attach 方式が変わる。
 *  KFUNC_PROBE が利用できない場合は LSM("...") や kprobe を使う実装に切り替える必要がある。）
 */
KFUNC_PROBE(security_file_permission, struct file *f, int mask)
{
  /*
   * comm（プロセス名）取得用バッファ。
   *
   * 注意:
   * - bpf_get_current_comm が返すのは TASK_COMM_LEN（通常16 bytes）相当の短い名前であり、
   *   ここで 256 bytes を確保しても実際に埋まるのは先頭の短い部分である。
   * - ただし大きめのバッファを持っていても verifier 的には問題になりにくい（スタック制約はあるが）。
   *   LSM など頻繁に呼ばれるパスで巨大スタックを使うのは避けたいので、実務的には 16〜32 程度が多い。
   */
  char command[256];

  /*
   * 現在実行中のタスクの comm（短いコマンド名）を取得する。
   * - 例: "bash", "python3", "sshd" など
   */
  bpf_get_current_comm(command, sizeof(command));

  /*
   * 現在実行中タスクの UID/GID を取得する。
   * bpf_get_current_uid_gid() は 64bit 値で、
   *   lower 32bit: UID
   *   upper 32bit: GID
   * なので UID だけ欲しければ lower を取り出す。
   */
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  /*
   * フィルタリング:
   *   UID=1001 のプロセスだけを対象にする。
   *
   * この early return が重要で、
   * - LSM フックは頻繁に呼ばれる可能性がある
   * - trace_printk は重い
   * ので、対象を絞らないとログが爆発して観測不能になる。
   */
  if (uid != 1001) {
    return 0; // 0 を返す = 「ここで拒否しない（許可/継続）」という意味合い
  }

  /*
   * ログ出力（trace_pipe へ）
   *
   * bpf_trace_printk はデバッグ向けで、性能コストが高い。
   * 学習用途には便利だが、検出器として実装するなら
   * - perf buffer / ring buffer で userspace にイベント送信
   * - map に統計を溜めて周期的に読む
   の方が現実的。
   *
   * ここで出している情報:
   * - File %s : f->f_path.dentry->d_iname
   *   これは「dentry の短い名前（basename っぽいもの）」であり、
   *   フルパスではない点に注意。
   *   例: "/etc/passwd" なら "passwd" だけになることがある。
   *
   * - mask %x : 権限チェックの種類（ビット集合）
   *   例（代表例）:
   *     MAY_READ  = 0x4
   *     MAY_WRITE = 0x2
   *     MAY_EXEC  = 0x1
   *   実際の値はカーネルの定義に依存するので、必要なら userspace 側で復号するとよい。
   *
   * 注意（BPF 安全性/互換性）:
   * - f->f_path.dentry->d_iname の直接参照は、環境や verifier によっては
   *   「直接ポインタ追跡が危険」とみなされることがある。
   * - CO-RE + BPF_CORE_READ を使う、または bpf_d_path が使える attach 方式を選ぶ、
   *   などの“堅い”取り方に寄せると移植性が上がる。
   */
  bpf_trace_printk("File %s mask %x", f->f_path.dentry->d_iname, mask);
  bpf_trace_printk("     opened by: %s", command);

  /*
   * 0 を返す:
   * - LSM hook は「0=許可、負値=-EPERM 等=拒否」という慣習で実装されることが多い。
   * - このプログラムは観測だけなので常に 0 を返す。
   *
   * もし「UID=1001 の書き込みを拒否」などをやりたいなら、
   * mask を見て条件一致で -EPERM を返す（ただし安全性と影響が大きいので注意）。
   */
  return 0;
}
"""

# BPF(text=...) により、上の eBPF C コードをコンパイルしてカーネルへロードする。
# - 失敗する場合、BTF/attach方式/ヘッダ/権限などが原因になりやすい。
b = BPF(text=program)

# trace_print() は trace_pipe を読み続けて表示する（Ctrl-C で終了）
# - bpf_trace_printk の出力がここに流れる
b.trace_print()
