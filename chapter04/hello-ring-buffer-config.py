#!/usr/bin/python3
# -*- coding: utf-8 -*-

# ============================================================
# BCC + eBPF（C文字列埋め込み）で execve をフックし、
# 「PID / UID / comm / メッセージ」をユーザ空間へイベント送信して表示するサンプル。
#
# 以前の PERF_OUTPUT 版と違い、今回は Ring Buffer（BPF_RINGBUF_OUTPUT）を使う。
# Ring Buffer は perf buffer よりも設計がシンプルで、低オーバーヘッドになりやすい。
#
# ざっくりデータフロー：
#   execve 発生
#     → kprobe で eBPF 関数 hello() 実行
#     → pid/uid/comm と message を data_t に詰める
#     → ringbuf_output でユーザ空間へ送信
#     → Python 側コールバック print_event が受信して print
# ============================================================

from bcc import BPF
import ctypes as ct

# ------------------------------------------------------------
# eBPF C プログラム本体を Python 文字列として埋め込む。
# r""" ... """ は raw string（バックスラッシュ等のエスケープを抑制）で、
# C コード中の \n や \t を Python 側が余計に解釈しないための定番。
# ------------------------------------------------------------
program = r"""
/*
 * ユーザごとのメッセージを格納する value 構造体。
 *
 * 注意：
 * - message[12] は固定長配列であり、「文字列終端 '\0'」も含めて 12 バイト。
 * - "Hello World" は 11 文字 + '\0' = 12 なのでピッタリ収まる。
 * - "Hey root!" は 8 文字 + '\0' = 9 なので余裕で収まる。
 * - 12 を超える文字列を入れると途中で切れる（または終端が入らず表示が崩れる）ので注意。
 */
struct user_msg_t {
   char message[12];
};

/*
 * BPF_HASH(map名, key型, value型)
 *   - ここでは config というハッシュマップを作る。
 *   - key: u32（UID を想定）
 *   - value: struct user_msg_t（その UID 向けの message）
 *
 * ユーザ空間（Python）から b["config"][uid] = ... の形で書き込み、
 * eBPF 側で config.lookup(&uid) して参照する。
 */
BPF_HASH(config, u32, struct user_msg_t);

/*
 * Ring Buffer 出力の定義。
 * BPF_RINGBUF_OUTPUT(output, 1);
 *
 * - "output" という ringbuf を作る。
 * - 第2引数は ring buffer の「ページ数」指定（BCC のマクロ定義に依存）。
 *   ※環境によって意味合いが違う/調整ポイントになる。
 *
 * ring buffer は perf buffer と違い、
 *   - 予約(reserve)→書き込み→submit
 * という流れを取る設計が一般的だが、BCC では ringbuf_output という簡易APIを提供している。
 */
BPF_RINGBUF_OUTPUT(output, 1);

/*
 * ユーザ空間へ送るイベントの payload。
 * 固定長構造体にしておくと、コピーとデコードが簡単になる。
 *
 * pid:
 *   - ここでは TGID（スレッドグループID）= 通常の PID として扱うために
 *     bpf_get_current_pid_tgid() >> 32 を使う。
 *
 * uid:
 *   - bpf_get_current_uid_gid() の下位32bitが UID。
 *
 * command:
 *   - bpf_get_current_comm で取れるコマンド名（comm）。
 *   - 最大 16 バイトで切り詰められる（カーネル仕様）。
 *
 * message:
 *   - config マップに UID があるならそのメッセージ
 *   - 無ければデフォルト "Hello World"
 */
struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
};

/*
 * kprobe から呼ばれる eBPF 関数。
 * attach_kprobe(event=syscall, fn_name="hello") により、
 * execve 実行時に hello() が走る。
 *
 * 引数 ctx は kprobe のコンテキストだが、このサンプルでは使わない。
 */
int hello(void *ctx) {
   // data_t を 0 初期化しておく（未初期化領域をユーザ空間に漏らさないのも重要）。
   struct data_t data = {};

   // デフォルトメッセージ。固定長 12 なので "Hello World" にちょうど一致。
   char message[12] = "Hello World";

   // config マップから lookup した結果を受けるポインタ。
   struct user_msg_t *p;

   // bpf_get_current_pid_tgid():
   //   上位32bit: TGID（一般にプロセスID相当）
   //   下位32bit: PID（スレッドID相当）
   // ここでは表示しやすい TGID を採用している。
   data.pid = bpf_get_current_pid_tgid() >> 32;

   // bpf_get_current_uid_gid():
   //   上位32bit: GID
   //   下位32bit: UID
   // ここでは UID を採用している。
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   // 現在のタスクの comm（コマンド名の短縮）を取得。
   // command は 16 バイト固定で、長い名前は切り詰められる。
   bpf_get_current_comm(&data.command, sizeof(data.command));

   // UID をキーにして config マップを参照する。
   // lookup に成功すると p は value のアドレスを指す（失敗なら 0）。
   p = config.lookup(&data.uid);

   if (p != 0) {
      /*
       * config に UID が登録されていた場合：
       *   p->message を data.message へコピーする。
       *
       * bpf_probe_read_kernel:
       *   - eBPF から「カーネル側メモリ」を安全に読み出すための helper。
       *   - map value はカーネル側にあるため、この形が定番になる。
       *
       * 注意：
       * - 固定長コピーなので、終端 '\0' が保証されないケースがあり得る。
       * - より「文字列として」安全に扱うなら *_str 系の helper を検討する。
       */
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
   } else {
      /*
       * config に UID が無い場合：
       *   デフォルト "Hello World" を data.message へコピーする。
       *
       * ここでも bpf_probe_read_kernel を使っているが、
       * message はスタック上（eBPF プログラム内）なので、
       * 実装や verifier の都合で「こう書くと通りやすい」ケースがある。
       * （環境によっては __builtin_memcpy などにした方が良い場合もある）
       */
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
   }

   /*
    * Ring Buffer にイベントを投げる。
    * output.ringbuf_output(&data, sizeof(data), 0)
    *
    * - 第3引数は flags（通常 0）。
    * - ring buffer は「イベントが捨てられる」可能性がある（バッファ満杯など）。
    *   本気で統計を取る場合は、ドロップ数カウントなどの設計を追加すると良い。
    */
   output.ringbuf_output(&data, sizeof(data), 0);

   return 0;
}
"""

# ------------------------------------------------------------
# ここから Python 側（ユーザ空間）ロジック
# ------------------------------------------------------------

# BPF(text=...) で eBPF プログラムをコンパイルしてロードする。
# BCC が裏で clang/llvm を呼び、BPF バイトコードを生成してカーネルへロードする。
b = BPF(text=program)

# config マップへ「UID=0(root) のメッセージ」を登録する。
#
# 注意ポイント：
# - eBPF 側は message[12] なので、ここで渡す文字列も 12 以内が安全。
# - ct.create_string_buffer は NUL 終端付きのバッファを作る。
# - key 側は u32 を想定しているので ct.c_int(0) で渡している（u32なら ct.c_uint の方が意図が明確）。
b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")

# execve のシステムコール名を環境に合わせて取得する。
# （アーキやカーネルにより __x64_sys_execve など実体名が違うので、BCC のヘルパを使う）
syscall = b.get_syscall_fnname("execve")

# kprobe を attach。これで execve が呼ばれるたびに eBPF 側 hello() が実行される。
b.attach_kprobe(event=syscall, fn_name="hello")

# ------------------------------------------------------------
# Ring Buffer の受信コールバック
# ------------------------------------------------------------
def print_event(cpu, data, size):
   """
   ring buffer から届いた生データを data_t として解釈して表示する。

   cpu: どのCPUでイベントが発生したか（参考情報）
   data: 生のバイト列ポインタ（BCC 内部表現）
   size: そのサイズ
   """
   # b["output"].event(data) で、eBPF 側の struct data_t としてデコードする。
   data = b["output"].event(data)

   # command/message は C の固定長 char 配列なので decode() して文字列化する。
   # 注意：終端 '\0' が無いケースでは、末尾にゴミが混ざって見えることがある。
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# ring buffer のオープン。
# perf buffer の open_perf_buffer と対応して、ring buffer 版が open_ring_buffer。
b["output"].open_ring_buffer(print_event)

# ------------------------------------------------------------
# メインループ：リングバッファをポーリングして受信
# ------------------------------------------------------------
while True:
   # ring_buffer_poll() がブロックしつつ、イベントが来たら print_event を呼ぶ。
   # 高頻度イベントではユーザ空間が追いつかずドロップが起きる可能性がある。
   b.ring_buffer_poll()
