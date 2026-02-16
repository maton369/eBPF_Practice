#!/usr/bin/python3
# -*- coding: utf-8 -*-

# このスクリプトは BCC (BPF Compiler Collection) を使って、
# 「プロセスが execve() される瞬間（= 新しいプログラムが起動する瞬間）」を kprobe で捕まえ、
# eBPF 側で収集したデータ（PID/UID/コマンド名/メッセージ）を perf buffer 経由で
# ユーザ空間（Python）へ送って表示するデモである。
#
# 全体像（ざっくり）
#  1) Python が eBPF C プログラム文字列をカーネルにロード
#  2) kprobe を execve に attach
#  3) execve が呼ばれるたびに eBPF 関数 hello() が走る
#  4) hello() が PID/UID/comm と「UID ごとのメッセージ」を用意して perf_submit
#  5) Python が perf buffer を poll して print_event() で表示

from bcc import BPF
import ctypes as ct

# BPF に渡す C コードは raw 文字列として記述する。
# ここに書いたものが「カーネル内で動く eBPF プログラム」になる。
program = r"""
// ─────────────────────────────────────────────────────────────
// eBPF 側のデータ構造とマップ定義
// ─────────────────────────────────────────────────────────────

// ユーザが UID ごとに設定する "メッセージ" を保持する値型。
// message[13] としているのは "Hey root!"(9 bytes + '\0') などを入れる想定で、
// 終端 '\0' も含めて少し余裕を見たい、という意図が多い。
// ただし下の data_t.message は 12 なので、実際にコピーする際はサイズ差に注意が必要。
struct user_msg_t {
   char message[13];
};

// BPF_HASH(name, key_type, value_type)
// これは eBPF のマップ（カーネル内の key-value ストア）を定義する。
// config: key=u32(UID), value=user_msg_t(UID ごとのメッセージ)
BPF_HASH(config, u32, struct user_msg_t);

// BPF_PERF_OUTPUT(name)
// ユーザ空間へイベントを送るための perf buffer 出口を定義する。
// eBPF -> (perf buffer) -> Python の callback で受け取れる。
BPF_PERF_OUTPUT(output);

// perf buffer に流す "イベント本体" の構造体。
// ここはユーザ空間(Python)でも同じレイアウトで読む必要があるため、
// 固定長配列などを使って ABI を安定させている。
struct data_t {
   int pid;               // プロセスID（厳密には tgid を入れる実装になっている）
   int uid;               // ユーザID
   char command[16];      // comm（タスク名）: bpf_get_current_comm の返す 16bytes
   char message[12];      // 表示メッセージ（固定長）
};

// ─────────────────────────────────────────────────────────────
// eBPF プログラム本体（kprobe から呼ばれる）
// ─────────────────────────────────────────────────────────────
//
// hello(void *ctx)
// ここでの ctx は kprobe のコンテキスト（レジスタ状態等）で、
// perf_submit の第一引数に渡すために受け取っている。
// kprobe の引数を取りたい場合は ctx から読むが、この例では使わない。
int hello(void *ctx) {
   // perf buffer に送るデータをゼロ初期化して確保する。
   // eBPF の verifier は「未初期化メモリの利用」を嫌うので {} 初期化は重要。
   struct data_t data = {};

   // config マップから引くためのポインタ（値型 user_msg_t への参照）
   struct user_msg_t *p;

   // config に該当が無い場合のデフォルトメッセージ。
   // char message[12] は data.message と同じサイズに合わせている。
   char message[12] = "Hello World";

   // bpf_get_current_pid_tgid() は 64bit 値を返す:
   //   上位32bit: tgid（一般に "プロセスID" と呼ぶもの）
   //   下位32bit: pid（スレッドID）
   // ここでは上位32bit を取りたいので >> 32 している。
   data.pid = bpf_get_current_pid_tgid() >> 32;

   // bpf_get_current_uid_gid() も 64bit 値:
   //   下位32bit: uid
   //   上位32bit: gid
   // ここでは uid が欲しいので下位32bit を & 0xFFFFFFFF で取っている。
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   // 現在タスクの comm（コマンド名っぽい短い識別子）を取得する。
   // 最大 16 バイト（終端含む）なので data.command[16] と揃えるのが定石。
   bpf_get_current_comm(&data.command, sizeof(data.command));

   // config マップを UID をキーに lookup し、ユーザごとのメッセージがあるか確認する。
   // 注意: config の key 型は u32 なので data.uid(int) を u32 として扱っているイメージ。
   // BCC の lookup は「キーのアドレス」を渡すスタイルなので &data.uid となる。
   p = config.lookup(&data.uid);

   if (p != 0) {
      // UID 用の設定があった場合:
      // p->message を data.message にコピーして出力する。
      //
      // ここで bpf_probe_read_kernel を使っているが、
      // マップの値は verifier 的には直接参照できる場合もあり、
      // BCC の例では probe_read を使う書き方が混ざりがち。
      // 学習としては「安全にコピーする」意図と理解すればよい。
      //
      // サイズは data.message(12) を基準にしているので、
      // user_msg_t.message(13) の最後の1byte（終端など）は落ちる可能性がある。
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
   } else {
      // UID 用の設定が無い場合: デフォルト "Hello World" をコピーする
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
   }

   // perf buffer へイベントを送信する。
   // ctx は kprobe のコンテキスト、&data は送るデータ、sizeof(data) はサイズ。
   output.perf_submit(ctx, &data, sizeof(data));

   // kprobe のハンドラとしては 0 を返して終了
   return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# ユーザ空間（Python）側：ロード、アタッチ、設定、受信
# ─────────────────────────────────────────────────────────────

# BPF(text=...) で eBPF プログラムをコンパイル＆ロードする。
# 内部では clang/LLVM を使って eBPF バイトコードにしてカーネルへ渡す。
b = BPF(text=program)

# b.get_syscall_fnname("execve")
# カーネルのバージョンや設定によって、syscall の実体シンボル名は変わりうる。
# 例: "__x64_sys_execve", "sys_execve" など。
# BCC がその差異を吸収して「今の環境での execve の関数名」を返してくれる。
syscall = b.get_syscall_fnname("execve")

# execve の kprobe に eBPF 関数 hello を attach する。
# 以後、execve が呼ばれるたびに hello() がカーネル内で実行される。
b.attach_kprobe(event=syscall, fn_name="hello")

# ─────────────────────────────────────────────────────────────
# config マップに UID ごとのメッセージを設定する
# ─────────────────────────────────────────────────────────────
#
# eBPF 側: BPF_HASH(config, u32, struct user_msg_t);
# Python 側: b["config"][key] = value で書き込める。
#
# ここでは UID=0(root) と UID=501 にメッセージを設定する。
# ct.create_string_buffer(...) は NUL 終端付きのバッファを作り、
# BCC がそれを user_msg_t の message 配列へ詰めてくれる挙動を期待している。

b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
b["config"][ct.c_int(501)] = ct.create_string_buffer(b"Hi user 501!")

# perf buffer でイベントを受け取ったときのコールバック。
# 引数:
#   cpu  : どのCPUでイベントが発生したか
#   data : 生のバイト列ポインタ
#   size : データサイズ
def print_event(cpu, data, size):
   # b["output"].event(data) で、data_t 構造体として解釈して Python オブジェクトにする。
   data = b["output"].event(data)

   # command/message は固定長 char 配列なので .decode() して文字列にする。
   # 末尾に '\0' が入っている場合もあるので、表示上は余計な NUL が見えることがある。
   # 必要なら .split(b'\0', 1)[0] のようにトリムしてもよい。
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# perf buffer を open し、イベント到着時に print_event を呼ぶよう登録する。
b["output"].open_perf_buffer(print_event)

# 無限ループで perf buffer をポーリングし続ける。
# execve が起きると eBPF が perf_submit し、ここで callback が実行される。
while True:
   b.perf_buffer_poll()

# ─────────────────────────────────────────────────────────────
# 補足（学習ポイント）
# ─────────────────────────────────────────────────────────────
# - このスクリプトを動かした状態で別ターミナルから `ls` や `bash` などを実行すると、
#   execve が走るのでイベントが流れてくる。
# - UID ごとのメッセージは config マップで切り替わる。
# - printk ではなく perf buffer を使っているので、
#   カーネルログに依存せずユーザ空間で扱いやすいのが利点。
