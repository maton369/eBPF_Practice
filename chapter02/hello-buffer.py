#!/usr/bin/python3
# =============================================================================
# BCC を用いた eBPF サンプル（詳細コメント付き）
#   - execve（プロセスが新しいプログラムを実行する瞬間）をトリガにして、
#     「PID / UID / コマンド名 / メッセージ」をユーザ空間へイベントとして送る。
#
# 重要（あなたの環境での注意点）
#   - あなたの環境では kprobe が不安定になるケースがあった（刺さるが発火しない等）。
#   - ただし、このサンプルは “Hello World をイベントで送る” 目的なので、
#     まずは元コードの意図を崩さずに「kprobe 版」を丁寧に解説する。
#   - もし実行しても何も表示されない場合は、前に動作確認できた tracepoint 版へ
#     置き換えるのが確実（後述コメント参照）。
#
# 実行方法（root が必要）
#   sudo -E /usr/bin/python3 -u hello-perf.py
#
# 動作確認（別ターミナルで）
#   /bin/echo hello
#   /usr/bin/ls >/dev/null
#
# =============================================================================

from bcc import BPF

# -----------------------------------------------------------------------------
# eBPF プログラム（C 風コード）
# -----------------------------------------------------------------------------
program = r"""
// BPF_PERF_OUTPUT(output);
//   - eBPF からユーザ空間へ「イベント」を送るための perf buffer を定義する。
//   - 名前は output。ユーザ空間(Python)側から b["output"] で参照できる。
BPF_PERF_OUTPUT(output);

// ユーザ空間へ渡すデータ構造（イベントのペイロード）
//   - perf_submit でこの構造体を丸ごと送る。
//   - Python 側は b["output"].event(data) でこの構造体として復元して読める。
struct data_t {
   // pid: プロセスID（実体は 32bit で足りるが int で持つ）
   int pid;

   // uid: ユーザID（同様に 32bit だが int で持つ）
   int uid;

   // command: 実行中プロセスのコマンド名（comm）。
   // Linux の comm は通常 16 bytes（TASK_COMM_LEN）なので 16 にしている。
   char command[16];

   // message: "Hello World" などの任意メッセージを運ぶフィールド。
   // 文字列終端 '\0' を含める必要があるため、サイズに注意。
   // ここでは 12 bytes（"Hello World" は 11文字 + '\0' で 12）にしている。
   char message[12];
};

// kprobe から呼ばれる eBPF プログラム本体
int hello(void *ctx) {
   // struct data_t data = {};
   //   - 送信する構造体をスタックに確保して 0 初期化する。
   //   - eBPF verifier 的にも「未初期化領域を送らない」ことが重要。
   struct data_t data = {};

   // message というローカル配列に "Hello World" を用意する。
   // これは “イベントに載せたい固定文字列” の例。
   //
   // 注意:
   //   - eBPF の世界では、通常の C と同じ感覚でポインタをいじれない。
   //   - 安全のため、固定長配列に入れてからコピーする流れを取ることが多い。
   char message[12] = "Hello World";

   // bpf_get_current_pid_tgid():
   //   64bit の戻り値に (tgid<<32 | pid) が詰まっている。
   //   - 上位32bit: TGID（ユーザ空間で見る PID とほぼ同義）
   //   - 下位32bit: PID（スレッドID）
   //
   // ここでは “プロセスIDとして見たい” ので上位32bit（>> 32）を使う。
   data.pid = bpf_get_current_pid_tgid() >> 32;

   // bpf_get_current_uid_gid():
   //   64bit の戻り値に (gid<<32 | uid) が詰まっている。
   //   下位32bitが UID なので & 0xFFFFFFFF で取り出す。
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   // bpf_get_current_comm(&data.command, sizeof(data.command)):
   //   現在タスクの comm（プロセス名）を data.command に書き込む。
   //   comm は最大 16 bytes なので command[16] と整合する。
   bpf_get_current_comm(&data.command, sizeof(data.command));

   // bpf_probe_read_kernel(&data.message, sizeof(data.message), message):
   //   カーネル空間のメモリから安全に読み出すための helper。
   //
   // ここはやや “学習用の書き方” になっている点に注意:
   //   - message はこの eBPF 関数内のローカル配列であり、
   //     実際には “カーネルメモリを読む” というより “安全なコピー手段として使っている”。
   //   - BCC/カーネルのバージョンによっては、代替として
   //       __builtin_memcpy(data.message, message, sizeof(data.message));
   //     のように書く例もある。
   //
   // ただし、bpf_probe_read_kernel は環境差が出ることがあるため、
   // 動かない場合は “単純コピー” に置き換えるのが現実的。
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

   // output.perf_submit(ctx, &data, sizeof(data));
   //   - perf buffer にイベントを送信する。
   //   - ctx は “この probe が呼ばれた文脈” を示すポインタで、
   //     perf_submit はこれを使って適切な CPU の buffer に書き込む。
   //   - &data は送る構造体、sizeof(data) はサイズ。
   output.perf_submit(ctx, &data, sizeof(data));

   // 0 を返して終了（probe の定型）
   return 0;
}
"""

# -----------------------------------------------------------------------------
# ユーザ空間側: eBPF をコンパイル/ロード
# -----------------------------------------------------------------------------
b = BPF(text=program)

# -----------------------------------------------------------------------------
# フック対象の解決と attach
# -----------------------------------------------------------------------------
# execve は syscall 名だが、カーネル内部の実体関数名は環境により変わる。
# get_syscall_fnname("execve") を使うと、その環境で正しい関数名（例: __x64_sys_execve）
# を返してくれるため、ハードコードより安全。
syscall = b.get_syscall_fnname("execve")

# kprobe attach:
#   - 指定したカーネル関数の“入口”で hello(ctx) が走る。
#
# 注意:
#   - あなたの環境では kprobe が不安定なケースがあったため、
#     実行してもイベントが出ない場合は tracepoint 方式へ移行するのが確実。
b.attach_kprobe(event=syscall, fn_name="hello")

# -----------------------------------------------------------------------------
# perf buffer で受け取ったイベントを処理する Python 側コールバック
# -----------------------------------------------------------------------------
def print_event(cpu, data, size):
   # b["output"].event(data):
   #   - perf buffer から来た生データ（ポインタ）を
   #     struct data_t として Python 側で復元する。
   data = b["output"].event(data)

   # command / message は C の char 配列なので bytes として来る。
   # decode() で文字列化して表示する。
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# -----------------------------------------------------------------------------
# perf buffer をオープンして、イベント受信ループへ
# -----------------------------------------------------------------------------
# open_perf_buffer(print_event):
#   - perf buffer の購読を開始し、イベント受信時に print_event が呼ばれる。
b["output"].open_perf_buffer(print_event)

# perf_buffer_poll():
#   - ユーザ空間側で perf buffer をポーリングし、届いているイベントを捌く。
#   - これを回さないとイベントが表示されない。
while True:
   b.perf_buffer_poll()

# =============================================================================
# 動作イメージ（図解）
# =============================================================================
#
# （1）ユーザがコマンドを実行
#     /bin/echo hello
#           |
#           v
# （2）カーネルで execve が走る
#           |
#           v
# （3）kprobe が発火 → eBPF hello(ctx) 実行
#           |
#           v
# （4）PID/UID/comm/"Hello World" を data_t に詰める
#           |
#           v
# （5）perf_submit で perf buffer にイベントを流す
#           |
#           v
# （6）Python が perf_buffer_poll で受信 → print_event で表示
#
# =============================================================================
#
# 追加メモ（あなたの環境で “何も出ない” とき）
#   - まず別ターミナルで /bin/echo hello を複数回叩いて、execve を確実に起こす。
#   - それでも出ない場合は、前に成功した tracepoint 方式が安定。
#     “syscalls:sys_enter_execve / execveat に TRACEPOINT_PROBE で刺す” 版へ変換すると良い。
# =============================================================================
