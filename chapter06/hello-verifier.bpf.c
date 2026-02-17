/*
 * hello-verifier.bpf.c（CO-RE + libbpf 想定 / verifier学習用）
 *
 * 目的:
 *   eBPF verifier が「何を嫌うのか / 何を要求するのか」を、わざと境界ケースを作って学ぶためのコードである。
 *
 *   具体的には 2 種類のプログラムを 1 ファイルに含めている:
 *     1) ksyscall/execve をフックする kprobe 系（SEC("ksyscall/execve")）
 *     2) XDP（SEC("xdp")）
 *
 *   それぞれで verifier が典型的にチェックするポイント（ヌルチェック、境界チェック、ループ、return の保証など）を
 *   コメント付きで示している。
 *
 * CO-RE（Compile Once – Run Everywhere）観点:
 *   - vmlinux.h を include し、カーネルの BTF 型情報に基づいてビルド時/ロード時に型整合が取れるようにする構成。
 *   - ただしこのファイル自体は、CO-RE でフィールドアクセス（BPF_CORE_READ 等）を積極的に使っているというより、
 *     「verifier の型/境界/ポインタ解析」に焦点がある。
 *   - CO-RE を本格的に活用するなら、カーネル構造体のフィールド参照で BPF_CORE_READ を使うケースが増える。
 *
 * 注意:
 *   - グローバル変数（.bss/.data）を使う場合、実行コンテキスト/並行性で “期待通りの値” にならないことがある。
 *     verifier 的には OK でも、意味論として race になるので学習用途に限定するのが無難。
 *   - このコードは verifier の「落ちる/通る」を試すコメントが多い。実運用向けではない。
 */

#include "vmlinux.h"          // CO-RE 用: カーネル型定義（BTF 由来）
#include <bpf/bpf_helpers.h>  // SEC マクロ、helper 宣言、map 定義補助など
#include <bpf/bpf_tracing.h>  // kprobe/tracepoint 用のマクロ群
#include <bpf/bpf_core_read.h>// CO-RE の READ マクロ群（今回は主役ではないが慣習的に入れる）
#include "hello-verifier.h"   // struct data_t / struct msg_t など共有定義（想定）

/*
 * グローバル変数（BPF プログラムの .bss / .data に置かれる）
 *
 * int c:
 *   - “カウンタっぽい値” を増やしながら、境界チェックの例（< と <= の違い）を観察するために使っている。
 *   - 注意: グローバルは CPU/タスク間で共有され得る。atomic でないので race になる。
 *     verifier は「データ競合」を防いでくれない（あくまでメモリ安全/解析可能性が中心）。
 *
 * message:
 *   - 固定長文字列。境界チェックのデモで message[c] の読みを行う。
 *   - "Hello World" は 11 文字 + '\0' で 12 バイトなので配列長 12 に収まる。
 */
int c = 1;
char message[12] = "Hello World";

/*
 * output: BPF_MAP_TYPE_PERF_EVENT_ARRAY
 *
 * 目的:
 *   eBPF → ユーザ空間へイベントを送るための “出力先 map”。
 *   bpf_perf_event_output(ctx, &output, ...) がここへ書き込み、
 *   ユーザ空間側は perf_buffer__poll() などで受け取る。
 *
 * map 仕様:
 *   - key: CPU id（u32）
 *   - value: u32（内部的に perf_event の関連付けに使われる）
 *
 * NOTE:
 *   ringbuf を使う場合は map type も helper も変わる（BPF_MAP_TYPE_RINGBUF と ringbuf helper）。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

/*
 * my_config: BPF_MAP_TYPE_HASH
 *
 * 目的:
 *   uid(u32) → struct msg_t（固定長メッセージ）を引く設定マップ。
 *   “map lookup の第1引数は map ポインタでなければならない” という verifier の基本を示す。
 *
 * value 型:
 *   - struct msg_t は hello-verifier.h 側で定義されている想定。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");

/*
 * ksyscall/execve フック（kprobe っぽい文脈）
 *
 * SEC("ksyscall/execve") は、libbpf で “syscall の入口” に attach するためのセクション名。
 * ここでは関数シグネチャを “生 ctx” で受けている：
 *   int kprobe_exec(void *ctx)
 *
 * この形の狙い:
 *   - bpf_perf_event_output の第1引数 ctx をそのまま渡せる（kprobe/tracepoint 系の ctx）。
 *   - syscall 引数 pathname 等はここでは取っていない（別バリエーションとしては BPF_KPROBE_SYSCALL 等を使う）。
 */
SEC("ksyscall/execve")
int kprobe_exec(void *ctx)
{
   /*
    * data_t:
    *   ユーザ空間へ送るイベント payload。
    *   = {} でゼロ初期化することで verifier に優しく、未初期化領域を送らない。
    */
   struct data_t data = {};

   /*
    * map lookup の結果（value へのポインタ）。
    *   p は “NULL になり得る” ポインタとして verifier に追跡される。
    *   そのため p の参照は必ず NULL チェックが必要。
    */
   struct msg_t *p;

   /*
    * uid は 64bit helper から下位 32bit を取り出すために u64 で受ける。
    * 注意:
    *   bpf_map_lookup_elem の key 型は u32 の想定なので、
    *   実際には u32 key = (u32)uid; を作って渡すほうが “意図が明確” で安全。
    *   （ここでは学習用途で “型/サイズのズレ” を気づきやすくするため u64 を残している可能性がある）
    */
   u64 uid;

   /*
    * counter の例:
    *   data.counter に “現在の c” を入れてから c++ する。
    *   verifier 観点では OK だが、グローバル c は race になり得る点は注意。
    */
   data.counter = c;
   c++;

   /*
    * pid/tgid:
    *   bpf_get_current_pid_tgid() は 64bit で返る。
    *   - upper 32: TGID（一般に “プロセスID”）
    *   - lower 32: PID（スレッドID）
    *
    * ここでは data.pid に “そのまま 64bit を代入” しているので、
    * data.pid の型が int のままだと情報落ち/符号問題が起きる。
    *
    * hello-verifier.h の data_t で pid を u32 / u64 にしている前提なら OK。
    * もし data.pid が int のままなら、以下のように修正すべき:
    *   data.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    *
    * このコードは verifier 学習のための “わざと曖昧” もあり得るので、ヘッダ定義と要整合。
    */
   data.pid = bpf_get_current_pid_tgid();

   /*
    * uid:
    *   bpf_get_current_uid_gid() の下位 32bit が UID。
    */
   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.uid = uid;

   /*
    * map lookup:
    *   正しい形: 第1引数は “map へのポインタ” でなければならない。
    *   つまり &my_config は OK。
    */
   p = bpf_map_lookup_elem(&my_config, &uid);

   /*
    * ここが verifier 的な重要ポイント:
    *   「第1引数 needs to be a pointer to a map」
    *
    * 以下は NG（コメントアウトされているが学習ポイント）
    *   p = bpf_map_lookup_elem(&data, &uid);
    *
    * 理由:
    *   &data はスタック上の struct data_t であって、BPF map ではない。
    *   verifier は helper の引数型を厳密にチェックし、
    *   “map ポインタであること” を証明できないものは弾く。
    */

   /*
    * NULL チェックとデリファレンス:
    *   p は NULL になり得るので、p->message[...] の参照は必ず if (p != 0) の中。
    *
    * verifier はここで「p が NULL でない」ことを分岐の中で把握する。
    */
   if (p != 0) {
      /*
       * p->message[0] を読む例。
       * - verifier 的には “p の NULL でない証明” に加え
       *   “message の範囲内アクセス” であることが必要。
       * - [0] は定数なので範囲チェックは容易。
       */
      char a = p->message[0];
      bpf_printk("%d", a);
   }

   /*
    * message のコピー:
    *   - p があれば p->message を data.message にコピー
    *   - なければグローバル message をコピー
    *
    * bpf_probe_read_kernel は “kernel メモリ” から読む helper。
    * - map value（p->message）はカーネル側にあるので kernel 扱い
    * - BPF グローバル message も kernel 扱い
    *
    * NOTE:
    *   文字列なら *_str 系 helper（bpf_probe_read_kernel_str）を使うと NUL 終端を扱いやすい。
    */
   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
   }

   /*
    * 境界チェック（global message 配列の読み）
    *
    * コメントにある通り、<= にすると “ちょうど sizeof(message)” を許してしまい、
    * message[sizeof(message)] を読む可能性が生まれる。
    *
    * 配列の valid index は 0..sizeof-1 なので、正しくは <。
    */
   // if (c <= sizeof(message)) {  // NG 例（境界外アクセス可能性）
   if (c < sizeof(message)) {     // OK（範囲内を保証しやすい）
      char a = message[c];
      bpf_printk("%c", a);
   }

   /*
    * 境界チェック（data.message 配列の読み）
    *
    * data.message も同様に valid index は 0..sizeof-1。
    * <= を使うと境界外アクセスになり得る。
    */
   // if (c <= sizeof(data.message)) { // NG 例
   if (c < sizeof(data.message)) {    // OK
      char a = data.message[c];
      bpf_printk("%c", a);
   }

   /*
    * comm を取得して data.command に格納。
    * - TASK_COMM_LEN は 16 バイトで、短い識別子が入る。
    */
   bpf_get_current_comm(&data.command, sizeof(data.command));

   /*
    * perf buffer へ送信
    *
    * bpf_perf_event_output(ctx, &output, flags, data, size)
    * - ctx は kprobe/tracepoint 系で渡されるコンテキストポインタ
    * - &output は PERF_EVENT_ARRAY map
    * - BPF_F_CURRENT_CPU は “今の CPU のバッファに出す”
    *
    * verifier 観点:
    * - ctx は “このプログラムタイプで有効な ctx” として認識される必要がある。
    * - data はスタック上だが、サイズが固定で verifier が追える（= {} 初期化も効く）。
    */
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

   return 0;
}

/*
 * XDP プログラム
 *
 * XDP は “パケット” を扱うプログラムタイプで、ctx は struct xdp_md*。
 * verifier は data/data_end の境界チェックを非常に厳密に要求する。
 */
SEC("xdp")
int xdp_hello(struct xdp_md *ctx)
{
  /*
   * パケットデータ範囲:
   *   ctx->data     : パケット先頭（ポインタ値）
   *   ctx->data_end : パケット末尾（先頭+長さ）
   *
   * verifier 的には:
   *   data <= ptr < data_end の範囲でしかロードできない、という制約を証明させる。
   */
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  /*
   * “境界外読み” の典型 NG 例:
   *   data_end++ で data_end をずらすと、
   *   “本来の末尾” を超えた範囲を指し得るため、以降の安全性が崩れて verifier が怒りやすい。
   */
  // data_end++;

  /*
   * ループの verifier ポイント:
   *
   * OK 例（固定回数）:
   *   for (int i=0; i < 10; i++) ...
   * - 上限が定数で、verifier が “必ず有限回で終わる” と証明できる。
   *
   * NG 例（実行時値依存）:
   *   for (int i=0; i < c; i++) ...
   * - c がグローバルで実行時に変化し得るため、
   *   verifier が “必ず終わる/上限が小さい” を証明できず弾かれることが多い。
   *   （最近は bounded loop が許されるケースも増えたが、証明不能だと落ちるのは同じ）
   */
   // for (int i=0; i < 10; i++) {
   //    bpf_printk("Looping %d", i);
   // }

   // for (int i=0; i < c; i++) {
   //    bpf_printk("Looping %d", i);
   // }

  /*
   * 返り値の保証:
   *   XDP は return で XDP_PASS / XDP_DROP 等を必ず返す必要がある。
   *   返りがないパスがあると verifier が落とす（制御フローが未定義）。
   *
   * 下の bpf_printk と return を消すと「return code が定義されない」パスができるので NG。
   */
  bpf_printk("%x %x", data, data_end);
  return XDP_PASS;
}

/*
 * ライセンス宣言:
 *   - これを削ると “GPL 限定 helper” が使えなくなる/ verifier が拒否するケースがある。
 *   - 学習用途では「license を変えると何が使えなくなるか」を観察できる。
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
