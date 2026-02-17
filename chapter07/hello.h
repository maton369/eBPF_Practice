/*
 * hello.h（eBPF側とユーザ空間側で共有するヘッダの一部を想定）
 *
 * 目的:
 *   eBPF プログラムが「ユーザ空間へ送るイベントデータ」として使う構造体を定義し、
 *   ユーザ空間プログラムが同じレイアウトで受信・解釈できるようにする。
 *
 * なぜ“共有”が必要か:
 *   perf buffer / ring buffer で送られてくるのは「バイト列」なので、
 *   送信側(eBPF)と受信側(ユーザ空間)で struct のフィールド順・型・サイズ・アラインメントが一致しないと、
 *   受信側で表示した値が壊れたり、最悪クラッシュする。
 *
 * 重要ポイント:
 *   - フィールド順序を変えない（変えるなら両方同時に変える）
 *   - 型サイズに注意（int のサイズはほぼ 32bit だが、明示したいなら __u32 等を使う）
 *   - 文字列配列は固定長（verifier に優しく、イベント転送もしやすい）
 *   - “文字列は常に NUL 終端”を保証する設計にする（*_str 系 helper を使うなど）
 */

/*
 * data_t:
 *   1イベント分のペイロード（eBPF → ユーザ空間）を表す構造体。
 *
 * 想定ユースケース:
 *   - execve のフックで「誰が何を実行したか」を通知する
 *   - PID/UID/comm/path などを詰め、message を添えてユーザ空間に送る
 *
 * 各フィールドの意味:
 *   pid     : プロセスID（通常は TGID。bpf_get_current_pid_tgid() >> 32 で取ることが多い）
 *   uid     : ユーザID（bpf_get_current_uid_gid() & 0xFFFFFFFF で取ることが多い）
 *   command : comm（プロセス名/タスク名、TASK_COMM_LEN=16 で固定）
 *   message : 任意メッセージ（UIDごとの設定やデフォルト文言など）
 *   path    : execve に渡された pathname など（固定長のため長いパスは切れる）
 *
 * サイズと終端:
 *   - command[16] は “最大15文字 + '\0'” が入る想定（bpf_get_current_comm は終端しやすい）
 *   - message[12] は "Hello World"（11文字 + '\0'）をちょうど収めるために 12
 *   - path[16] は短い例としての固定長（実用なら 64〜256 などにすることが多い）
 *
 * NOTE（設計上の注意）:
 *   - path[16] は現実のパスに対してかなり短いので、観測用途だと情報が欠けやすい。
 *     学習目的なら OK だが、実用寄りにするならサイズ拡張を推奨。
 *   - int を使うとユーザ空間/カーネルでサイズが一致する前提になりやすい。
 *     より厳密にしたいなら __u32 / __s32（linux/types.h 系）へ寄せると安全。
 */
struct data_t {
    int pid;              /* プロセスID（TGID想定）。eBPF側で >>32 して入れることが多い */
    int uid;              /* ユーザID（UID）。下位32bitを使うことが多い */

    char command[16];     /* プロセス名（TASK_COMM_LEN=16）。短い識別子 */
    char message[12];     /* 表示用の短いメッセージ。例: "Hello World" */
    char path[16];        /* 実行ファイルのパス等。固定長なので長いパスは切り捨て */
};

/*
 * msg_t:
 *   UIDごとのメッセージ設定などに使う “map の value 型” を表す構造体。
 *
 * 典型パターン:
 *   - BPF_MAP_TYPE_HASH の value にして
 *       key   = uid
 *       value = msg_t（message）
 *     のように「UID→メッセージ」を引けるようにする。
 *
 * なぜ struct にするのか:
 *   - value を単なる char[12] でも良いが、
 *     struct にしておくと将来フィールド追加（例: severity, flags など）がしやすい。
 *   - bpf_map_update_elem で更新する時も “構造体1個” として扱える。
 */
struct msg_t {
    char message[12];     /* UIDごとに差し替えるメッセージ（固定長） */
};
