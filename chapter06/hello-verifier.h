/*
 * hello-verifier.h（eBPF とユーザ空間で共有するデータ構造）
 *
 * 目的:
 *   eBPF プログラム（カーネル側）とユーザ空間プログラム（libbpf/bcc 側）が
 *   「同じレイアウト」で読み書きするための共有構造体を定義する。
 *
 * なぜ “共有ヘッダ” が必要か:
 *   eBPF 側は bpf_perf_event_output() などで “生のバイト列” をユーザ空間へ送る。
 *   ユーザ空間側は、そのバイト列を struct data_t として解釈して表示する。
 *
 *   つまり、両者が
 *     - フィールドの順序
 *     - 型のサイズ（int は 4 bytes 前提）
 *     - アラインメント（境界揃え）
 *     - 配列サイズ（command[16] など）
 *   を一致させないと、受信データが壊れて見えたり、未定義動作になる。
 *
 * CO-RE との関係:
 *   CO-RE（Compile Once, Run Everywhere）は主に
 *     「カーネル内部の型（task_struct など）を BTF を使って吸収する」
 *   ための仕組みである。
 *
 *   一方、この data_t / msg_t は “自分で定義したイベント形式” なので、
 *   CO-RE が勝手に面倒を見てくれるわけではない。
 *   そのため、共有ヘッダで “ユーザ空間と eBPF の合意” を固定するのが重要になる。
 *
 * 注意（よくあるハマりどころ）:
 *   - int のサイズは通常 4 bytes（LP64）だが、環境依存の可能性がゼロではない。
 *     共有データとしては、より堅牢にするなら __u32 / __u64（linux/types.h）や
 *     uint32_t / uint64_t（stdint.h）を使う方が安全。
 *
 *   - 構造体の詰め方（padding）が入ることがある。
 *     フィールド順序を変えると padding 位置が変わり、互換性が壊れる。
 *
 *   - 文字列配列は “必ず NUL 終端される” とは限らない。
 *     eBPF 側では *_str 系 helper（bpf_get_current_comm や bpf_probe_read_*_str）
 *     を使うと終端されやすいが、ユーザ空間側でも防御的に扱うのが堅い。
 */

/*
 * struct data_t:
 *   eBPF からユーザ空間へ送る “1イベント分” のレコード。
 *
 * 典型的な流れ:
 *   eBPF側:
 *     struct data_t data = {};
 *     data.pid = ...;
 *     ...
 *     bpf_perf_event_output(ctx, &output, ..., &data, sizeof(data));
 *
 *   ユーザ空間側:
 *     void handle_event(..., void *data, ...) {
 *        struct data_t *m = data;
 *        printf("%d ...", m->pid, ...);
 *     }
 */
struct data_t {
   /*
    * pid:
    *   ここでは “プロセスID（TGID）” を入れる想定。
    *   bpf_get_current_pid_tgid() は 64bit を返し、
    *     upper 32bit = TGID（一般に “pid” と呼ぶ値）
    *     lower 32bit = PID（スレッドID）
    *   なので eBPF 側で >>32 したものを格納するケースが多い。
    *
    * 注意:
    *   このフィールドが「TGID」なのか「PID（tid）」なのかは
    *   実装側の取り方次第で変わるので、コメントで明確にしておくと混乱が減る。
    */
   int pid;

   /*
    * uid:
    *   実効ユーザID（uid）を入れる想定。
    *   bpf_get_current_uid_gid() は 64bit を返し、
    *     lower 32bit = UID
    *     upper 32bit = GID
    *   なので eBPF 側で & 0xFFFFFFFF した値を入れることが多い。
    */
   int uid;

   /*
    * counter:
    *   “観測回数” や “通し番号” のような用途を想定したカウンタ。
    *
    * 重要（eBPFの実務的観点）:
    *   eBPF プログラム内でグローバル変数をインクリメントする場合、
    *   - 並行実行（複数CPU/複数タスク）で競合し、値が飛んだり取りこぼしが起きる
    *   - verifier 的には “書ける” が、意味論的には “原子性がない”
    *   という点に注意が必要。
    *
    *   厳密にカウントしたいなら
    *     - BPF_MAP_TYPE_PERCPU_ARRAY で per-CPU カウンタ
    *     - bpf_spin_lock を使う（重い）
    *     - atomic 操作（環境や helper 制約あり）
    *   などを検討する。
    */
   int counter;

   /*
    * command:
    *   プロセス名（comm: task_struct->comm 相当）を入れる固定長バッファ。
    *   Linux の TASK_COMM_LEN が 16 なので、慣習的に 16 bytes を使う。
    *
    * 取得:
    *   eBPF 側で bpf_get_current_comm(command, sizeof(command))
    *
    * 注意:
    *   - 16 bytes なので長いコマンド名は切れる。
    *   - 文字列終端が常に保証されるとは限らないので、
    *     ユーザ空間側で念のため終端処理を入れると堅い。
    */
   char command[16];

   /*
    * message:
    *   ユーザ定義のメッセージ文字列。
    *   “Hello World” (11文字 + '\0') を想定して 12 bytes。
    *
    * 使い方例:
    *   - my_config[uid] に msg_t.message を入れておき、
    *     eBPF 側が uid で引いて data.message にコピーする。
    *   - 見つからなければデフォルト "Hello World" を入れる。
    *
    * 注意:
    *   バッファが 12 bytes と小さいので、
    *   設定値が長いと切れて表示される。
    */
   char message[12];
};

/*
 * struct msg_t:
 *   “UIDごとのメッセージ設定” 用の map の value として使う構造体。
 *
 * eBPF 側:
 *   BPF_MAP_TYPE_HASH my_config: key=u32(uid), value=struct msg_t
 *   p = bpf_map_lookup_elem(&my_config, &uid);
 *
 * ユーザ空間側:
 *   bpf_map__update_elem(skel->maps.my_config, &uid, sizeof(uid), &msg, sizeof(msg), 0);
 *
 * なぜ data_t と分けるか:
 *   data_t はイベント全体のレコードであり、
 *   msg_t は “設定” の最小単位。
 *   役割を分けておくと、map value のサイズを小さく保てて扱いやすい。
 */
struct msg_t {
   /*
    * message:
    *   ユーザが差し替えたいメッセージ。
    *   data_t.message と同じサイズ/意味にしておくとコピーが簡単。
    */
   char message[12];
};
