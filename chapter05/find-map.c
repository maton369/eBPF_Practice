/*
 * find-map.c（ユーザ空間側 / libbpf の低レベルAPIを直接使う例）
 *
 * 目的:
 *   bpffs（/sys/fs/bpf）に pin（固定）された BPF オブジェクト（ここでは map を想定）
 *   をパス指定で開き（bpf_obj_get）、
 *   その FD（ファイルディスクリプタ）からメタ情報（bpf_map_info）を取得して表示する。
 *
 * 何が嬉しいか:
 *   - eBPF の map を “プロセス間で共有” したいとき、bpffs に pin しておくのが定石。
 *   - pin された map は /sys/fs/bpf/... に「ファイルっぽく」現れ、別プロセスから再利用できる。
 *   - その pin 先パスを bpf_obj_get() に渡せば、map の FD を取得できる。
 *
 * 前提:
 *   - /sys/fs/bpf は通常 bpffs としてマウントされている（多くのディストリでデフォルト）。
 *   - /sys/fs/bpf/findme に map が pin されていること（例: bpftool map pin など）。
 *   - 一般に root（もしくは適切な CAP_BPF/CAP_SYS_ADMIN 等）で実行する必要がある。
 *
 * 全体の流れ（アルゴリズム）:
 *
 *   ┌───────────────────────────────────┐
 *   │ (1) bpf_map_info 構造体を用意      │
 *   │     - 0 クリアしておく（安全）     │
 *   └───────────────────┬───────────────┘
 *                       │
 *                       v
 *   ┌───────────────────────────────────┐
 *   │ (2) bpf_obj_get() で pin パスを開く │
 *   │     - 成功: map の FD が返る       │
 *   │     - 失敗: -1 が返り errno が立つ │
 *   └───────────────────┬───────────────┘
 *                       │
 *                       v
 *   ┌───────────────────────────────────┐
 *   │ (3) bpf_obj_get_info_by_fd()      │
 *   │     - FD から map 情報を取得       │
 *   │     - info.name などが埋まる        │
 *   └───────────────────┬───────────────┘
 *                       │
 *                       v
 *   ┌───────────────────────────────────┐
 *   │ (4) 表示して終了                  │
 *   └───────────────────────────────────┘
 *
 * 注意（よくあるハマりどころ）:
 *   - bpf_obj_get() は「0以上」の FD を返す。失敗時は -1。
 *     なので「<=0 判定」は FD=0 の可能性を誤って失敗扱いする（通常 FD=0 は標準入力なので
 *     実際には返らないことが多いが、判定としては厳密ではない）。
 *   - bpf_obj_get_info_by_fd() は失敗することがあり、その場合 errno を見るべき。
 *   - 取得した FD は close() で閉じるのが作法（短いプログラムでも）。
 */

#include <stdio.h>      // printf, perror
#include <unistd.h>     // close
#include <errno.h>      // errno
#include <string.h>     // strerror（必要なら）
#include <bpf/bpf.h>    // bpf_obj_get, bpf_obj_get_info_by_fd, bpf_map_info

// Run this as root
int main(void)
{
    /*
     * bpf_map_info:
     *   - カーネルが返してくる map のメタ情報を受け取る構造体。
     *   - info.name のほか、map type / key_size / value_size / max_entries などが入る。
     *
     * `= {}` でゼロ初期化しておくことで、
     *   - 未初期化領域が混ざるのを防ぐ
     *   - カーネルが埋めないフィールドがあっても安全
     */
    struct bpf_map_info info = {};

    /*
     * len:
     *   - bpf_obj_get_info_by_fd() は「どれくらいのサイズを埋めるか」を len で受け取る。
     *   - 呼び出し側はまず「自分が持っている構造体サイズ」を渡す。
     *   - 呼び出し後は「実際に埋められたサイズ」が返る（場合がある）。
     */
    unsigned int len = sizeof(info);

    /*
     * bpf_obj_get(path):
     *   - bpffs に pin された BPF オブジェクト（map/prog/link など）を
     *     パス指定で開いて FD を返す。
     *
     * ここでは /sys/fs/bpf/findme を開きたい。
     *   - このパスが存在しない / pin されていない → -1 で errno=ENOENT など
     *   - 権限がない → -1 で errno=EPERM/EACCES など
     *
     * 戻り値:
     *   - 成功: 0以上の FD
     *   - 失敗: -1
     */
    int findme = bpf_obj_get("/sys/fs/bpf/findme");

    /*
     * 判定は findme < 0 が正しい（失敗は -1）。
     * 元コードの <= 0 だと “もし FD=0 が返ったら” 誤判定する。
     * （実際の運用では FD=0 が返ることは稀だが、コードとしては <0 が厳密）
     */
    if (findme < 0) {
        /*
         * 失敗理由は errno に入っているので、
         * perror() などで出すとデバッグが非常に楽。
         */
        perror("bpf_obj_get(/sys/fs/bpf/findme) failed");
        return 1;
    }

    /*
     * bpf_obj_get_info_by_fd(fd, info, len):
     *   - FD が指す BPF オブジェクトの情報を取得する。
     *   - fd が map の FD なら、info は bpf_map_info として解釈される。
     *
     * ここで得られる info.name は「map 名」。
     *   - ただし map 名は最大 BPF_OBJ_NAME_LEN（通常 16）で、
     *     長い名前は切り詰められることがある。
     */
    int err = bpf_obj_get_info_by_fd(findme, &info, &len);
    if (err) {
        /*
         * 失敗したら errno を見る。
         * 例:
         *   - fd が map ではない（prog/link だった）
         *   - len が不正
         *   - 権限不足
         */
        perror("bpf_obj_get_info_by_fd failed");
        close(findme);
        return 1;
    }

    /*
     * map 名を表示。
     * info.name は NUL 終端されている想定だが、
     * もし心配なら %.*s で長さ制限して表示するのが堅い。
     */
    printf("name %s\n", info.name);

    /*
     * 追加で表示すると学習が進む情報例:
     *   - info.type        : map の種類（HASH/ARRAY/RINGBUF 等）
     *   - info.key_size    : key サイズ
     *   - info.value_size  : value サイズ
     *   - info.max_entries : 最大要素数
     *
     * 例:
     * printf("type=%u key=%u value=%u max=%u\n",
     *        info.type, info.key_size, info.value_size, info.max_entries);
     */

    /* FD は閉じる（短いプログラムでも作法として） */
    close(findme);

    return 0;
}
