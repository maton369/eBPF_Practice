#ifndef HELLO_BUFFER_CONFIG_H
#define HELLO_BUFFER_CONFIG_H

/*
 * hello-buffer-config.h
 *
 * 目的:
 *   eBPF 側（hello-buffer-config.bpf.c）とユーザ空間側（hello-buffer-config.c）が
 *   同じイベント構造体レイアウト（ABI）を共有するためのヘッダである。
 *
 * 重要（絶対に守る）:
 *   - ここに定義した struct data_t は eBPF 側/ユーザ空間側で完全一致が必要。
 *   - フィールド順序・型・配列長を変えると、受信側の解釈が壊れる。
 *   - 共有 ABI なので、変更したら「eBPF 側もユーザ側も」同時に作り直すこと。
 *
 * よくある落とし穴:
 *   - int のサイズは通常 32bit だが、環境差を避けたいなら __u32 を使う手もある。
 *   - char 配列の長さが短すぎると execve のパスが切れる。
 *     （学習用途なら 64 や 256 に増やすのもあり。ただしイベントサイズが増える）
 */

struct data_t {
    int  pid;              /* TGID（いわゆるプロセスID）: bpf_get_current_pid_tgid() >> 32 */
    int  uid;              /* UID（下位 32bit）: bpf_get_current_uid_gid() & 0xFFFFFFFF    */

    char command[16];      /* TASK_COMM_LEN 相当（短いコマンド名） */
    char message[12];      /* "Hello World" (11) + '\0' で 12 bytes を想定 */
    char path[16];         /* execve(pathname, ...) の pathname（短いと切れる） */
};

#endif /* HELLO_BUFFER_CONFIG_H */
