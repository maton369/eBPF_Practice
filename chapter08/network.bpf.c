/*
 * network.bpf.c（BCC + eBPF サンプル群）
 *
 * このファイルは「同じ“パケット”という対象」に対して、
 * eBPF の複数フックポイント（kprobe/Socket Filter/XDP/TC）で
 * それぞれ何ができるかをまとめて示す“実験用の詰め合わせ”である。
 *
 * ざっくり何をしているか（アルゴリズム俯瞰）
 *
 *   ┌───────────────────────────────────────────────────────────────┐
 *   │ 目的: パケットやソケットイベントを観測し、条件に応じて          │
 *   │       - ログ出力（trace_pipe）                                 │
 *   │       - ユーザ空間への転送（socket filter の -1）               │
 *   │       - 破棄（XDP_DROP / TC_ACT_SHOT）                          │
 *   │       - 書き換え＆擬似応答（TCで ping を pong に変える）         │
 *   │ を行う。                                                        │
 *   └───────────────────────────────────────────────────────────────┘
 *
 * フックポイントごとの位置づけ（超重要）
 *
 *  1) kprobe (tcpconnect)
 *     - カーネル関数に差し込む「プロセス/カーネルイベント観測」寄り。
 *     - ここでは単にログを出すだけ。
 *
 *  2) Socket Filter (socket_filter)
 *     - ソケット層に近い「パケット観測」。
 *     - BCC の cursor_advance を使って L2->L3 をパースし、
 *       TCP だけ “ユーザ空間へ送る” ために return -1 する。
 *
 *  3) XDP (xdp)
 *     - NIC ドライバ直後の “最速” パスで、パケットを早期に落とせる。
 *     - ICMP ping request を見つけたら XDP_DROP で破棄。
 *
 *  4) TC (tc_drop_ping / tc_drop / tc_pingpong)
 *     - qdisc による ingress/egress フックで skb を扱う。
 *     - ping request を落とす、全部落とす、または ping request を
 *       その場で echo reply に書き換えて“擬似応答”する。
 *
 * つまりこのファイルは：
 *   - 観測だけ（ログ）
 *   - 条件でユーザ空間へ転送
 *   - 条件で破棄
 *   - 条件で改変して反射（ping->pong）
 * の “検出器/防御器/変換器” をフックポイント別に比較できるようにしている。
 */

#include "network.h"          // is_icmp_ping_request / swap_* / update_* 等の自作ヘルパ（想定）

#include <bcc/proto.h>        // BCC のパケット構造体(ethernet_t/ip_t等)や cursor_advance など
#include <linux/pkt_cls.h>    // TC のアクション定数 (TC_ACT_OK/TC_ACT_SHOT など)

/*
 * tcpconnect（kprobe などから呼ばれる想定）
 *
 * 目的:
 *   「tcp connect に関するイベントが発生した」ことを trace に出すだけ。
 *
 * ctx:
 *   kprobe のコンテキスト（BCC では void* にして雑に受ける例が多い）。
 *
 * アルゴリズム:
 *   - ログを出して終了（副作用なし）
 *
 * 注意:
 *   - これ単体では “どの tcp connect か” の情報は取っていない。
 *     実用なら pid/comm, sockaddr, ポート等を ctx から読んでイベント化する。
 */
int tcpconnect(void *ctx) {
  bpf_trace_printk("[tcpconnect]\n");
  return 0;
}

/*
 * socket_filter（Socket Filter / classic BPF 的にソケットに付くフィルタ）
 *
 * 目的:
 *   受信パケットを L2(LAN)→L3(IP) まで簡易パースし、
 *   - ICMP ならログ
 *   - TCP ならログ＋“ユーザ空間へ送る”（return -1）
 *   - それ以外は何もしない
 *
 * 重要: cursor_advance について
 *   BCC の socket filter サンプルでは、
 *   `unsigned char *cursor = 0;` を “読み取り位置” として使い、
 *   `cursor_advance(cursor, nbytes)` が内部で skb から nbytes 読み、
 *   cursor を進めた位置にある struct へのポインタを返す。
 *
 * アルゴリズム:
 *   1) Ethernet header を読む（ethernet_t）
 *   2) type が IPv4(0x0800) 以外なら無視して return 0
 *   3) IPv4 header を読む（ip_t）
 *   4) next protocol が ICMP(0x01) ならログ
 *   5) next protocol が TCP(0x06) ならログして return -1（ユーザ空間転送）
 *   6) それ以外は return 0
 *
 * return 値の意味（ここが混乱しがち）
 *   Socket Filter の “返り値” はフック方式によって意味が揺れる。
 *   BCC の古典的 socket filter 例では、
 *     - 0    : drop
 *     - -1   : pass かつ userspace へ（ソケットへ配信） という扱いで使われることがある
 *   実際の attach 形態（SO_ATTACH_BPF なのか、raw socket なのか）や
 *   サンプルの受信側実装に依存するため、
 *   「return -1 で送る」は “この教材の前提” として理解するのが安全。
 */
int socket_filter(struct __sk_buff *skb) {
  /* BCC の cursor パーサ用の読み取り位置。0 で初期化するのが作法。 */
  unsigned char *cursor = 0;

  /* Ethernet(L2) を読む */
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  /* IPv4 以外は無視（0x0800 = EtherType IPv4） */
  if (ethernet->type != 0x0800) {
    return 0;
  }

  /* IP(L3) を読む */
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

  /* nextp: 次のプロトコル番号（IPヘッダの protocol フィールド相当） */
  if (ip->nextp == 0x01) { /* 1 = ICMP */
    bpf_trace_printk("[socket_filter] ICMP request for %x\n", ip->dst);
  }

  if (ip->nextp == 0x06) { /* 6 = TCP */
    bpf_trace_printk("[socket_filter] TCP packet for %x\n", ip->dst);

    /*
     * “TCP パケットはユーザ空間へ送る” という教材上の合図。
     * 受信側が raw socket / perf / ringbuf など何を使うかで
     * ここは別方式にもできるが、サンプルでは return -1 をトリガにしている。
     */
    return -1;
  }

  return 0;
}

/*
 * xdp（XDP フック）
 *
 * 目的:
 *   “最速の入口” で ICMP ping request を検出して即 drop する。
 *
 * XDP の特徴:
 *   - skb ではなく “生パケットバッファ” を直接扱う（data/data_end）
 *   - 早期に落とせるので DDoS 緩和などにも向く
 *   - ただし使える helper や操作が TC と比べて制約される
 *
 * アルゴリズム:
 *   1) ctx->data / ctx->data_end を取り出す
 *   2) is_icmp_ping_request(data, data_end) で “安全に” ping 判定
 *   3) ping ならログ出して XDP_DROP
 *   4) それ以外は XDP_PASS
 *
 * 注意:
 *   - data + sizeof(ethhdr) のようなポインタ計算は、
 *     必ず data_end との境界チェックが必要。
 *     ここでは is_icmp_ping_request() 側が境界チェックをしている前提。
 */
int xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    /* Ethernet + IPv4 + ICMP の順にヘッダを見る（※境界チェックは helper 側前提） */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_trace_printk("[xdp] ICMP request for %x type %x DROPPED\n",
                     iph->daddr, icmp->type);
    return XDP_DROP;
  }

  return XDP_PASS;
}

/*
 * tc_drop_ping（TC ingress/egress）
 *
 * 目的:
 *   TC で skb を見て、ICMP ping request なら落とす。
 *
 * XDP と TC の比較（検出器として）
 *   - XDP: 早い、ただし skb 操作がない、機能制約がある
 *   - TC : skb を扱える、改変・リダイレクトがやりやすい、ただし XDP より遅い
 *
 * アルゴリズム:
 *   1) ログ
 *   2) skb->data / skb->data_end を取り出す（XDP と似た雰囲気だが skb）
 *   3) ping ならログして TC_ACT_SHOT（破棄）
 *   4) それ以外は TC_ACT_OK（通す）
 */
int tc_drop_ping(struct __sk_buff *skb) {
  bpf_trace_printk("[tc] ingress got packet\n");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_trace_printk("[tc] ICMP request for %x type %x\n",
                     iph->daddr, icmp->type);
    return TC_ACT_SHOT; /* 破棄 */
  }
  return TC_ACT_OK;     /* 通過 */
}

/*
 * tc_drop（TC）
 *
 * 目的:
 *   条件なしで全パケットを drop（実験用の極端な例）。
 *
 * アルゴリズム:
 *   - ログを出して TC_ACT_SHOT（破棄）
 */
int tc_drop(struct __sk_buff *skb) {
  bpf_trace_printk("[tc] dropping packet");
  return TC_ACT_SHOT;
}

/*
 * tc_pingpong（TC）
 *
 * 目的:
 *   ICMP Echo Request（ping）を検出したら、
 *   パケットを書き換えて ICMP Echo Reply（pong）にして返す。
 *
 * これは “検出器 + 変換器（修復/自動応答）” のデモ。
 *
 * アルゴリズム（ping→pong変換の流れ）
 *
 *   ingress skb を受け取る
 *        │
 *        │ ping でなければ通す
 *        v
 *   ping を検出
 *        │
 *        ├─(1) MAC を入れ替え（宛先/送信元）
 *        ├─(2) IP を入れ替え（宛先/送信元）
 *        ├─(3) ICMP type を 8→0 に変更（Echo Request→Echo Reply）
 *        ├─(4) bpf_clone_redirect で “同じIFに” 送り返す
 *        └─(5) 元の skb は drop（クローンを飛ばしたので二重送信防止）
 *
 * 重要ポイント:
 *   - “書き換えた skb をそのまま返す” のではなく、
 *     clone を redirect して、元は落とすという流れにしている。
 *     こうすると ingress の処理パスが分かりやすく、二重送信も避けやすい。
 *
 * 注意（実運用上のツッコミどころ）
 *   - チェックサム更新が必要。
 *     update_icmp_type() 内で ICMP checksum を再計算/差分更新している前提。
 *     IP checksum も場合によって必要になる（IPヘッダを書き換えるなら特に）。
 *   - 返信の生成としては “正しい” が、現実には ping 応答はホストの IP スタックが行う。
 *     これは「eBPF でパケットを改変できる」ことを見せる教材。
 */
int tc_pingpong(struct __sk_buff *skb) {
  bpf_trace_printk("[tc] ingress got packet");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  /* ping request じゃないなら何もしない */
  if (!is_icmp_ping_request(data, data_end)) {
    bpf_trace_printk("[tc] ingress not a ping request");
    return TC_ACT_OK;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

  bpf_trace_printk("[tc] ICMP request for %x type %x\n",
                   iph->daddr, icmp->type);

  /* L2/L3 の送受信アドレスを入れ替えて「返答方向」にする */
  swap_mac_addresses(skb);
  swap_ip_addresses(skb);

  /*
   * ICMP type を Echo Request(8) -> Echo Reply(0) に変更。
   * helper 内で checksum を正しく更新する前提。
   */
  update_icmp_type(skb, 8, 0);

  /*
   * 書き換えた skb を同一 IF に再送。
   * ここでは clone を redirect し、元 skb は drop する設計。
   */
  bpf_clone_redirect(skb, skb->ifindex, 0);

  /* 元のパケットは破棄（clone を飛ばしたので） */
  return TC_ACT_SHOT;
}

/*
 * 追加メモ（検出器としての整理）
 *
 * - socket_filter:
 *     “どのプロトコルをユーザ空間へ上げるか” の前段フィルタとして便利。
 *     TCP を -1 で上げる設計は教材向けで、実際は perf/ringbuf でイベント化しがち。
 *
 * - XDP:
 *     早期ドロップの検出器。軽量 DDoS 緩和・単純なブロックルールに向く。
 *
 * - TC:
 *     skb を改変しやすい検出器。観測だけでなく、変換（修復/応答）までやれる。
 *
 * つまり、同じ「ICMP ping を検出する」でも、
 *   XDP は “落とす” で強い
 *   TC は “改変して返す” までできる
 * という役割差がこのファイルで比較できる。
 */
