# hello-verifier 用 Makefile
#
# 目的:
#   CO-RE + libbpf(skeleton) 方式で eBPF プログラムをビルドするための Makefile。
#   具体的には、次の 2 つを作る:
#
#   (A) カーネル側(eBPF) : hello-verifier.bpf.o
#       - clang -target bpf でコンパイル
#       - BTF を前提とした CO-RE（vmlinux.h）を include
#
#   (B) ユーザ空間側     : hello-verifier
#       - libbpf をリンク
#       - skeleton ヘッダ（hello-verifier.skel.h）を使ってロード/アタッチ
#
# 全体の流れ（図解）
#
#   ┌──────────────┐
#   │ vmlinux.h     │  (BTF から生成。CO-RE の要)
#   └──────┬───────┘
#          │
#          v
#   ┌───────────────────────┐
#   │ hello-verifier.bpf.c   │  (eBPF プログラム本体)
#   └──────┬────────────────┘
#          │ clang -target bpf
#          v
#   ┌───────────────────────┐
#   │ hello-verifier.bpf.o   │  (BPF ELF オブジェクト)
#   └──────┬────────────────┘
#          │ bpftool gen skeleton
#          v
#   ┌───────────────────────┐
#   │ hello-verifier.skel.h  │  (ユーザ空間が使う skeleton API)
#   └──────┬────────────────┘
#          │ gcc + libbpf
#          v
#   ┌───────────────────────┐
#   │ hello-verifier         │  (ユーザ空間ローダ/受信側)
#   └───────────────────────┘
#
# 重要ポイント（CO-RE 観点）:
#   - vmlinux.h は “カーネルの型定義” を BTF から取り出したもの。
#     これにより、カーネルバージョン差があっても BTF を頼りに
#     フィールドオフセット等を解決できる（= Compile Once, Run Everywhere）。
#
#   - -D __TARGET_ARCH_$(ARCH) は CO-RE / tracing のマクロが
#     アーキごとの ABI 差を吸収するために必要になることがある。
#     （例: pt_regs の扱い、引数取得マクロなど）
#
#   - skeleton は “ロード/アタッチ/マップ操作” を定型化してくれるので、
#     手で bpf_object__open/load/attach を書くよりミスが減る。

# ユーザ空間バイナリ名（= ターゲット名）
TARGET = hello-verifier

# uname -m で CPU アーキを取得し、libbpf が期待する表記に正規化する。
# - x86_64 -> x86
# - aarch64 -> arm64
#
# NOTE:
#   libbpf の __TARGET_ARCH_* は “x86” “arm64” のような値を期待することが多い。
#   ここがズレると、CO-RE の一部マクロが想定どおり動かない/ビルドが通らないことがある。
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# eBPF 側ファイル名の構成:
#   BPF_TARGET = hello-verifier.bpf
#   BPF_C      = hello-verifier.bpf.c
#   BPF_OBJ    = hello-verifier.bpf.o
#
# ここは “hello-verifier.bpf.c という命名規則” を前提にしている。
# よくある命名:
#   <name>.bpf.c  -> <name>.bpf.o
BPF_TARGET = ${TARGET:=.bpf}
BPF_C      = ${BPF_TARGET:=.c}
BPF_OBJ    = ${BPF_TARGET:=.o}

# ユーザ空間側:
#   hello-verifier.c
#   hello-verifier.skel.h（bpftool が生成）
USER_C    = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

# eBPF とユーザ空間で共有するヘッダ（イベント構造体など）
COMMON_H  = ${TARGET:=.h}

# デフォルトターゲット:
#   - ユーザ空間バイナリ（hello-verifier）
#   - eBPF オブジェクト（hello-verifier.bpf.o）
#
# NOTE:
#   skeleton 生成は $(TARGET) の依存で暗黙に走る（後述）。
all: $(TARGET) $(BPF_OBJ)
.PHONY: all

# ─────────────────────────────────────────────
# ユーザ空間バイナリを作るルール
# ─────────────────────────────────────────────
#
# 依存関係:
#   - hello-verifier.c        : ユーザ空間ローダ/受信コード
#   - hello-verifier.skel.h   : eBPF オブジェクトから生成される skeleton
#   - hello-verifier.h        : eBPF と共有する構造体
#
# リンク:
#   -L../libbpf/src -l:libbpf.a : ローカルでビルドした静的 libbpf をリンク
#   -lelf -lz                  : libbpf が必要とする依存（libelf, zlib）
#
# 注意:
#   - ../libbpf/src に libbpf.a が存在している前提。
#     ない場合は “先に libbpf をビルドする” 必要がある。
#
$(TARGET): $(USER_C) $(USER_SKEL) $(COMMON_H)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

# ─────────────────────────────────────────────
# eBPF オブジェクトを作るルール
# ─────────────────────────────────────────────
#
# $(BPF_OBJ) を “パターンルール %.o” で生成する。
#
# 依存関係:
#   - hello-verifier.bpf.c : eBPF プログラム本体
#   - vmlinux.h            : BTF から生成したカーネル型定義（CO-RE）
#   - hello-verifier.h     : 共有構造体
#
# clang フラグ解説:
#   -target bpf
#       eBPF バイトコード向けにコンパイルする。
#
#   -D __BPF_TRACING__
#       tracing 系の補助マクロ（bpf_tracing.h など）が
#       “BPF 側としてコンパイルされている” ことを前提に分岐する場合がある。
#       （環境によっては不要だが、学習用途では明示しておくとトラブルが減る）
#
#   -D __TARGET_ARCH_$(ARCH)
#       アーキ依存マクロの選択（x86 / arm64 など）。
#       CO-RE や syscall 引数取得マクロが参照することがある。
#
#   -Wall
#       eBPF でも警告を見ておく（型不一致等が verifier 以前に分かる）。
#
#   -O2 -g
#       -O2: eBPF は制約が強いので最適化前提で通るケースがある。
#       -g : BTF/デバッグ情報（bpftool/libbpf が扱う情報）が増える。
#
# llvm-strip -g
#       生成物から DWARF を落としてサイズを減らす。
#       eBPF 側は “BTF は残しつつ DWARF を削る” のが定番。
#
$(BPF_OBJ): %.o: $(BPF_C) vmlinux.h $(COMMON_H)
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

# ─────────────────────────────────────────────
# skeleton ヘッダ生成ルール
# ─────────────────────────────────────────────
#
# hello-verifier.bpf.o から hello-verifier.skel.h を生成する。
#
# skeleton の意味:
#   - BPF オブジェクトを “型安全っぽく” 扱うための C API が生成される。
#   - open/load/attach/destroy や maps/progs 参照が簡単になる。
#
# 注意:
#   bpftool のバージョンが古いと skeleton の生成に失敗することがある。
#   （CO-RE を真面目に使うなら bpftool/libbpf を揃えるのが大事）
#
$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# ─────────────────────────────────────────────
# vmlinux.h 生成ルール（CO-RE の要）
# ─────────────────────────────────────────────
#
# /sys/kernel/btf/vmlinux から BTF を取り出し、C ヘッダ形式にダンプする。
# これにより、カーネル内部の型（task_struct 等）を include できる。
#
# 注意:
#   - カーネルが BTF を提供している必要がある（最近の distro は大抵 OK）。
#   - コンテナ環境などで /sys/kernel/btf/vmlinux が見えない場合は失敗する。
#
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# ─────────────────────────────────────────────
# clean
# ─────────────────────────────────────────────
#
# 中間生成物（.o）と最終バイナリを削除する。
#
# NOTE:
#   skeleton ヘッダ（hello-verifier.skel.h）や vmlinux.h も消したい場合は
#   ここに追加することが多い（学習用途なら残しても良い）。
#
clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
