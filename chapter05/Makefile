# -----------------------------------------------------------------------------
# Makefile（libbpf + CO-RE + skeleton 生成）
#
# 目的:
#   1) eBPF 側（.bpf.c）を clang で BPF バイトコード（.bpf.o）にコンパイルする
#   2) その .bpf.o から bpftool で skeleton ヘッダ（.skel.h）を生成する
#   3) ユーザ空間側（.c）を gcc でビルドし、libbpf をリンクして実行ファイルを作る
#   4) ついでに map を覗くための補助ツール find-map もビルドする
#
# この Makefile の「全体像（データの流れ）」:
#
#   (A) カーネルBTF
#        |
#        v
#   /sys/kernel/btf/vmlinux  --bpftool-->  vmlinux.h
#        |
#        v
#   (B) eBPF C ソース            (C) libbpf skeleton 生成
#   hello-buffer-config.bpf.c  --clang--> hello-buffer-config.bpf.o --bpftool--> hello-buffer-config.skel.h
#        |                                                                  |
#        v                                                                  v
#   (D) ユーザ空間 C ソース  +  (E) skeleton ヘッダ  ----gcc+link(libbpfa+elf+z)----> 実行ファイル hello-buffer-config
#
# 重要ポイント:
#   - vmlinux.h は CO-RE (Compile Once, Run Everywhere) のための型情報。
#   - __TARGET_ARCH_xxx は CO-RE の relocation や一部マクロの分岐に必要。
#   - skeleton は「BPF オブジェクトを libbpf でロード/アタッチする boilerplate」を自動生成する。
#   - libbpf は静的リンク（-l:libbpf.a）しているため、../libbpf/src にビルド済みの libbpf.a が必要。
#   - -lelf -lz は libbpf が内部で使う依存（ELF 解析と圧縮関連）に対応する。
# -----------------------------------------------------------------------------

# ユーザ空間の実行ファイル名（同時にベース名として使う）
TARGET = hello-buffer-config

# アーキテクチャ名を libbpf/clang が期待する形式に寄せる:
# - uname -m は環境により x86_64 / aarch64 等を返す。
# - eBPF 側で -D __TARGET_ARCH_$(ARCH) を定義するため、
#   ここでは x86_64 -> x86、aarch64 -> arm64 へ変換している。
#
# 例:
#   uname -m = x86_64  -> ARCH=x86    -> -D __TARGET_ARCH_x86
#   uname -m = aarch64 -> ARCH=arm64  -> -D __TARGET_ARCH_arm64
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 生成物の名前展開:
#   ${TARGET:=.bpf.o} は "TARGET の末尾に .bpf.o を付ける" という意味。
# 例:
#   TARGET=hello-buffer-config
#   BPF_OBJ = hello-buffer-config.bpf.o
BPF_OBJ = ${TARGET:=.bpf.o}

# ユーザ空間の C ソース:
#   hello-buffer-config.c を想定
USER_C = ${TARGET:=.c}

# skeleton ヘッダ:
#   hello-buffer-config.skel.h を想定
USER_SKEL = ${TARGET:=.skel.h}

# デフォルトターゲット:
#   - ユーザ空間実行ファイル $(TARGET)
#   - eBPF オブジェクト $(BPF_OBJ)
#   - 補助ツール find-map
#
# NOTE:
#   $(TARGET) は $(USER_SKEL) を依存に含むので、
#   実質的には「eBPF を作る→skeletonを作る→ユーザ空間をリンク」が揃う。
all: $(TARGET) $(BPF_OBJ) find-map
.PHONY: all

# -----------------------------------------------------------------------------
# (D) ユーザ空間プログラムのビルド
#
# 依存:
#   - $(USER_C)     : ユーザ空間 C
#   - $(USER_SKEL)  : skeleton ヘッダ（bpftool が生成）
#
# ビルド:
#   - gcc -Wall : 警告を有効化
#   - -L../libbpf/src -l:libbpf.a : 静的libbpfをリンク（パスに libbpf.a が必要）
#   - -lelf -lz : libbpf が使う依存ライブラリ
#
# 注意:
#   - include パス（-I）を指定していないので、
#     USER_C 側で skeleton を include するときに
#     "hello-buffer-config.skel.h" が同じディレクトリにある前提。
#   - libbpf のヘッダ（bpf/libbpf.h 等）が必要なら、USER_C 側で適切に -I を追加すること。
# -----------------------------------------------------------------------------
$(TARGET): $(USER_C) $(USER_SKEL)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

# -----------------------------------------------------------------------------
# (B) eBPF オブジェクトのビルド（.bpf.c -> .bpf.o）
#
# パターンルール:
#   %.bpf.o: %.bpf.c vmlinux.h
#   - 任意の xxx.bpf.c を xxx.bpf.o にするルール。
#   - さらに CO-RE 用の vmlinux.h を依存に入れている。
#
# clang オプション:
#   -target bpf              : eBPF 用にコンパイル
#   -D __TARGET_ARCH_$(ARCH) : アーキ依存マクロ（CO-RE / bpf_tracing 等で重要）
#   -Wall                    : 警告を有効化
#   -O2 -g                   : 最適化 + デバッグ情報（BTF/CO-RE のため -g を付けるのは定石）
#   -o $@ -c $<              : 出力=ターゲット、入力=最初の依存
#
# llvm-strip -g $@:
#   - .bpf.o から DWARF 等の不要なデバッグ情報を落とす（サイズ削減）。
#   - BTF は通常残る（が、環境によって扱いは変わり得る）。
#
# 注意:
#   - vmlinux.h を毎回生成し直すのは重いので、
#     変更がない限り Make の依存解決に任せる（この書き方でOK）。
# -----------------------------------------------------------------------------
%.bpf.o: %.bpf.c vmlinux.h
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

# -----------------------------------------------------------------------------
# (C) skeleton ヘッダの生成
#
# $(USER_SKEL): $(BPF_OBJ)
#   - eBPF オブジェクトから skeleton を作る。
#
# bpftool gen skeleton:
#   - libbpf を使ったロード/アタッチのための C ヘッダを自動生成する。
#   - 生成物（.skel.h）には、
#       * map のハンドル取得
#       * プログラムの open/load/attach/cleanup
#       * rodata/bss/data セクションのアクセス
#     などが含まれる（ボイラープレート排除の主目的）。
#
# リダイレクト:
#   > $@ でファイルとして出力する。
# -----------------------------------------------------------------------------
$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# -----------------------------------------------------------------------------
# (A) vmlinux.h の生成
#
# bpftool btf dump file /sys/kernel/btf/vmlinux format c:
#   - running kernel が提供する BTF から C ヘッダ相当を生成する。
#   - これが CO-RE の基盤（型・オフセット情報が揃う）。
#
# 注意:
#   - /sys/kernel/btf/vmlinux が無いカーネルではこの手法は使えない（BTF無効等）。
#   - Docker/WSL などでは BTF が見えないケースもある。
# -----------------------------------------------------------------------------
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# -----------------------------------------------------------------------------
# clean:
#   ビルド生成物を削除する。
#   - 先頭の '-' は「失敗しても make を止めない」指定。
#   例: ファイルが存在しない場合 rm が非0でも継続。
# -----------------------------------------------------------------------------
clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
	- rm find-map

# -----------------------------------------------------------------------------
# 補助ツール: find-map
#
# 目的（想定）:
#   - /sys/fs/bpf や pinned map を調べたり、
#     map の中身を覗いたりする支援ツール。
#
# ビルド:
#   - libbpf をリンクしているので、BPF map を開く/探索する処理を入れやすい。
#   - -lelf -lz も同様に必要。
#
# 注意:
#   - find-map.c の内容次第では -I など追加が必要になることがある。
# -----------------------------------------------------------------------------
find-map: find-map.c
	gcc -Wall -o find-map find-map.c -L../libbpf/src -l:libbpf.a -lelf -lz
