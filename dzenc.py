# -*- coding: utf-8 -*-
"""
DZEnc 核心加密引擎

安全设计（三层）：
  第一层 密钥派生  Argon2id —— 内存硬函数，每次猜测强制吃掉 64MiB 内存，
                   把 GPU 并行暴破的路子堵死（显卡内存带宽成为瓶颈）。
  第二层 加密算法  AES-256-GCM —— 认证加密。密文被改动任意一个 bit，
                   解密直接失败，不会解出一堆乱码蒙混过关。
  第三层 分块绑定  每块把「块序号」和「是否末块」写进 AAD 参与认证，
                   防重排、防截断（这是自写加密最常翻车的地方）。

文件格式（.enc）：
  ┌──────────┬─────────────────────────────────────────┐
  │ 偏移 0   │ Magic  b"DZENC\\x01"             (6 字节) │
  │ 偏移 6   │ memory_cost  uint32 小端          (4 字节) │
  │ 偏移 10  │ iterations   uint32 小端          (4 字节) │
  │ 偏移 14  │ lanes        uint32 小端          (4 字节) │
  │ 偏移 18  │ salt                             (16 字节)│
  ├──────────┴─────────────────────────────────────────┤
  │ 数据块 × N（顺序排列）：                              │
  │   nonce (12) │ flags (1) │ len (4) │ 密文+tag (len)  │
  │   flags bit0 = 1 表示这是最后一块                     │
  └─────────────────────────────────────────────────────┘

命令行用法：
  python dzenc.py encrypt 文件路径 [-p 口令] [-o 输出路径]
  python dzenc.py decrypt 文件路径 [-p 口令] [-o 输出路径]
  不带参数运行则启动图形界面
"""

import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# ---------------------------------------------------------------- 常量定义

MAGIC = b"DZENC\x01"          # 魔数 + 格式版本号
SALT_LEN = 16                 # 盐长度
NONCE_LEN = 12                # GCM 推荐的 nonce 长度
KEY_LEN = 32                  # 256 位密钥
HEADER_LEN = 6 + 4 + 4 + 4 + SALT_LEN   # 头部总长 = 34 字节
CHUNK_SIZE = 1 << 20          # 分块大小 1 MiB

# Argon2id 参数：本机实测约 0.07 秒，老机器约 0.3 秒
KDF_MEMORY = 65536            # 内存开销，单位 KiB（= 64 MiB）
KDF_ITERATIONS = 3            # 迭代轮数
KDF_LANES = 4                 # 并行度

ENC_SUFFIX = ".enc"           # 加密文件后缀


class EncError(Exception):
    """加密工具自身的异常基类。"""


class FormatError(EncError):
    """文件不是本工具产生的，或结构已损坏。"""


class AuthError(EncError):
    """认证失败——口令错误，或者文件被篡改/损坏。"""


# ---------------------------------------------------------------- 密钥派生

def derive_key(password, salt, memory_cost=KDF_MEMORY,
               iterations=KDF_ITERATIONS, lanes=KDF_LANES):
    """用 Argon2id 把口令派生成 256 位密钥。

    参数从文件头读取而非写死，这样将来调高强度时，老文件依然能解开。
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    return Argon2id(
        salt=salt,
        length=KEY_LEN,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    ).derive(password)


# ---------------------------------------------------------------- 工具函数

def default_encrypt_name(src):
    return src + ENC_SUFFIX


def default_decrypt_name(src):
    """解密输出名：去掉 .enc 后缀；若没有该后缀则补 .dec 避免覆盖原文件。"""
    if src.lower().endswith(ENC_SUFFIX):
        return src[:-len(ENC_SUFFIX)]
    return src + ".dec"


def human_size(n):
    """把字节数转成人类可读的形式。"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024.0


def _check_password(password):
    if not password:
        raise EncError("口令不能为空")


# ---------------------------------------------------------------- 加密

def encrypt_file(src, dst=None, password="", progress=None):
    """加密文件。

    src      源文件路径
    dst      输出路径，None 则自动加 .enc
    password 口令
    progress 进度回调 progress(已处理字节, 总字节)，可为 None

    返回实际输出路径。
    """
    _check_password(password)
    if not os.path.isfile(src):
        raise EncError(f"找不到文件：{src}")
    if dst is None:
        dst = default_encrypt_name(src)
    if os.path.abspath(dst) == os.path.abspath(src):
        raise EncError("输出路径不能和源文件相同")

    total = os.path.getsize(src)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    aes = AESGCM(key)

    tmp = dst + ".part"          # 先写临时文件，成功后改名，避免半截产物
    done = 0
    try:
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            fo.write(MAGIC)
            fo.write(struct.pack("<III", KDF_MEMORY, KDF_ITERATIONS, KDF_LANES))
            fo.write(salt)

            index = 0
            while True:
                chunk = fi.read(CHUNK_SIZE)
                # 预读 1 字节判断后面还有没有数据，从而确定本块是否为末块
                nxt = fi.read(1) if chunk else b""
                if nxt:
                    fi.seek(-1, 1)
                is_final = 1 if not nxt else 0

                nonce = os.urandom(NONCE_LEN)
                # AAD 参与认证但不写入文件：块序号防重排，末块标志防截断
                aad = struct.pack("<QB", index, is_final)
                ct = aes.encrypt(nonce, chunk, aad)

                fo.write(nonce)
                fo.write(struct.pack("<BI", is_final, len(ct)))
                fo.write(ct)

                done += len(chunk)
                if progress:
                    progress(done, total)

                index += 1
                if is_final:
                    break
        os.replace(tmp, dst)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise
    return dst


# ---------------------------------------------------------------- 解密

def decrypt_file(src, dst=None, password="", progress=None):
    """解密文件。参数含义同 encrypt_file。返回实际输出路径。"""
    _check_password(password)
    if not os.path.isfile(src):
        raise EncError(f"找不到文件：{src}")
    if dst is None:
        dst = default_decrypt_name(src)
    if os.path.abspath(dst) == os.path.abspath(src):
        raise EncError("输出路径不能和加密文件相同")

    total = os.path.getsize(src)
    tmp = dst + ".part"
    done = 0
    try:
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            header = fi.read(HEADER_LEN)
            if len(header) < HEADER_LEN or header[:6] != MAGIC:
                raise FormatError("这不是本工具加密的文件，或者文件结构已被破坏")
            memory_cost, iterations, lanes = struct.unpack("<III", header[6:18])
            salt = header[18:HEADER_LEN]

            key = derive_key(password, salt, memory_cost, iterations, lanes)
            aes = AESGCM(key)

            index = 0
            while True:
                block_head = fi.read(NONCE_LEN + 1 + 4)
                if len(block_head) < NONCE_LEN + 1 + 4:
                    # 没读到末块标志就断了，说明文件被截断
                    raise FormatError("文件不完整，可能传输中断或被截断")
                nonce = block_head[:NONCE_LEN]
                is_final, ct_len = struct.unpack("<BI", block_head[NONCE_LEN:])
                ct = fi.read(ct_len)
                if len(ct) != ct_len:
                    raise FormatError("文件不完整，可能传输中断或被截断")

                aad = struct.pack("<QB", index, is_final)
                try:
                    plain = aes.decrypt(nonce, ct, aad)
                except Exception:
                    raise AuthError(
                        "口令错误，或文件已损坏/被篡改（两者无法区分）")

                fo.write(plain)
                done += len(ct)
                if progress:
                    progress(min(done, total), total)

                index += 1
                if is_final:
                    break
        os.replace(tmp, dst)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise
    return dst


# ---------------------------------------------------------------- 命令行

def _usage():
    print(__doc__.strip())
    print()
    print("示例：")
    print("  python dzenc.py encrypt 报告.docx -p 我的口令")
    print("  python dzenc.py decrypt 报告.docx.enc -p 我的口令")


def _main(argv):
    if len(argv) < 3 or argv[1] not in ("encrypt", "decrypt", "e", "d"):
        _usage()
        return 2

    action = argv[1]
    src = argv[2]
    password = None
    dst = None

    i = 3
    while i < len(argv):
        if argv[i] in ("-p", "--password") and i + 1 < len(argv):
            password = argv[i + 1]
            i += 2
        elif argv[i] in ("-o", "--output") and i + 1 < len(argv):
            dst = argv[i + 1]
            i += 2
        else:
            print(f"无法识别的参数：{argv[i]}")
            return 2

    if password is None:
        try:
            import getpass
            password = getpass.getpass("请输入口令：")
        except Exception:
            # 打包成无控制台的 exe 时读不到交互输入，必须显式给 -p
            print("当前环境无法交互输入口令，请用 -p 参数指定，例如：-p 我的口令")
            return 2

    def show(done, total):
        pct = (done * 100 // total) if total else 100
        sys.stdout.write(f"\r  {pct:3d}%  {human_size(done)} / {human_size(total)}")
        sys.stdout.flush()

    try:
        if action in ("encrypt", "e"):
            out = encrypt_file(src, dst, password, show)
            print(f"\n已加密 → {out}")
        else:
            out = decrypt_file(src, dst, password, show)
            print(f"\n已解密 → {out}")
        return 0
    except EncError as e:
        print(f"\n失败：{e}")
        return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
