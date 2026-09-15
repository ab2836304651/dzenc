# -*- coding: utf-8 -*-
"""DZEnc 验收测试：逐项对应计划的验收表。运行：python test_dzenc.py"""

import hashlib
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dzenc

PASS, FAIL = "[通过]", "[失败]"
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{PASS if ok else FAIL} {name}" + (f"  —— {detail}" if detail else ""))


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    d = tempfile.mkdtemp(prefix="dzenc_test_")
    pw = "测试口令-OpenAI#2026"

    # ---------- 验收项 1：往返无损（含多种长度，覆盖分块边界） ----------
    cases = {
        "空文件": b"",
        "1字节": b"A",
        "正好1MiB": os.urandom(1 << 20),
        "1MiB+1字节": os.urandom((1 << 20) + 1),
        "3MiB随机": os.urandom(3 * (1 << 20) + 12345),
        "含中文文本": ("圆周率前三百万位" * 3).encode("utf-8"),
    }
    all_ok = True
    for label, data in cases.items():
        src = os.path.join(d, f"case_{label}.bin")
        with open(src, "wb") as f:
            f.write(data)
        enc = dzenc.encrypt_file(src, None, pw)
        dec = dzenc.decrypt_file(enc, os.path.join(d, f"out_{label}.bin"), pw)
        ok = sha(src) == sha(dec) and os.path.getsize(src) == os.path.getsize(dec)
        if not ok:
            all_ok = False
            print(f"       ↳ {label} 不一致：原 {os.path.getsize(src)} / 解 {os.path.getsize(dec)}")
    check("验收1 加密→解密往返无损（6 种长度含边界）", all_ok)

    # ---------- 验收项 2：口令错误必须失败且不留垃圾文件 ----------
    src = os.path.join(d, "case_3MiB随机.bin")
    enc = src + ".enc"
    out_wrong = os.path.join(d, "wrong_out.bin")
    try:
        dzenc.decrypt_file(enc, out_wrong, "错误的密码")
        check("验收2a 错误口令被拒绝", False, "居然解密成功了")
    except dzenc.AuthError as e:
        check("验收2a 错误口令被拒绝", True, str(e))
    except Exception as e:
        check("验收2a 错误口令被拒绝", False, f"异常类型不对：{type(e).__name__}: {e}")
    leftover = [f for f in os.listdir(d) if ".part" in f or f == "wrong_out.bin"]
    check("验收2b 失败后不留半截垃圾文件", not leftover, f"残留：{leftover}" if leftover else "")

    # ---------- 验收项 3：篡改密文必须被检测 ----------
    src = os.path.join(d, "case_1字节.bin")
    enc = dzenc.encrypt_file(src, os.path.join(d, "tamper.enc"), pw)
    raw = bytearray(open(enc, "rb").read())
    raw[-1] ^= 0x01                      # 翻转密文最后一个字节
    tampered = os.path.join(d, "tampered.enc")
    open(tampered, "wb").write(bytes(raw))
    try:
        dzenc.decrypt_file(tampered, os.path.join(d, "tamper_out.bin"), pw)
        check("验收3a 篡改密文被拒绝", False, "篡改后仍解密成功")
    except dzenc.AuthError:
        check("验收3a 篡改密文被拒绝", True, "翻转 1 bit 即触发认证失败")

    # 截断攻击：砍掉最后一个数据块
    src = os.path.join(d, "case_3MiB随机.bin")
    enc = dzenc.encrypt_file(src, os.path.join(d, "trunc.enc"), pw)
    raw = open(enc, "rb").read()
    cut = os.path.join(d, "truncated.enc")
    open(cut, "wb").write(raw[:len(raw) - (1 << 20)])   # 丢掉末尾约 1MiB
    try:
        dzenc.decrypt_file(cut, os.path.join(d, "trunc_out.bin"), pw)
        check("验收3b 截断密文被拒绝", False, "截断后仍解密成功")
    except dzenc.EncError as e:
        check("验收3b 截断密文被拒绝", True, str(e))

    # 块重排：交换头两个数据块（保持长度一致才能交换干净）
    src = os.path.join(d, "case_3MiB随机.bin")
    enc = dzenc.encrypt_file(src, os.path.join(d, "swap.enc"), pw)
    raw = open(enc, "rb").read()
    hdr = raw[:dzenc.HEADER_LEN]
    body = raw[dzenc.HEADER_LEN:]
    blk = dzenc.CHUNK_SIZE + dzenc.NONCE_LEN + 5 + 16      # 满块密文长度
    b1, b2, rest = body[:blk], body[blk:2 * blk], body[2 * blk:]
    swapped = os.path.join(d, "swapped.enc")
    open(swapped, "wb").write(hdr + b2 + b1 + rest)
    try:
        dzenc.decrypt_file(swapped, os.path.join(d, "swap_out.bin"), pw)
        check("验收3c 密文块重排被拒绝", False, "重排后仍解密成功")
    except dzenc.EncError as e:
        check("验收3c 密文块重排被拒绝", True, str(e))

    # ---------- 验收项 4：随机性——同文件同口令两次加密结果必须不同 ----------
    src = os.path.join(d, "case_含中文文本.bin")
    e1 = dzenc.encrypt_file(src, os.path.join(d, "r1.enc"), pw)
    e2 = dzenc.encrypt_file(src, os.path.join(d, "r2.enc"), pw)
    c1, c2 = open(e1, "rb").read(), open(e2, "rb").read()
    check("验收4 两次加密密文不同（salt/nonce 随机）",
          c1 != c2 and len(c1) == len(c2),
          f"长度 {len(c1)} 字节，内容不同")
    # 且两者都能正常解开
    ok = all(sha(dzenc.decrypt_file(e, os.path.join(d, f"r_out{i}.bin"), pw)) == sha(src)
             for i, e in enumerate([e1, e2], 1))
    check("验收4b 两份密文都能正常解密", ok)

    # ---------- 附加：文件格式识别 ----------
    fake = os.path.join(d, "fake.enc")
    open(fake, "wb").write(b"this is not an encrypted file" * 10)
    try:
        dzenc.decrypt_file(fake, os.path.join(d, "fake_out.bin"), pw)
        check("附加 非本工具文件被识别", False, "居然没报错")
    except dzenc.FormatError as e:
        check("附加 非本工具文件被识别", True, str(e))

    # ---------- 附加：空口令拒绝 ----------
    try:
        dzenc.encrypt_file(src, os.path.join(d, "empty_pw.enc"), "")
        check("附加 空口令被拒绝", False)
    except dzenc.EncError:
        check("附加 空口令被拒绝", True)

    # ---------- 附加：源文件在加密后保持完好 ----------
    src2 = os.path.join(d, "keep.txt")
    open(src2, "wb").write("原始内容不应被改动".encode("utf-8"))
    before = sha(src2)
    dzenc.encrypt_file(src2, None, pw)
    check("附加 加密不破坏源文件", sha(src2) == before)

    print()
    n_ok = sum(results)
    print(f"总计 {n_ok}/{len(results)} 项通过")
    print(f"测试目录：{d}")
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
