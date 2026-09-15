# -*- coding: utf-8 -*-
"""对打包后的 exe 做端到端实测：走真实进程，不用源码。

验证点：
  1. exe 的命令行模式能真正完成加密/解密（证明 cryptography 及其
     OpenSSL 二进制确实被打进了包，而不只是"能启动界面"）
  2. 错误口令被拒绝
  3. 篡改的密文被拒绝

运行：python test_exe_e2e.py
"""

import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "dist", "文件加密工具.exe")
PW = "Exe-E2E-Test-2026!"

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'[通过]' if ok else '[失败]'} {name}" + (f"  —— {detail}" if detail else ""))


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def run_exe(work, args):
    """跑 exe 的命令行模式。--windowed 打包的程序没有控制台，
    输出会落在工作目录的 dzenc_cli.log 里。"""
    log = os.path.join(work, "dzenc_cli.log")
    if os.path.exists(log):
        os.remove(log)
    r = subprocess.run([EXE] + args, cwd=work, capture_output=True,
                       timeout=180)
    text = ""
    if os.path.exists(log):
        text = open(log, encoding="utf-8", errors="replace").read()
    return r.returncode, text


def main():
    if not os.path.exists(EXE):
        print("找不到 exe，先运行 build.py")
        return 1

    work = tempfile.mkdtemp(prefix="dzenc_exe_")
    src = os.path.join(work, "测试文档.txt")
    with open(src, "w", encoding="utf-8") as f:
        f.write("圆周率与加密工具验收\n" * 500)
    orig_hash = sha(src)

    # ---- 1. 加密 ----
    code, out = run_exe(work, ["encrypt", src, "-p", PW])
    enc = src + ".enc"
    ok = code == 0 and os.path.exists(enc)
    check("exe 命令行加密", ok,
          f"退出码 {code}，产物 {'已生成' if os.path.exists(enc) else '缺失'}"
          + (f"，输出：{out.strip().splitlines()[-1]}" if out.strip() else ""))

    # ---- 2. 解密并比对 ----
    dec = os.path.join(work, "还原.txt")
    code, out = run_exe(work, ["decrypt", enc, "-p", PW, "-o", dec])
    ok = code == 0 and os.path.exists(dec) and sha(dec) == orig_hash
    check("exe 命令行解密且内容一致", ok,
          f"sha256 {'匹配' if os.path.exists(dec) and sha(dec) == orig_hash else '不匹配'}")

    # ---- 3. 错误口令 ----
    code, out = run_exe(work, ["decrypt", enc, "-p", "错误口令",
                               "-o", os.path.join(work, "bad.txt")])
    ok = code != 0 and not os.path.exists(os.path.join(work, "bad.txt"))
    check("exe 拒绝错误口令", ok, f"退出码 {code}")

    # ---- 4. 篡改密文 ----
    raw = bytearray(open(enc, "rb").read())
    raw[-1] ^= 0x01
    bad = os.path.join(work, "篡改.enc")
    open(bad, "wb").write(bytes(raw))
    code, out = run_exe(work, ["decrypt", bad, "-p", PW,
                               "-o", os.path.join(work, "tamper.txt")])
    ok = code != 0 and not os.path.exists(os.path.join(work, "tamper.txt"))
    check("exe 拒绝被篡改的密文", ok, f"退出码 {code}")

    n_ok = sum(results)
    print(f"\n总计 {n_ok}/{len(results)} 项通过")
    print(f"工作目录：{work}")
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
