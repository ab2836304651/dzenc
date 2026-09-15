# -*- coding: utf-8 -*-
"""GUI 冒烟测试：自动走完「选文件→输口令→加密→解密」全流程，每步截图。

不是给人看的脚本，是给验收用的：跑完会产出若干张 PNG 和一份结果清单。
运行：python test_gui.py
"""

import hashlib
import os
import sys
import tempfile
import time
import tkinter as tk

from PIL import ImageGrab

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dzenc
import dzgui

try:
    from tkinterdnd2 import TkinterDnD
    HAS_DND = True
except Exception:
    HAS_DND = False

WORK = tempfile.mkdtemp(prefix="dzenc_gui_")
SHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "验收截图")
os.makedirs(SHOT_DIR, exist_ok=True)

log = []


def note(msg):
    print(msg, flush=True)
    log.append(msg)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# 造一个测试源文件：既有中文又有足够长度，能看出分块进度
SRC = os.path.join(WORK, "期末成绩汇总.txt")
with open(SRC, "w", encoding="utf-8") as f:
    for i in range(4000):
        f.write(f"第{i + 1}行：这是一段用于验证加密工具的测试文本内容。\n")

root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
try:
    import ttk
    ttk.Style().theme_use("clam")
except Exception:
    pass
app = dzgui.App(root)


def shot(name):
    # 窗口必须先置顶，否则 ImageGrab 抓到的是压在上面的其它窗口
    root.attributes("-topmost", True)
    root.lift()
    root.focus_force()
    root.update_idletasks()
    root.update()
    time.sleep(0.3)
    root.update()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    w, h = root.winfo_width(), root.winfo_height()
    box = (max(0, x - 10), max(0, y - 42), x + w + 10, y + h + 10)
    img = ImageGrab.grab(bbox=box, all_screens=True)
    path = os.path.join(SHOT_DIR, name)
    img.save(path)
    note(f"[截图] {name}  {img.size[0]}x{img.size[1]}")
    return path


def fail(msg):
    note(f"[失败] {msg}")
    root.destroy()


# ------------------------------------------------------------------ 流程

def step1():
    note(f"拖拽功能可用：{app.dnd_ok}")
    app._set_file(SRC)
    shot("1_已选文件_加密模式.png")
    root.after(250, step2)


def step2():
    app.pw.insert(0, "Test-Password-2026!")
    app.pw2.insert(0, "Test-Password-2026!")
    app._on_pw_change()
    shot("2_已填口令.png")
    root.after(250, step3)


def step3():
    app.start()
    root.after(1800, step4)


def step4():
    if app.busy:
        root.after(600, step4)
        return
    shot("3_加密完成.png")
    enc = SRC + ".enc"
    if not os.path.exists(enc):
        return fail("加密未产生输出文件")
    note(f"加密产物：{os.path.basename(enc)}  {dzenc.human_size(os.path.getsize(enc))}")
    root.after(250, step5)


def step5():
    # 切换到解密模式：把 .enc 文件塞进界面
    app._set_file(SRC + ".enc")
    shot("4_已选加密文件_解密模式.png")
    root.after(250, step6)


def step6():
    app.pw.delete(0, "end")
    app.pw.insert(0, "Test-Password-2026!")
    app.start()
    root.after(1800, step7)


def step7():
    if app.busy:
        root.after(600, step7)
        return
    shot("5_解密完成.png")
    root.after(200, step8)


def step8():
    # ---- 结果核验：解密回原路径，内容应与加密前逐字节一致 ----
    if not os.path.exists(SRC):
        return fail("解密未产生输出文件")
    ok = sha(SRC) == ORIG_SHA
    note(f"[{'通过' if ok else '失败'}] GUI 全流程往返内容一致")

    # ---- 测「生成强口令」按钮 ----
    app.pw.delete(0, "end")
    app._gen_password()
    shot("6_生成强口令.png")
    strength = dzgui._strength(app.pw.get())[0]
    note(f"[通过] 生成强口令：长度 {len(app.pw.get())}，强度「{strength.split(' ')[0]}」")

    note("GUI 冒烟测试结束")
    root.after(300, root.destroy)


# 先记下原始指纹，最后用来核验往返无损
ORIG_SHA = sha(SRC)

root.after(400, step1)
root.mainloop()
print(f"\n截图目录：{SHOT_DIR}")
