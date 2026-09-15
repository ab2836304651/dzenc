# -*- coding: utf-8 -*-
"""
DZEnc 图形界面

设计原则：使用者不需要理解任何密码学概念。
  选文件 → 输口令 → 点按钮，三步结束。
  程序自己根据文件后缀判断该加密还是该解密。
"""

import math
import os
import secrets
import sys
import threading
import traceback

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dzenc

# Windows 高分屏下避免界面模糊
try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# 拖拽支持（可选）：装了 tkinterdnd2 就能拖文件进来，没装则退回"点击选择"
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except Exception:
    HAS_DND = False

# ------------------------------------------------------------------ 配色

BG = "#f4f6fa"
CARD = "#ffffff"
BORDER = "#cfd8e3"
TEXT = "#1f2937"
MUTED = "#6b7280"
PRIMARY = "#2563eb"
PRIMARY_DARK = "#1d4ed8"
OK_COLOR = "#059669"
ERR_COLOR = "#dc2626"
WARN_COLOR = "#d97706"

FONT = "Microsoft YaHei UI"


def _strength(password):
    """口令强度评估：粗估信息熵，只做提示不阻止使用。

    熵 = 长度 × log2(候选字符集大小)。只看字符种类会误判——
    一个 14 位随机字母串的强度远高于 6 位「大小写+数字」短口令。
    """
    if not password:
        return "", MUTED
    n = len(password)
    if any(ord(c) > 127 for c in password):
        pool = 3000                       # 中文等非 ASCII：按常用字规模估
    else:
        kinds = sum([
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ])
        pool = (10, 36, 62, 95)[max(0, min(3, kinds - 1))]
    bits = n * math.log2(pool)
    if bits < 40:
        return f"弱（约 {bits:.0f} 位熵）—— 容易被暴力破解，建议加长", ERR_COLOR
    if bits < 70:
        return f"中（约 {bits:.0f} 位熵）—— 可用，再长一点更稳", WARN_COLOR
    return f"强（约 {bits:.0f} 位熵）", OK_COLOR


class App:
    def __init__(self, root):
        self.root = root
        self.src_path = None
        self.mode = "encrypt"
        self.busy = False

        root.title("文件加密工具")
        root.configure(bg=BG)

        self._build()

        # 按内容需要的高度调整窗口；额外留 60px 余量，
        # 因为完成后状态栏文字（长路径）会折成两行，不预留就会把底部提示挤掉
        root.update_idletasks()
        w = 620
        h = min(root.winfo_reqheight() + 60, root.winfo_screenheight() - 120)
        root.geometry(f"{w}x{h}")
        root.minsize(w, h)
        self._center(w, h)

    def _center(self, w, h):
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw - w) // 2}+{max(0, (sh - h) // 2 - 30)}")

    # -------------------------------------------------------------- 界面构建

    def _build(self):
        pad = 24
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=pad, pady=18)

        # 标题
        tk.Label(wrap, text="🔒  文件加密工具", bg=BG, fg=TEXT,
                 font=(FONT, 17, "bold")).pack(anchor="w")
        tk.Label(wrap, text="选文件 → 输口令 → 点按钮，密文可以放心用微信或网盘传",
                 bg=BG, fg=MUTED, font=(FONT, 9)).pack(anchor="w", pady=(2, 12))

        # ---- 文件选择卡片
        card = tk.Frame(wrap, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="x")

        self.drop = tk.Label(
            card, text="📄  点击这里选择文件\n加密请选原文件；解密请选 .enc 文件",
            bg=CARD, fg=MUTED, font=(FONT, 10), cursor="hand2",
            justify="center", pady=26)
        self.drop.pack(fill="x")
        self.drop.bind("<Button-1>", lambda e: self.choose_file())
        self.drop.bind("<Enter>", lambda e: self.drop.config(fg=PRIMARY))
        self.drop.bind("<Leave>", lambda e: self.drop.config(fg=MUTED))

        # 拖拽注册：tkinterdnd2 只有在用 TkinterDnD.Tk() 建窗口时才可用，
        # 注册失败就静默退回「点击选择」，不影响主要功能
        self.dnd_ok = False
        if HAS_DND:
            try:
                self.drop.drop_target_register(DND_FILES)
                self.drop.dnd_bind("<<Drop>>", self.on_drop)
                self.dnd_ok = True
                self.drop.config(text="📄  把文件拖到这里\n加密请选原文件；解密请选 .enc 文件")
            except Exception:
                self.dnd_ok = False

        # ---- 口令区
        pw_card = tk.Frame(wrap, bg=BG)
        pw_card.pack(fill="x", pady=(14, 0))

        tk.Label(pw_card, text="口令", bg=BG, fg=TEXT,
                 font=(FONT, 10)).pack(anchor="w")
        row1 = tk.Frame(pw_card, bg=BG)
        row1.pack(fill="x", pady=(4, 0))
        self.pw = tk.Entry(row1, show="●", font=(FONT, 11), relief="solid",
                           bd=1, highlightthickness=0)
        self.pw.pack(side="left", fill="x", expand=True, ipady=5)
        self.pw.bind("<KeyRelease>", self._on_pw_change)
        self.show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row1, text="显示", variable=self.show_var, bg=BG,
                       activebackground=BG, font=(FONT, 9),
                       command=self._toggle_show).pack(side="left", padx=(6, 0))
        tk.Button(row1, text="生成强口令", font=(FONT, 9), relief="flat",
                  bg="#e5e9f0", fg=TEXT, cursor="hand2", padx=8,
                  activebackground="#d6dce6",
                  command=self._gen_password).pack(side="left", padx=(6, 0))

        self.pw_hint = tk.Label(pw_card, text="", bg=BG, font=(FONT, 8))
        self.pw_hint.pack(anchor="w", pady=(3, 0))

        # 确认口令（仅加密模式显示）
        self.confirm_wrap = tk.Frame(pw_card, bg=BG)
        self.confirm_wrap.pack(fill="x", pady=(8, 0))
        tk.Label(self.confirm_wrap, text="再输一遍（防止打错）", bg=BG,
                 fg=TEXT, font=(FONT, 10)).pack(anchor="w")
        self.pw2 = tk.Entry(self.confirm_wrap, show="●", font=(FONT, 11),
                            relief="solid", bd=1, highlightthickness=0)
        self.pw2.pack(fill="x", pady=(4, 0), ipady=5)

        # ---- 主按钮
        self.btn = tk.Button(wrap, text="开 始 加 密", font=(FONT, 12, "bold"),
                             bg=PRIMARY, fg="white", relief="flat",
                             cursor="hand2", pady=11,
                             activebackground=PRIMARY_DARK,
                             activeforeground="white", command=self.start)
        self.btn.pack(fill="x", pady=(16, 0))

        # ---- 进度与状态
        self.bar = ttk.Progressbar(wrap, mode="determinate", maximum=100)
        self.bar.pack(fill="x", pady=(12, 0))

        self.status = tk.Label(wrap, text="等待选择文件…", bg=BG, fg=MUTED,
                               font=(FONT, 9), wraplength=560, justify="left")
        self.status.pack(anchor="w", pady=(6, 0))

        tk.Label(wrap, text="提示：口令请通过另一条渠道告知对方（当面、电话），"
                            "不要和密文发在同一个聊天窗口里。",
                 bg=BG, fg=MUTED, font=(FONT, 8), wraplength=560,
                 justify="left").pack(anchor="w", pady=(10, 0))

        # 快捷键：Ctrl+O 选文件，回车直接开始（不想用鼠标的人可以用键盘走完全程）
        self.root.bind("<Control-o>", lambda e: self.choose_file())
        self.root.bind("<Return>", lambda e: self.start())

    # -------------------------------------------------------------- 交互逻辑

    def _toggle_show(self):
        ch = "" if self.show_var.get() else "●"
        self.pw.config(show=ch)
        self.pw2.config(show=ch)

    def _on_pw_change(self, _event=None):
        text, color = _strength(self.pw.get())
        self.pw_hint.config(text=f"强度：{text}" if text else "", fg=color)

    def _gen_password(self):
        # 剔除易混淆字符（0/O、1/l/I），方便口头转述
        lower = "abcdefghijkmnpqrstuvwxyz"
        upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        digit = "23456789"
        allc = lower + upper + digit
        chars = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digit)]
        chars += [secrets.choice(allc) for _ in range(11)]
        secrets.SystemRandom().shuffle(chars)     # 保证三类字符都出现
        pw = "".join(chars)
        self.pw.delete(0, "end")
        self.pw.insert(0, pw)
        self.pw2.delete(0, "end")
        self.pw2.insert(0, pw)
        self.show_var.set(True)
        self._toggle_show()
        self._on_pw_change()
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        self.set_status(f"已生成口令并复制到剪贴板：{pw}    请通过电话等方式告知对方", OK_COLOR)

    def choose_file(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(title="选择文件")
        if path:
            self._set_file(path)

    def on_drop(self, event):
        if self.busy:
            return
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            paths = [event.data]
        if paths:
            self._set_file(paths[0])

    def _set_file(self, path):
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            self.set_status("请选择一个文件（暂不支持文件夹）", ERR_COLOR)
            return
        self.src_path = path
        name = os.path.basename(path)
        size = dzenc.human_size(os.path.getsize(path))
        is_enc = path.lower().endswith(dzenc.ENC_SUFFIX)
        self.mode = "decrypt" if is_enc else "encrypt"

        icon = "🔓" if is_enc else "🔒"
        self.drop.config(text=f"{icon}  {name}\n{size}", fg=TEXT)
        if is_enc:
            self.confirm_wrap.pack_forget()
            self.btn.config(text="开 始 解 密", bg=OK_COLOR,
                            activebackground="#047857")
            self.set_status("已选择加密文件，请输入口令后解密", MUTED)
        else:
            self.confirm_wrap.pack(fill="x", pady=(8, 0))
            self.btn.config(text="开 始 加 密", bg=PRIMARY,
                            activebackground=PRIMARY_DARK)
            self.set_status("已选择文件，请输入口令后加密", MUTED)
        self.bar["value"] = 0
        self.pw.focus_set()

    def set_status(self, text, color=MUTED):
        self.status.config(text=text, fg=color)

    # -------------------------------------------------------------- 执行

    def start(self):
        if self.busy:
            return
        if not self.src_path:
            messagebox.showwarning("还没选文件", "请先选择要处理的文件。")
            return
        pw = self.pw.get()
        if not pw:
            messagebox.showwarning("口令为空", "请输入口令。")
            return
        if self.mode == "encrypt":
            if pw != self.pw2.get():
                messagebox.showwarning("两次口令不一致", "请检查两次输入的口令是否相同。")
                return
            _, color = _strength(pw)
            if color == ERR_COLOR:
                if not messagebox.askyesno(
                        "口令较弱",
                        "当前口令容易被暴力破解。\n\n"
                        "建议点击「生成强口令」，或改用一句较长的中文短语。\n\n"
                        "仍要继续吗？"):
                    return
            dst = dzenc.default_encrypt_name(self.src_path)
            if os.path.exists(dst) and not messagebox.askyesno(
                    "文件已存在", f"{os.path.basename(dst)} 已存在，要覆盖吗？"):
                return
        else:
            dst = dzenc.default_decrypt_name(self.src_path)
            if os.path.exists(dst) and not messagebox.askyesno(
                    "文件已存在", f"{os.path.basename(dst)} 已存在，要覆盖吗？"):
                return

        self.busy = True
        self.btn.config(state="disabled")
        self.bar["value"] = 0
        verb = "加密" if self.mode == "encrypt" else "解密"
        self.set_status(f"正在{verb}…", MUTED)

        t = threading.Thread(target=self._worker, args=(pw, dst, verb), daemon=True)
        t.start()

    def _worker(self, pw, dst, verb):
        def progress(done, total):
            pct = int(done * 100 / total) if total else 100
            self.root.after(0, lambda: self.bar.config(value=pct))

        try:
            if self.mode == "encrypt":
                out = dzenc.encrypt_file(self.src_path, dst, pw, progress)
            else:
                out = dzenc.decrypt_file(self.src_path, dst, pw, progress)
        except Exception as e:
            err = str(e)
            if not isinstance(e, dzenc.EncError):
                err = f"发生未预期的错误：{type(e).__name__}: {e}"
                traceback.print_exc()
            self.root.after(0, lambda: self._finish(None, err, verb))
        else:
            self.root.after(0, lambda: self._finish(out, None, verb))

    def _finish(self, out, err, verb):
        self.busy = False
        self.btn.config(state="normal")
        self.bar["value"] = 100
        if err:
            self.bar["value"] = 0
            self.set_status(f"{verb}失败：{err}", ERR_COLOR)
            messagebox.showerror(f"{verb}失败", err)
        else:
            size = dzenc.human_size(os.path.getsize(out))
            self.set_status(f"{verb}完成 → {out}   （{size}）", OK_COLOR)


def _ensure_output_stream():
    """打包成 --windowed 的 exe 没有控制台，sys.stdout 会是 None。
    命令行模式下改写日志文件，保证有输出可查。"""
    if sys.stdout is not None:
        return None
    try:
        path = os.path.join(os.getcwd(), "dzenc_cli.log")
        f = open(path, "w", encoding="utf-8", buffering=1)
    except Exception:
        return None
    sys.stdout = f
    sys.stderr = f
    return f


def main():
    # 带参数启动 = 命令行模式，不弹窗口。
    # 例：文件加密工具.exe encrypt 报告.docx -p 口令
    if len(sys.argv) > 1:
        _ensure_output_stream()
        return dzenc._main(sys.argv)

    root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TProgressbar", troughcolor="#e5e9f0", background=PRIMARY,
                    bordercolor="#e5e9f0", lightcolor=PRIMARY, darkcolor=PRIMARY)
    App(root)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
