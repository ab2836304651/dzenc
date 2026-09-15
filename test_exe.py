# -*- coding: utf-8 -*-
"""验证打包后的 exe：独立启动、界面渲染、拖拽支持是否随包带过去。

运行：python test_exe.py
"""

import os
import subprocess
import sys
import time
from ctypes import windll

import win32con
import win32gui
import win32ui
from PIL import Image

# 必须让截图进程也具备 DPI 感知，否则 GetWindowRect 返回的是虚拟化坐标，
# 与屏幕物理像素对不上，截出来的图会比真实窗口小一圈
try:
    windll.shcore.SetProcessDpiAwareness(2)      # PER_MONITOR_AWARE
except Exception:
    try:
        windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def capture_window(hwnd):
    """用 PrintWindow 直接抓窗口自身渲染的内容，不受遮挡和坐标缩放影响。"""
    left, top, right, bot = win32gui.GetWindowRect(hwnd)
    w, h = right - left, bot - top
    hwnd_dc = win32gui.GetWindowDC(hwnd)
    mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
    save_dc = mfc_dc.CreateCompatibleDC()
    bmp = win32ui.CreateBitmap()
    bmp.CreateCompatibleBitmap(mfc_dc, w, h)
    save_dc.SelectObject(bmp)
    # PW_RENDERFULLCONTENT = 2，能抓到 DWM 合成后的完整内容
    windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
    info = bmp.GetInfo()
    bits = bmp.GetBitmapBits(True)
    img = Image.frombuffer("RGB", (info["bmWidth"], info["bmHeight"]),
                           bits, "raw", "BGRX", 0, 1)
    win32gui.DeleteObject(bmp.GetHandle())
    save_dc.DeleteDC()
    mfc_dc.DeleteDC()
    win32gui.ReleaseDC(hwnd, hwnd_dc)
    return img

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "dist", "文件加密工具.exe")
SHOT_DIR = os.path.join(HERE, "验收截图")
TITLE = "文件加密工具"


def find_window(timeout=40):
    """等 exe 启动并找到它的主窗口（onefile 首次启动要解压，会慢）。"""
    deadline = time.time() + timeout
    found = []

    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == TITLE:
            found.append(hwnd)

    while time.time() < deadline:
        found.clear()
        win32gui.EnumWindows(cb, None)
        if found:
            return found[0]
        time.sleep(0.5)
    return None


def main():
    if not os.path.exists(EXE):
        print(f"找不到 {EXE}，请先运行 build.py 打包")
        return 1

    size = os.path.getsize(EXE) / 1048576
    print(f"exe 大小：{size:.1f} MB")

    t0 = time.time()
    proc = subprocess.Popen([EXE], cwd=os.path.dirname(EXE))
    print("已启动，等待窗口出现…")
    hwnd = find_window()
    if not hwnd:
        proc.terminate()
        print("[失败] 40 秒内没等到窗口")
        return 1

    print(f"[通过] 启动耗时 {time.time() - t0:.1f} 秒，窗口已出现")

    # 置顶并截图
    try:
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
    except Exception as e:
        print(f"（置顶失败，不影响验证）{e}")
    time.sleep(1.2)

    rect = win32gui.GetWindowRect(hwnd)
    x, y, x2, y2 = rect
    print(f"窗口位置 {rect}  尺寸 {x2 - x} x {y2 - y}")

    img = capture_window(hwnd)
    out = os.path.join(SHOT_DIR, "7_exe独立运行.png")
    img.save(out)
    print(f"[截图] {out}")

    print(f"窗口标题：{win32gui.GetWindowText(hwnd)}")
    proc.terminate()
    time.sleep(1)
    print("已关闭 exe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
