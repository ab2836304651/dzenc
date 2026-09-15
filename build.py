# -*- coding: utf-8 -*-
"""重新打包成单文件 exe。用法：双击 build.bat，或 python build.py

代码里写中文路径/名字，避免批处理文件的编码坑。
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "文件加密工具"


def main():
    os.chdir(HERE)
    if not os.path.exists("dzgui.py"):
        print("找不到 dzgui.py，请在工具目录下运行")
        return 1

    for d in ("dist", "build"):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",           # 单文件，方便拷贝分发
        "--windowed",          # 不弹黑色控制台窗口
        "--noconfirm", "--clean",
        "--name", APP_NAME,
        "--distpath", "dist",
        "--workpath", "build",
        "--specpath", "build",
        # 不用 UPX：压缩后更容易被杀毒软件误报
        "dzgui.py",
    ]
    print("打包中，请稍候（约 1-2 分钟）…")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("\n打包失败。")
        return r.returncode

    exe = os.path.join("dist", APP_NAME + ".exe")
    if not os.path.exists(exe):
        print("\n打包命令跑完了，但没找到产物。")
        return 1
    size = os.path.getsize(exe) / 1048576
    print(f"\n打包成功：{exe}  （{size:.1f} MB）")
    print("把它拷给使用者即可，对方电脑不需要装 Python。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
