#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
process_cleaner.py —— 内存扫描与进程清理工具（Windows / 跨平台）

功能
----
1. 扫描当前所有进程的内存占用（工作集 / 私有内存），按内存从大到小排序显示，
   并识别每个进程属于哪个软件（读取 exe 文件版本信息中的产品名/公司名）；
2. 在表格下方绘制内存占比纯 ASCII 横向柱状图（Top30，占物理内存百分比）；
3. 支持按 序号 / PID / 名称关键词 选择要结束的进程，可多选；
3. 内置两级保护，防止误杀系统关键进程：
   - 硬保护：结束即可能导致系统崩溃 / 蓝屏 / 注销 / 输入法失效，程序直接拒绝；
   - 软保护：默认拒绝，输入 FORCE-KILL 可强制结束（如 explorer 结束会重启桌面）。

用法
----
    python process_cleaner.py                 # 交互式：扫描 -> 选择 -> 清理
    python process_cleaner.py --top 50        # 每次显示前 50 个进程
    python process_cleaner.py --list-only     # 只打印一次列表，不进入交互

交互输入说明
------------
    12,15,18          结束列表中第 12、15、18 个进程
    p:1234            按 PID 结束进程 1234
    chrome            结束名称包含 chrome 的所有进程
    f:微信             用关键词过滤后重新显示列表
    r                 重新扫描
    q                 退出

依赖
----
    pip install psutil
"""

import argparse
import os
import re
import shutil
import sys

try:
    import psutil
except ImportError:
    print("缺少依赖 psutil，请先运行: pip install psutil")
    sys.exit(1)

# ==================== 保护配置 ====================
# 硬保护：结束即可能导致系统崩溃 / 蓝屏 / 注销 / 功能失效，程序一律拒绝
HARD_PROTECTED = {
    "system", "registry", "smss", "csrss", "wininit", "winlogon",
    "services", "lsass", "svchost", "dwm", "msmpeng", "audiodg",
    "fontdrvhost", "runtimebroker", "sihost", "ctfmon",
}
# 软保护：默认拒绝，输入 FORCE-KILL 可强制结束
SOFT_PROTECTED = {"explorer", "conhost", "cmd", "windowsterminal"}

PROTECT_REASON = {
    "system": "系统进程", "registry": "注册表", "smss": "会话管理器",
    "csrss": "核心运行时", "wininit": "Windows 启动初始化",
    "winlogon": "登录进程", "services": "服务控制管理器",
    "lsass": "本地安全认证", "svchost": "服务宿主(多个系统服务)",
    "dwm": "桌面窗口管理器", "msmpeng": "Windows Defender 杀毒",
    "audiodg": "音频设备图", "fontdrvhost": "字体驱动",
    "runtimebroker": "系统后台代理", "sihost": "Shell 基础设施",
    "ctfmon": "输入法/文本服务",
    "explorer": "资源管理器(结束会重启桌面)", "conhost": "控制台窗口宿主",
    "cmd": "命令提示符", "windowsterminal": "Windows 终端",
}

# ==================== 控制台与颜色 ====================
_ANSI = False


def _enable_ansi():
    """Windows 上尝试开启 VT 转义序列支持；非终端或失败则关闭颜色。"""
    global _ANSI
    if sys.stdout.isatty():
        if os.name == "nt":
            try:
                import ctypes

                k32 = ctypes.windll.kernel32
                h = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                mode = ctypes.c_uint32()
                if k32.GetConsoleMode(h, ctypes.byref(mode)):
                    _ANSI = k32.SetConsoleMode(h, mode.value | 0x0004) != 0
            except Exception:
                _ANSI = False
        else:
            _ANSI = True


def col(code, text):
    return f"\033[{code}m{text}\033[0m" if _ANSI else text


BOLD, RED, GREEN, YELLOW, CYAN, DIM = "1", "91", "92", "93", "96", "90"


def fmt_mb(b):
    return f"{b / 1048576:,.0f}"


# ==================== 显示宽度（中文字符按 2 列计算） ====================
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def disp_width(s):
    s = _ANSI_RE.sub("", s)  # 忽略 ANSI 颜色转义，只按可见字符计数
    return sum(2 if ord(ch) > 0x7F else 1 for ch in s)


def pad(s, width):
    return s + " " * max(0, width - disp_width(s))


def truncate(s, width):
    """按显示宽度截断，超宽时末尾加省略号。"""
    if disp_width(s) <= width:
        return s
    out, w = "", 0
    for ch in s:
        cw = 2 if ord(ch) > 0x7F else 1
        if w + cw > width - 1:
            break
        out += ch
        w += cw
    return out + "…"


# ==================== 软件归属识别 ====================
_VER_CACHE = {}


def _file_version_info(exe):
    """读取 exe 的 (公司名, 产品名)；仅 Windows，失败返回空。结果按路径缓存。"""
    key = exe.lower()
    if key in _VER_CACHE:
        return _VER_CACHE[key]
    result = ("", "")
    if os.name == "nt" and exe:
        try:
            import ctypes
            from ctypes import wintypes

            ver = ctypes.windll.version
            # 显式声明参数/返回类型，避免 ctypes 按 ANSI 传宽字符串导致崩溃
            ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
            ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
            ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                                wintypes.DWORD, wintypes.LPVOID]
            ver.GetFileVersionInfoW.restype = wintypes.BOOL
            ver.VerQueryValueW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR,
                                           ctypes.POINTER(wintypes.LPVOID),
                                           ctypes.POINTER(wintypes.UINT)]
            ver.VerQueryValueW.restype = wintypes.BOOL

            size = ver.GetFileVersionInfoSizeW(exe, None)
            if size and size != 0xFFFFFFFF:
                buf = ctypes.create_string_buffer(size)
                if ver.GetFileVersionInfoW(exe, 0, size, ctypes.cast(buf, wintypes.LPVOID)):
                    trans_ptr = wintypes.LPVOID()
                    trans_len = wintypes.UINT()
                    if ver.VerQueryValueW(ctypes.cast(buf, wintypes.LPVOID),
                                          "\\VarFileInfo\\Translation",
                                          ctypes.byref(trans_ptr), ctypes.byref(trans_len)):
                        lang_cp = ctypes.cast(trans_ptr.value,
                                              ctypes.POINTER(ctypes.c_uint)).contents.value
                        lang = lang_cp & 0xFFFF
                        codepage = (lang_cp >> 16) & 0xFFFF

                        def query(sub):
                            sub_key = "\\StringFileInfo\\%04x%04x\\%s" % (lang, codepage, sub)
                            ptr = wintypes.LPVOID()
                            ln = wintypes.UINT()
                            if ver.VerQueryValueW(ctypes.cast(buf, wintypes.LPVOID), sub_key,
                                                  ctypes.byref(ptr), ctypes.byref(ln)):
                                try:
                                    # 注意：StringFileInfo 字符串值的长度单位是“字”(2字节)，
                                    # 直接按字节读会被截断一半，故乘 2 并限制不超过缓冲区剩余
                                    offset = ptr.value - ctypes.addressof(buf)
                                    nbytes = min(ln.value * 2, max(0, size - offset))
                                    return ctypes.string_at(ptr.value, nbytes).decode(
                                        "utf-16-le", "ignore").split("\x00", 1)[0]
                                except Exception:
                                    return ""
                            return ""

                        result = (query("CompanyName"), query("ProductName"))
        except Exception:
            result = ("", "")
    _VER_CACHE[key] = result
    return result


_GENERIC_PRODUCTS = {
    "", "windows", "windows operating system", "microsoft windows",
    "microsoft windows operating system", "microsoft® windows® operating system",
}


def software_of(name, exe):
    """推断进程所属软件：产品名 -> 公司名 -> exe 所在目录名 依次兜底。"""
    company, product = _file_version_info(exe)
    if product and product.lower() not in _GENERIC_PRODUCTS:
        return product
    if company:
        return company
    if exe:
        folder = os.path.basename(os.path.dirname(exe))
        if folder and folder.lower() not in (
            "program files", "program files (x86)", "windows", "system32",
            "syswow64", "application data", "local", "roaming",
        ):
            return folder
    return ""


# ==================== 扫描 ====================
def scan_processes():
    rows = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = p.info["pid"]
            name = p.info["name"] or "?"
            mi = p.info["memory_info"]
            rss = mi.rss if mi else 0
            private = getattr(mi, "private", 0) or 0
            exe = ""
            try:
                exe = p.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ""
            rows.append({
                "pid": pid, "name": name, "rss": rss, "private": private,
                "exe": exe, "software": software_of(name, exe),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return rows


# ==================== 保护判定 ====================
def norm(name):
    return (name or "").lower().replace(".exe", "")


def _ancestor_pids():
    pids = set()
    try:
        for a in psutil.Process(os.getpid()).parents():
            pids.add(a.pid)
    except Exception:
        pass
    return pids


_ANCESTORS = _ancestor_pids()


def protection_of(pid, name):
    """返回 (级别, 原因)：2=硬保护(拒绝) 1=软保护(需FORCE-KILL) 0=可结束"""
    n = norm(name)
    if pid == os.getpid():
        return 2, "本程序自身"
    if pid in _ANCESTORS:
        return 1, "本程序所在控制台"
    if n in HARD_PROTECTED:
        return 2, PROTECT_REASON.get(n, "系统关键进程")
    if n in SOFT_PROTECTED:
        return 1, PROTECT_REASON.get(n, "默认保护")
    return 0, ""


# ==================== 横向柱状图（纯 ASCII） ====================
def draw_bars(segments, max_width=60):
    """segments: [(标签, 占比%)]，返回纯 ASCII 横向柱状图行列表。

    柱长按占比线性映射，最大占比者占满 max_width 个 '#' 字符。
    """
    lines = []
    if not segments:
        return lines
    max_pct = max(p for _, p in segments) or 1.0
    for label, pct in segments:
        bar_len = int(round(pct / max_pct * max_width))
        lines.append("%s %s %5.1f%%" % (pad(truncate(label, 14), 14),
                                        "#" * bar_len, pct))
    return lines


# ==================== 展示 ====================
def show_table(rows, top):
    vm = psutil.virtual_memory()
    lines = []
    lines.append(col(BOLD, f"物理内存: 总量 {vm.total / 2**30:.1f}GB  已用 {vm.used / 2**30:.1f}GB "
                           f"({vm.percent:.0f}%)  可用 {vm.available / 2**30:.1f}GB  进程数 {len(rows)}"))
    lines.append(col(CYAN, f"  {'#':<3}{'PID':<7}{'进程名':<14}{'所属软件':<18}{'工作集MB':>10}{'私有MB':>10}  状态"))
    lines.append(col(CYAN, "-" * 84))
    for i, r in enumerate(rows[:top], 1):
        lvl, reason = protection_of(r["pid"], r["name"])
        if lvl == 2:
            flag = col(RED, pad(truncate("硬保护-" + reason, 15), 16))
        elif lvl == 1:
            flag = col(YELLOW, pad(truncate("软保护-" + reason, 15), 16))
        else:
            flag = ""
        name = pad(truncate(r["name"], 12), 14)
        sw = pad(truncate(r.get("software") or "-", 16), 18)
        lines.append(f"  {i:<3}{r['pid']:<7}{name}{sw}{fmt_mb(r['rss']):>10}{fmt_mb(r['private']):>10}  {flag}")
    lines.append(col(CYAN, "-" * 84))
    if len(rows) > top:
        lines.append(col(DIM, f"(共 {len(rows)} 个进程，仅显示前 {top} 个；输入 r 刷新、f:关键词 过滤)"))
    lines.append(col(DIM, "选择: 输入序号/PID(p:1234)/名称关键词(如 chrome)，逗号分隔可多选；q 退出"))

    for line in lines:
        print(line)

    # 表格下方绘制纯 ASCII 横向柱状图：内存占比 Top30（占物理内存 %）
    if rows:
        segments = [(r["name"], r["rss"] / vm.total * 100.0) for r in rows[:30]]
        term_w = shutil.get_terminal_size((120, 40)).columns
        bar_w = max(20, min(60, term_w - 30))
        print("")
        print("内存占比 Top30（占物理内存 %%），已用内存合计 %.1f%%" % vm.percent)
        for line in draw_bars(segments, bar_w):
            print(line)


# ==================== 选择解析 ====================
def resolve_selection(text, rows):
    targets, seen = [], set()
    parts = [x.strip() for x in text.replace("，", ",").replace(";", ",").replace(" ", ",").split(",") if x.strip()]
    for part in parts:
        pl = part.lower()
        if pl.startswith("p:"):
            pid = pl[2:]
            if pid.isdigit():
                for r in rows:
                    if str(r["pid"]) == pid and r["pid"] not in seen:
                        seen.add(r["pid"])
                        targets.append(r)
        elif pl.isdigit():
            idx = int(pl)
            if 1 <= idx <= len(rows):
                r = rows[idx - 1]
                if r["pid"] not in seen:
                    seen.add(r["pid"])
                    targets.append(r)
        else:
            for r in rows:
                hay = (r["name"] + " " + (r.get("software") or "")).lower()
                if pl in hay and r["pid"] not in seen:
                    seen.add(r["pid"])
                    targets.append(r)
    return targets


# ==================== 结束进程 ====================
def kill_process(pid, name):
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return True, "进程已不存在"
    try:
        p.terminate()          # 先优雅结束（Windows 上相当于发送关闭消息）
        p.wait(timeout=5)
        return True, "已优雅结束"
    except psutil.NoSuchProcess:
        return True, "进程已结束"
    except psutil.AccessDenied:
        return False, "权限不足(请以管理员身份运行本程序)"
    except psutil.TimeoutExpired:
        try:
            p.kill()           # 超时兜底：强制结束
            p.wait(timeout=5)
            return True, "超时后已强制结束"
        except psutil.NoSuchProcess:
            return True, "进程已结束"
        except psutil.AccessDenied:
            return False, "权限不足(请以管理员身份运行本程序)"
        except Exception as e:
            return False, f"强制结束失败: {e}"
    except Exception as e:
        return False, f"结束失败: {e}"


# ==================== 主流程 ====================
def main():
    ap = argparse.ArgumentParser(description="内存扫描与进程清理工具")
    ap.add_argument("--top", type=int, default=30, help="显示进程数量(默认30)")
    ap.add_argument("--list-only", action="store_true", help="仅列出进程，不进入交互")
    args = ap.parse_args()

    _enable_ansi()
    print(col(BOLD, "进程内存扫描与清理工具"))
    print(col(DIM, "硬保护进程无法结束；软保护进程需输入 FORCE-KILL 确认。"
                   "系统关键进程结束可能导致蓝屏/注销，已默认拒绝。"))

    rows = sorted(scan_processes(), key=lambda r: r["rss"], reverse=True)
    show_table(rows, args.top)

    if args.list_only:
        return

    while True:
        try:
            text = input(col(CYAN, "\n> ")).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n已退出")
            break
        if not text:
            continue
        low = text.lower()
        if low in ("q", "quit", "exit"):
            print("已退出")
            break
        if low == "r":
            rows = sorted(scan_processes(), key=lambda r: r["rss"], reverse=True)
            show_table(rows, args.top)
            continue
        if low.startswith("f:"):
            kw = text[2:].strip().lower()
            filtered = [r for r in rows if kw in (r["name"] + " " + (r.get("software") or "")).lower() or kw in str(r["pid"])]
            if not filtered:
                print(col(YELLOW, f"没有匹配 '{text[2:]}' 的进程"))
            else:
                show_table(filtered, len(filtered))
                print(col(DIM, f"(已过滤: {text[2:]}，输入 r 恢复全部)"))
            continue

        targets = resolve_selection(text, rows)
        if not targets:
            print(col(YELLOW, "未匹配到任何进程，请检查输入"))
            continue

        killable, refused, soft = [], [], []
        for t in targets:
            lvl, reason = protection_of(t["pid"], t["name"])
            if lvl == 2:
                refused.append((t, reason))
            elif lvl == 1:
                soft.append((t, reason))
            else:
                killable.append(t)

        if refused:
            print(col(RED, "以下进程受硬保护，已拒绝结束:"))
            for t, reason in refused:
                print(col(RED, f"  - {t['name']} (PID {t['pid']}): {reason}"))
            print(col(RED, "(结束这些进程会导致系统崩溃、蓝屏、注销或功能失效)"))
        if soft:
            print(col(YELLOW, "以下进程受软保护，输入 FORCE-KILL 才会结束:"))
            for t, reason in soft:
                print(col(YELLOW, f"  - {t['name']} (PID {t['pid']}): {reason}"))
        if not killable and not soft:
            continue

        print(col(BOLD, f"\n将结束 {len(killable) + len(soft)} 个进程:"))
        for t in killable:
            print(f"  - {t['name']} (PID {t['pid']})  工作集 {fmt_mb(t['rss'])}MB")
        for t, reason in soft:
            print(col(YELLOW, f"  - {t['name']} (PID {t['pid']})  [软保护-{reason}]"))

        confirm = input(col(CYAN, "确认结束? [y/N] 软保护进程请输入 FORCE-KILL: ")).strip()
        force = confirm.upper() == "FORCE-KILL"
        proceed = force or confirm.lower() in ("y", "yes")
        if not proceed:
            print(col(DIM, "已取消"))
            continue

        to_kill = killable + (soft if force else [])
        if not to_kill:
            print(col(DIM, "没有可结束的进程"))
            continue

        freed, ok_count = 0, 0
        print("")
        for t in to_kill:
            ok, msg = kill_process(t["pid"], t["name"])
            tag = "[OK]  " if ok else "[失败]"
            print(f"  {tag} {t['name']} (PID {t['pid']}): {msg}")
            if ok:
                ok_count += 1
                freed += t["rss"]
        print(col(GREEN if ok_count else YELLOW,
                  f"\n本次成功结束 {ok_count}/{len(to_kill)} 个进程，约释放 {fmt_mb(freed)}MB 内存(工作集口径)"))
        if not force and soft:
            print(col(YELLOW, "提示: 软保护进程未结束，如需强制请重新选择并输入 FORCE-KILL"))


if __name__ == "__main__":
    main()
