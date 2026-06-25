#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
check_gmail_alias.py — 批量检测 Google 账号"自定义邮箱前缀"是否可用。

背景
----
Google 现在允许在 myaccount.google.com 修改账号邮箱地址的前缀。
当你在编辑框输入一个候选前缀时,页面会调用:

    POST https://myaccount.google.com/u/<N>/_/AccountSettingsUi/data/batchexecute?rpcids=chspYe ...

请求体:
    f.req=[[["chspYe","[\"<候选前缀>\"]",null,"generic"]]]&at=<XSRF token>&

响应(gzip 压缩,带 )]}' 前缀)内层 payload 形如:
    [status, [替代建议1, 替代建议2, 替代建议3], "<候选前缀>@gmail.com"]

判定规则(基于抓包样本):
    - status == 2 且 alternatives 非空  => 已被占用
    - alternatives 为空 / status != 2   => 大概率可用(见下方说明)

用法
----
1) 在浏览器里登录目标账号,打开 myaccount.google.com 的"修改邮箱地址"页面,
   用浏览器 DevTools(或抓包工具)抓到一条 rpcids=chspYe 的 POST 请求,
   右键 → Copy as cURL(bash)。
2) 把整条 curl 存进同目录的 template.txt,或者用 --curl 直接传字符串。
3) 把候选前缀写进 names.txt(每行一个),或用 --names a,b,c。
4) 运行:
       python check_gmail_alias.py --curl-file template.txt --names-file names.txt

输出会打印到控制台,并写入 results.csv。

注意
----
- 认证参数(cookie / at / rapt / f.sid)有时效,跑之前务必重新抓一条新鲜 curl。
- Google 风控严格,默认每次请求间隔 8 秒 + 随机抖动;不要把间隔调太小,
  也不要并发,否则极易触发风控或要求重新验证。
- 本脚本仅用于检测你自己账号想用的前缀是否被占用,请勿用于批量探测他人地址。
"""

import argparse
import base64
import csv
import gzip
import json
import os
import random
import re
import shlex
import sys
import time
import urllib.parse
from pathlib import Path

# Windows 终端默认 GBK,强制 stdout/stderr 用 UTF-8,避免中文乱码
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    import requests
except ImportError:
    sys.stderr.write("缺少 requests 库,请先安装:  pip install requests\n")
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # 没装 python-dotenv 时降级:仅读系统环境变量

# 固定端点(URL 里只有 _reqid 会变,在 bump_reqid 处理;其余写死即可)
ENDPOINT_URL = (
    "https://myaccount.google.com/u/{u}/_/AccountSettingsUi/data/batchexecute"
    "?rpcids=chspYe&source-path=%2Fu%2F{u}%2Fgoogle-account-email"
    "&f.sid={fsid}&bl={bl}&hl=zh-CN&rapt={rapt}"
    "&soc-app=1&soc-platform=1&soc-device=1&_reqid={{reqid}}&rt=c"
)
# 固定请求头(cookie 由 .env 注入;其余浏览器头写死)
BASE_HEADERS = {
    "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
    "x-same-domain": "1",
    "x-goog-ext-525002608-jspb": "[507]",
    "origin": "https://myaccount.google.com",
    "user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"),
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
}

# 从 cookie 里抽取的、有认证意义的字段(其余 cookie 可不带)
AUTH_COOKIE_KEYS = [
    "SID", "__Secure-1PSID", "__Secure-3PSID",
    "HSID", "SSID", "APISID", "SAPISID",
    "__Secure-1PAPISID", "__Secure-3PAPISID",
    "OSID", "__Secure-OSID",
    "__Secure-1PSIDTS", "__Secure-1PSIDRTS",
    "__Secure-3PSIDTS", "__Secure-3PSIDRTS",
    "SIDCC", "__Secure-1PSIDCC", "__Secure-3PSIDCC",
]


# ─────────────────────────── curl / 请求解析 ────────────────────────────

def parse_curl(curl_str: str):
    """从一条 curl 命令里解析出 method / url / headers / body。"""
    tokens = shlex.split(curl_str, posix=True)
    method = "GET"
    url = None
    headers = {}
    data = None

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("curl", "$curl", "curl.exe"):
            i += 1
            continue
        if t in ("-X", "--request"):
            method = tokens[i + 1]
            i += 2
            continue
        if t in ("-H", "--header"):
            h = tokens[i + 1]
            if ":" in h:
                k, v = h.split(":", 1)
                lk = k.strip().lower()
                v = v.strip()
                if lk == "cookie":
                    # curl 导出常把每个 cookie 拆成单独 -H,必须用 "; " 合并
                    cur = headers.get("cookie")
                    headers["cookie"] = (cur + "; " + v) if cur else v
                elif lk in headers:
                    headers[lk] = headers[lk] + ", " + v
                else:
                    headers[lk] = v
            i += 2
            continue
        if t in ("-b", "-c", "--cookie", "--cookie-jar"):
            # curl 的 -b 'k=v; ...' / --cookie 同样传 cookie(DevTools/部分工具用这种)
            cv = tokens[i + 1]
            cur = headers.get("cookie")
            headers["cookie"] = (cur + "; " + cv) if cur else cv
            i += 2
            continue
        if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            data = tokens[i + 1]
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if t in ("--compressed", "-k", "--insecure", "--location", "-L"):
            i += 1
            continue
        if t.startswith("http://") or t.startswith("https://"):
            if url is None:
                url = t
            i += 1
            continue
        i += 1

    if not url:
        raise ValueError("curl 里没有找到 URL")
    return method, url, headers, data


def extract_at(body: str) -> str:
    """从模板 body 的 at=... 里提取 XSRF token。"""
    if not body:
        raise ValueError("模板 curl 没有 -d body,无法提取 at= 参数")
    decoded = urllib.parse.unquote_plus(body)
    m = re.search(r"&at=([^&]+)", decoded) or re.search(r"\bat=([^&]+)", decoded)
    if not m:
        raise ValueError("body 里找不到 at= (XSRF token)")
    return m.group(1).strip()


# ─────────────────────────── cookie / .env 凭据 ────────────────────────────

def parse_cookie_string(cookie_str: str) -> dict:
    """把 'k1=v1; k2=v2; ...' 解析成 dict。"""
    out = {}
    for seg in re.split(r";\s*", cookie_str.strip()):
        if "=" in seg:
            k, v = seg.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def build_cookie_string(cookie_dict: dict) -> str:
    """dict 反向拼回 'k1=v1; k2=v2'。"""
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def extract_credentials_from_curl(curl_str: str):
    """
    从一条新鲜 curl 里提取全部凭据,返回 dict:
      {u, fsid, bl, rapt, at, cookie: {全部 cookie}}
    用于一键导出到 .env。
    """
    method, url, headers, body = parse_curl(curl_str)
    at = extract_at(body)
    cookies = parse_cookie_string(headers.get("cookie", ""))

    # 从 URL 里抠出 u / f.sid / bl / rapt
    m_u = re.search(r"/u/(\d+)/", url)
    u = m_u.group(1) if m_u else "0"
    fsid = (re.search(r"[?&]f\.sid=([^&]+)", url) or ["", ""])[1]
    bl = (re.search(r"[?&]bl=([^&]+)", url) or ["", ""])[1]
    rapt = (re.search(r"[?&]rapt=([^&]+)", url) or ["", ""])[1]
    return {"u": u, "fsid": fsid, "bl": bl, "rapt": rapt, "at": at, "cookie": cookies}


def render_env_block(account: str, cred: dict) -> str:
    """把一份凭据渲染成可粘贴进 .env 的文本(用整段 cookie,最稳)。"""
    lines = [f"# ── 账号 {account} ──"]
    lines.append(f"{account}_U={cred['u']}")
    lines.append(f"{account}_FSID={cred['fsid']}")
    lines.append(f"{account}_BL={cred['bl']}")
    lines.append(f"{account}_RAPT={cred['rapt']}")
    lines.append(f"{account}_AT={cred['at']}")
    lines.append(f"{account}_COOKIE={build_cookie_string(cred['cookie'])}")
    return "\n".join(lines)


def load_account(account: str) -> dict:
    """
    从 .env(优先)或环境变量读取指定账号的凭据,拼出 (url, headers, at)。
    必需字段:COOKIE、AT。URL 里的 u/fsid/bl/rapt 也从 .env 读,缺失用空串。
    """
    p = "env" if load_dotenv is None else "系统环境变量/.env"
    if load_dotenv is not None:
        load_dotenv()  # 读取同目录 .env
    A = account.upper()
    cookie = os.environ.get(f"{A}_COOKIE", "").strip()
    at = os.environ.get(f"{A}_AT", "").strip()
    if not cookie or not at:
        raise SystemExit(
            f"[!] .env / 环境变量里没找到账号 {account} 的凭据\n"
            f"    需要 {A}_COOKIE 和 {A}_AT。\n"
            f"    用法:先运行 `python check_gmail_alias.py --import-curl 账号名 -f curl文件`\n"
            f"    把抓到的 curl 转成 .env 片段粘进去。"
        )
    u = os.environ.get(f"{A}_U", "0").strip() or "0"
    fsid = os.environ.get(f"{A}_FSID", "").strip()
    bl = os.environ.get(f"{A}_BL", "").strip()
    rapt = os.environ.get(f"{A}_RAPT", "").strip()

    url_tmpl = ENDPOINT_URL.format(u=u, fsid=fsid, bl=bl, rapt=rapt)
    headers = dict(BASE_HEADERS)
    headers["cookie"] = cookie
    headers["referer"] = (f"https://myaccount.google.com/u/{u}/google-account-email"
                          + (f"?rapt={rapt}" if rapt else ""))
    return {"url": url_tmpl, "headers": headers, "at": at, "u": u, "source": p}


# ─────────────────────────── 请求构造 ────────────────────────────

def build_body(name: str, at: str) -> str:
    """构造 f.req + at 表单 body。"""
    inner_param = json.dumps([name], ensure_ascii=False)          # ["8888888"]
    freq_value = json.dumps(
        [[["chspYe", inner_param, None, "generic"]]],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return (
        "f.req=" + urllib.parse.quote(freq_value, safe="")
        + "&at=" + urllib.parse.quote(at, safe="")
        + "&"
    )


def bump_reqid(url: str, reqid: int) -> str:
    """把 URL 里的 _reqid= 改成给定值(batchexecute 里它是递增计数器)。"""
    if "_reqid=" in url:
        return re.sub(r"_reqid=\d+", f"_reqid={reqid}", url)
    return url + ("&" if "?" in url else "?") + f"_reqid={reqid}"


def strip_hop_headers(headers: dict) -> dict:
    """去掉 curl 自带但 requests 不该手动设置的头(content-length / Host 等)。"""
    drop = {"content-length", "host", "accept-encoding"}
    return {k: v for k, v in headers.items() if k.lower() not in drop}


# ─────────────────────────── 响应解析 ────────────────────────────

def decode_response(resp) -> str:
    """返回明文响应体。

    requests 会自动按 Content-Encoding (gzip/deflate/br) 解压;
    若服务器返回 zstd 需额外 `pip install zstandard`。
    batchexecute 正常响应一定带 )]}' 前缀。
    """
    return resp.text


def parse_batchexecute(text: str):
    """
    解析 Google batchexecute 响应,提取 chspYe 的 payload。

    返回 dict: {status, alternatives, email, raw_payload}
    解析失败时 raw_payload = None。
    """
    out = {"status": None, "alternatives": None, "email": None,
           "raw_payload": None, "found": False}
    s = text.lstrip()
    if s.startswith(")]}'"):
        s = s[4:].strip()

    # 扫描每个非空行,找包含 wrb.fr + chspYe 的 JSON 数组
    for line in s.splitlines():
        line = line.strip()
        if not line or not line.startswith("["):
            continue
        try:
            arr = json.loads(line)
        except json.JSONDecodeError:
            continue
        # arr 形如 [["wrb.fr","chspYe","<inner_json>",null,...], ["di",N], ...]
        for item in arr:
            if isinstance(item, list) and len(item) >= 3 \
                    and item[0] == "wrb.fr" and item[1] == "chspYe":
                out["found"] = True
                inner_json = item[2]
                # payload 显式为 null:无替代建议 → 通常即"可用"
                if inner_json is None:
                    return out
                if not isinstance(inner_json, str):
                    out["raw_payload"] = inner_json
                    return out
                try:
                    inner = json.loads(inner_json)
                except (json.JSONDecodeError, ValueError):
                    out["raw_payload"] = inner_json
                    return out
                # inner = [status, [alternatives], "email@gmail.com"]
                if isinstance(inner, list):
                    out["raw_payload"] = inner
                    if len(inner) >= 1:
                        out["status"] = inner[0]
                    if len(inner) >= 2:
                        alts = inner[1]
                        out["alternatives"] = alts if isinstance(alts, list) else None
                    if len(inner) >= 3:
                        out["email"] = inner[2]
                return out
    return out


def interpret(parsed: dict):
    """
    根据 payload 给出可用性判定。

    返回 (status_str, note):
        status_str ∈ {"AVAILABLE", "TAKEN", "UNKNOWN"}
    """
    alts = parsed.get("alternatives")
    status = parsed.get("status")
    found = parsed.get("found", False)

    # 根本没找到 chspYe 响应项 —— 多半是风控/重定向/需要重新登录
    if not found:
        return "UNKNOWN", "未找到 chspYe 响应(可能是风控或登录态失效,请检查 raw)"

    # ★ 判定唯一依据是 payload 第一位 status(经抓包实证):
    #   status == 1 → 真正可用(可注册)
    #   status == 0 → 系统不允许此用户名(被保留/受限/被冻结账号,非占用也非可用)
    #   status == 2 → 已被占用,并返回替代建议列表
    if status == 1:
        return "AVAILABLE", "status=1 → 可用"
    if status == 2:
        sug = ", ".join(alts) if isinstance(alts, list) and alts else "无"
        return "TAKEN", f"status=2 → 已被占用,建议:{sug}"
    if status == 0:
        return "UNAVAILABLE", "status=0 → 系统不允许使用此用户名(保留/受限)"
    return "UNKNOWN", f"未知 status={status},payload={parsed.get('raw_payload')}"


# ─────────────────────────── 前缀合法性预校验 ────────────────────────────

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.]{0,28}[a-z0-9])?$")


def validate_name(name: str):
    """
    Gmail 前缀基本规则:
      - 只允许 a-z 0-9 .
      - 6~30 字符
      - 不能以 . 开头/结尾,不能连续 ..
    返回 (ok, reason)。
    """
    n = name.lower()
    if not NAME_RE.match(n):
        return False, "含非法字符或首尾为点"
    if 6 > len(n) or len(n) > 30:
        return False, f"长度 {len(n)} 不在 6~30"
    if ".." in n:
        return False, "包含连续点"
    return True, ""


# ─────────────────────────── 主循环 ────────────────────────────

def check_one(session: requests.Session, url: str, headers: dict, at: str,
              name: str, reqid: int, timeout: float = 30):
    """发送一次可用性检查请求,返回 (resp, parsed, verdict, note, elapsed)。"""
    full_url = bump_reqid(url, reqid)
    body = build_body(name, at)
    t0 = time.time()
    resp = session.post(full_url, headers=headers, data=body, timeout=timeout)
    elapsed = time.time() - t0
    parsed = parse_batchexecute(decode_response(resp))
    verdict, note = interpret(parsed)
    return resp, parsed, verdict, note, elapsed


def main():
    ap = argparse.ArgumentParser(
        description="批量检测 Google 账号自定义邮箱前缀是否可用(凭据放 .env,用 --account 切换)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  # 1) 从一条新抓的 curl 导出账号凭据(打印 .env 片段,复制粘贴进 .env)
  python check_gmail_alias.py --import-curl work -f template_real.txt

  # 2) 用 .env 里的 work 账号跑候选(推荐,切换账号只改 --account)
  python check_gmail_alias.py --account work --names-file names.txt

  # 3) 旧方式仍然可用(直接吃整条 curl,不经 .env)
  python check_gmail_alias.py --curl-file template_real.txt --names-file names.txt
""",
    )
    ap.add_argument("--import-curl", metavar="ACCOUNT",
                    help="从 curl 文件/字符串提取凭据,打印可粘进 .env 的片段后退出")
    ap.add_argument("-f", "--curl-file", help="--import-curl 时的 curl 文件;或作为旧凭据源")
    ap.add_argument("--curl", help="直接传一条 curl 字串(--import-curl 或旧凭据源)")
    ap.add_argument("--account", help="从 .env 读哪个账号的凭据(如 work / personal)")
    names_src = ap.add_mutually_exclusive_group()
    names_src.add_argument("--names-file", default="names.txt", help="候选前缀文件,每行一个")
    names_src.add_argument("--names", help="逗号分隔的候选前缀,如 aaaa,bbbb")
    ap.add_argument("--delay", type=float, default=2.0, help="每次请求间隔秒数(默认 2)")
    ap.add_argument("--jitter", type=float, default=1.0, help="间隔随机抖动秒数(默认 1)")
    ap.add_argument("--start-reqid", type=int, default=1000000, help="_reqid 起始值")
    ap.add_argument("--out", default="results.csv", help="结果 CSV 输出路径")
    ap.add_argument("--proxy", help="可选,如 http://127.0.0.1:8080(走抓包代理便于观察)")
    ap.add_argument("--skip-validate", action="store_true", help="跳过本地前缀合法性预校验")
    ap.add_argument("--dry-run", action="store_true", help="只构造请求不发送,用于自检")
    args = ap.parse_args()

    # ---------- 模式 1:从 curl 导出 .env 片段 ----------
    if args.import_curl:
        if args.curl_file:
            curl_str = Path(args.curl_file).read_text(encoding="utf-8")
        elif args.curl:
            curl_str = args.curl
        else:
            sys.exit("[!] --import-curl 需配合 -f curl文件 或 --curl 字符串")
        cred = extract_credentials_from_curl(curl_str)
        n_ck = len(cred["cookie"])
        has_psidts = "__Secure-1PSIDTS" in cred["cookie"]
        print(f"[i] 账号名: {args.import_curl}")
        print(f"[i] u={cred['u']}  cookie 数={n_ck}  含 PSIDTS={has_psidts}  "
              f"at={cred['at'][:16]}...")
        if not has_psidts:
            print("[!] 警告:cookie 里没抓到 __Secure-1PSIDTS(认证核心),"
                  "重新在浏览器触发一次检查再抓。")
        print("\n# 把下面这段粘进 .env(覆盖同名账号即可):\n")
        print(render_env_block(args.import_curl.upper(), cred))
        return

    # ---------- 决定凭据来源:.env 账号(优先) or 旧 curl 方式 ----------
    if args.account:
        acct = load_account(args.account)
        url, headers, at = acct["url"], acct["headers"], acct["at"]
        print(f"[i] 凭据来源: .env 账号 {args.account}  (u={acct['u']}, {acct['source']})")
    elif args.curl_file or args.curl:
        curl_str = (Path(args.curl_file).read_text(encoding="utf-8")
                    if args.curl_file else args.curl)
        method, url, headers, body = parse_curl(curl_str)
        at = extract_at(body)
        headers = strip_hop_headers(headers)
        print("[i] 凭据来源: curl(旧方式,建议改用 --account + .env)")
    else:
        sys.exit("[!] 缺少凭据来源:请用 --account <名字>(读 .env)或 --curl-file/-f <curl文件>。")
    print(f"[i] 端点: {url.split('?')[0]}  | at={at[:16]}...")

    # ---------- 读取候选名单 ----------
    if args.names:
        names = [n.strip() for n in args.names.split(",") if n.strip()]
    else:
        p = Path(args.names_file)
        if not p.exists():
            sys.stderr.write(f"[!] 找不到候选文件 {p}\n")
            sys.exit(1)
        names = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
    print(f"[i] 候选前缀共 {len(names)} 个\n")

    # ---------- 本地预校验 ----------
    if not args.skip_validate:
        bad = [(n, validate_name(n)[1]) for n in names if not validate_name(n)[0]]
        for n, reason in bad:
            print(f"  [skip] {n!r:25} 非法:{reason}")
        names = [n for n in names if validate_name(n)[0]]
        if not names:
            print("[!] 过滤后没有合法候选,退出。")
            return

    if args.dry_run:
        print("\n[dry-run] 构造的第一个请求 body:")
        print(build_body(names[0], at))
        print("\n[dry-run] URL:", bump_reqid(url, args.start_reqid))
        return

    # ---------- 发请求 ----------
    session = requests.Session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
        session.verify = False  # 抓包代理自签证书

    rows = []
    reqid = args.start_reqid
    counters = {"AVAILABLE": 0, "TAKEN": 0, "UNKNOWN": 0}
    for idx, name in enumerate(names, 1):
        ok, reason = validate_name(name)
        try:
            resp, parsed, verdict, note, elapsed = check_one(
                session, url, headers, at, name, reqid)
            counters[verdict] = counters.get(verdict, 0) + 1
            status_code = resp.status_code
        except requests.RequestException as e:
            verdict, note, status_code, parsed, elapsed = "ERROR", str(e), 0, {}, 0.0
            counters["UNKNOWN"] += 1

        flag = {"AVAILABLE": "✓ 可用", "TAKEN": "✗ 占用",
                "UNAVAILABLE": "⊘ 不允许", "UNKNOWN": "? 未知",
                "ERROR": "!! 错误"}.get(verdict, "? " + verdict)
        print(f"[{idx}/{len(names)}] {name:20} HTTP {status_code}  {flag}  ({note})")

        rows.append({
            "name": name,
            "valid": "yes" if ok else "no:" + reason,
            "verdict": verdict,
            "status_code": status_code,
            "rpc_status": parsed.get("status") if isinstance(parsed, dict) else "",
            "alternatives": ",".join(parsed.get("alternatives") or []) if isinstance(parsed, dict) else "",
            "note": note,
            "elapsed_ms": round(elapsed * 1000),
        })

        # 写增量,防止中途被打断丢结果
        with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

        if idx < len(names):
            wait = args.delay + random.uniform(0, args.jitter)
            time.sleep(wait)
        reqid += 100000

    print("\n===== 汇总 =====")
    for k, v in counters.items():
        print(f"  {k:10}: {v}")
    print(f"详细结果已写入 {args.out}")


if __name__ == "__main__":
    main()
