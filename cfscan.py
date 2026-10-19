#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF 优选 IP 扫描工具（分地区）—— 纯 Python3，无需安装依赖
电脑 / 安卓 Termux / iPhone a-Shell 都能跑。在你自己的网络上跑，延迟和落地机房才准。

用法示例：
  python3 cfscan.py                        # 反代IP，香港/日本/新加坡/台湾/美国各10个
  python3 cfscan.py -r HK,JP -n 20         # 只要香港、日本，各20个
  python3 cfscan.py -m cf -r HK -n 10      # 官方CF段，筛出你线路落地香港的
  python3 cfscan.py -r US -n 50 -s 1500    # 多测点（-s 每个地区抽测数量）

结果：屏幕打印 + 保存 result.csv / ip.txt / vless.txt（vless.txt 可全选复制导入）
"""
import argparse, base64, csv, os, random, re, socket, ssl, sys, time, ipaddress, urllib.request
import concurrent.futures as cf
from urllib.parse import quote

# ====== 你的节点（改这里，把 YOUR-UUID-HERE 换成你自己的 UUID）======
UUID = "YOUR-UUID-HERE"
HOST = "huangguan.de5.net"
PATH = "/"
EXCLUDE = {"104.16.0.89"}
# =============================

PROXY_LIST = "https://zip.cm.edu.kg/all.txt"   # 反代IP合集，格式 ip:port#国家
CF_RANGES = ["104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.159.0.0/16",
             "108.162.192.0/18", "188.114.96.0/20", "141.101.64.0/18", "190.93.240.0/20"]
COLO = {  # 地区代码 -> 允许的CF机房
    "HK": {"HKG"}, "TW": {"TPE", "KHH"}, "JP": {"NRT", "KIX", "FUK", "OKA"},
    "SG": {"SIN"}, "KR": {"ICN"},
    "US": {"LAX", "SJC", "SFO", "SEA", "PDX", "LAS", "PHX", "DEN", "DFW", "IAH", "MCI", "ORD",
           "STL", "ATL", "MIA", "IAD", "EWR", "BOS", "PIT", "MSP", "SLC", "SAN", "CLT", "JAX"},
}
CN = {"HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "KR": "韩国", "US": "美国"}
CTX = ssl.create_default_context()


def tls(ip, port, t=3):
    s = socket.create_connection((ip, port), t)
    ss = CTX.wrap_socket(s, server_hostname=HOST)
    ss.settimeout(4)
    return ss


def test(item):
    ip, port, cc = item
    try:
        st = time.time()
        ss = tls(ip, port)
        key = base64.b64encode(os.urandom(16)).decode()
        ss.sendall((f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        r = ss.recv(64).decode(errors="ignore")
        ms = round((time.time() - st) * 1000)
        ss.close()
        if " 101 " not in r:
            return None
        ss = tls(ip, port)
        ss.sendall(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
        b = b""
        while len(b) < 4000:
            d = ss.recv(2048)
            if not d:
                break
            b += d
        m = re.search(rb"colo=([A-Z]+)", b)
        return (ip, port, cc, m.group(1).decode() if m else "", ms)
    except Exception:
        return None


def candidates_proxy(regions, sample):
    print(f"下载反代IP列表 {PROXY_LIST} ...")
    txt = urllib.request.urlopen(urllib.request.Request(PROXY_LIST, headers={"User-Agent": "Mozilla/5.0"}),
                                 timeout=30).read().decode(errors="ignore")
    pool = {r: [] for r in regions}
    for line in txt.splitlines():
        m = re.match(r"([\d.]+):(\d+)#([A-Z]{2})", line.strip())
        if m and m.group(3) in pool:
            pool[m.group(3)].append((m.group(1), int(m.group(2)), m.group(3)))
    out = []
    for r, v in pool.items():
        random.shuffle(v)
        out += v[:sample]
        print(f"  {CN.get(r, r)}: 候选 {len(v)}，抽测 {min(len(v), sample)}")
    return out


def candidates_cf(regions, sample):
    n = sample * max(1, len(regions))
    out = set()
    while len(out) < n:
        net = ipaddress.ip_network(random.choice(CF_RANGES))
        out.add((str(net[random.randrange(1, net.num_addresses - 1)]), 443, "CF"))
    print(f"官方CF段随机抽测 {n} 个，按你线路的落地机房分地区")
    return list(out)


def main():
    ap = argparse.ArgumentParser(description="CF 优选IP 分地区扫描")
    ap.add_argument("-r", "--regions", default="HK,JP,SG,TW,US", help="地区: HK,TW,JP,SG,KR,US")
    ap.add_argument("-n", "--num", type=int, default=10, help="每个地区要几个")
    ap.add_argument("-s", "--sample", type=int, default=600, help="每个地区抽测数量")
    ap.add_argument("-m", "--mode", default="proxy", choices=["proxy", "cf"], help="proxy=反代IP  cf=官方段")
    ap.add_argument("-t", "--threads", type=int, default=100)
    a = ap.parse_args()
    regions = [x.strip().upper() for x in a.regions.split(",") if x.strip()]

    cands = candidates_proxy(regions, a.sample) if a.mode == "proxy" else candidates_cf(regions, a.sample)
    cands = [c for c in cands if c[0] not in EXCLUDE]
    print(f"开始测试 {len(cands)} 个 ...")
    ok, done = [], 0
    with cf.ThreadPoolExecutor(a.threads) as ex:
        for r in ex.map(test, cands):
            done += 1
            if r:
                ok.append(r)
            if done % 200 == 0:
                print(f"  进度 {done}/{len(cands)}，可用 {len(ok)}")

    res, seen = [], set()
    for reg in regions:
        hit = sorted([x for x in ok if x[3] in COLO.get(reg, set()) and (a.mode == "cf" or x[2] == reg)],
                     key=lambda x: x[4])
        k = 0
        for ip, port, _, colo, ms in hit:
            if ip in seen:
                continue
            seen.add(ip); k += 1
            res.append((ip, port, reg, colo, ms, k))
            if k >= a.num:
                break
        print(f"{CN.get(reg, reg)}: 找到 {k} 个")

    links, lines = [], []
    for ip, port, reg, colo, ms, k in res:
        name = quote(f"{CN.get(reg, reg)}{k:02d}-{colo}-{ms}ms")
        links.append(f"vless://{UUID}@{ip}:{port}?encryption=none&security=tls&sni={HOST}&fp=chrome"
                     f"&type=ws&host={HOST}&path={quote(PATH, safe='')}#{name}")
        lines.append(f"{ip}:{port}  {CN.get(reg, reg)}  {colo}  {ms}ms")
    print("\n".join(lines))
    with open("result.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["IP:端口", "地区", "机房", "延迟ms"])
        for ip, port, reg, colo, ms, _ in res:
            w.writerow([f"{ip}:{port}", CN.get(reg, reg), colo, ms])
    open("ip.txt", "w", encoding="utf-8").write("\n".join(lines) + "\n")
    open("vless.txt", "w", encoding="utf-8").write("\n".join(links) + "\n")
    print(f"\n共 {len(res)} 个，已保存 result.csv / ip.txt / vless.txt")


if __name__ == "__main__":
    main()
