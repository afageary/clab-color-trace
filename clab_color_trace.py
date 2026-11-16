#!/usr/bin/env python3
"""
clab-color-trace — color-tag pings from a Linux container in a containerlab
topology, discover which links they actually traverse, and paint that path
(in the flow's color) onto the topology graph.

How it works
  1. Reads the lab's topology-data.json (written by `containerlab deploy`).
  2. Starts a tcpdump on every data-plane interface of every node, inside the
     node's network namespace (nsenter), capturing egress only (-Q out).
     tcpdump runs from the *host*, so the router images need no tooling.
  3. Runs `ping -p <16-byte marker>` from the source container. The marker
     encodes the color and a per-run nonce. Because it sits in the ICMP
     payload it survives any encapsulation the routers add (SRv6 H.Encaps,
     SR-MPLS, VXLAN, GRE...), so it is found on core links too.
  4. Scans every capture for the marker. A hit on node A's egress interface
     means the A->Z link carried that color. The ICMP type next to the marker
     tells echo-request (forward path) from echo-reply (return path).
  5. Writes an HTML page (SVG graph, links painted per color, request solid,
     reply dashed, toggle per flow), plus JSON and Mermaid.

Requirements on the lab host: root, docker, nsenter (util-linux), tcpdump.
Source containers need iputils ping (e.g. nicolaka/netshoot,
wbitt/network-multitool); busybox ping only accepts a 1-byte pattern.

Python 3.8+, standard library only.
"""
import argparse
import glob
import html
import json
import math
import os
import random
import re
import secrets
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "0.1.0"

NAMED_COLORS = {
    "red": "#e5484d", "blue": "#3e63dd", "green": "#30a46c",
    "orange": "#f76b15", "purple": "#8e4ec6", "teal": "#12a594",
    "pink": "#d6409f", "yellow": "#ffe100", "cyan": "#00a2c7",
    "brown": "#a07553", "gold": "#b8860b", "magenta": "#c026d3", "lightblue": "#4fc3f7", "light-blue": "#4fc3f7",
}

# Kinds that have no network namespace of their own to capture in.
NO_NETNS_KINDS = {"bridge", "ovs-bridge", "host", "mgmt-net", "macvlan"}

MARKER_MAGIC = b"\xc0\x10"          # "COLO(r)" — first 2 bytes of every marker
ICMP_REQ = {8: "request", 128: "request"}   # IPv4 / IPv6 echo request
ICMP_REP = {0: "reply", 129: "reply"}       # IPv4 / IPv6 echo reply


def log(msg):
    print(f"[clab-color-trace] {msg}", file=sys.stderr, flush=True)


def die(msg, code=1):
    log(f"error: {msg}")
    sys.exit(code)


# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------

def find_topology_data(args):
    if args.lab_dir:
        p = Path(args.lab_dir) / "topology-data.json"
        if not p.is_file():
            die(f"{p} not found — is the lab deployed?")
        return p
    if args.topo:
        topo = Path(args.topo)
        m = re.search(r"^name:\s*['\"]?([\w.-]+)", topo.read_text(), re.M)
        if not m:
            die(f"could not read 'name:' from {topo}")
        name = m.group(1)
        # Default lab dir is clab-<name> next to the topology file.
        for cand in (topo.parent / f"clab-{name}", Path.cwd() / f"clab-{name}"):
            if (cand / "topology-data.json").is_file():
                return cand / "topology-data.json"
        die(f"clab-{name}/topology-data.json not found; pass --lab-dir")
    found = glob.glob("clab-*/topology-data.json")
    if len(found) == 1:
        return Path(found[0])
    if not found:
        die("no clab-*/topology-data.json in this directory; pass -t or --lab-dir")
    die("several labs here (" + ", ".join(found) + "); pass -t or --lab-dir")


def load_topology(path):
    d = json.loads(Path(path).read_text())
    lab = d.get("name", "lab")
    prefix = (((d.get("clab") or {}).get("config") or {}).get("prefix")) or "clab"
    nodes = {}
    for short, n in (d.get("nodes") or {}).items():
        longname = n.get("longname") or (f"{prefix}-{lab}-{short}" if prefix else short)
        nodes[short] = {
            "name": short,
            "longname": longname,
            "kind": n.get("kind", ""),
            "labels": n.get("labels") or {},
        }
    links = []
    for l in d.get("links") or []:
        ep = l.get("endpoints", l)
        a, z = ep.get("a"), ep.get("z")
        if not a or not z:
            continue
        for e in (a, z):   # endpoints like host / macvlan are not in "nodes"
            if e["node"] not in nodes:
                nodes[e["node"]] = {"name": e["node"], "longname": None,
                                    "kind": "host" if e["node"] == "host" else "external",
                                    "labels": {}}
        links.append({"a": {"node": a["node"], "ifname": a["interface"]},
                      "z": {"node": z["node"], "ifname": z["interface"]}})
    return {"name": lab, "nodes": nodes, "links": links}


def ifname_candidates(kind, ifname):
    """Linux interface names a topology interface name may map to.

    Topology files can use interface aliases (ethernet-1/1, 1/1/c1/1);
    inside the container namespace the veth carries the Linux name.
    """
    c = [ifname]
    if "/" in ifname:
        m = re.fullmatch(r"ethernet-(\d+)/(\d+)(?:/(\d+))?", ifname)   # SR Linux
        if m:
            c.append("e" + "-".join(g for g in m.groups() if g))
        dashed = ifname.replace("/", "-")
        c.append(dashed)
        if dashed[:1].isdigit():          # SR OS style 1/1/c1/1
            c.append("e" + dashed)
    return list(dict.fromkeys(c))


# --------------------------------------------------------------------------
# Live capture (needs root + docker on the lab host)
# --------------------------------------------------------------------------

def run(cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip() or r.stdout.strip()}")
    return r


def container_pid(runtime, longname):
    r = run([runtime, "inspect", "-f", "{{.State.Pid}}", longname], check=False)
    pid = r.stdout.strip()
    if r.returncode != 0 or not pid.isdigit() or pid == "0":
        return None
    return pid


def netns_ifnames(pid):
    r = run(["nsenter", "-t", pid, "-n", "ip", "-o", "link", "show"], check=False)
    names = set()
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) > 1:
            names.add(parts[1].strip().split("@")[0])
    return names


def preflight(args):
    if os.geteuid() != 0:
        die("must run as root (tcpdump inside node namespaces) — use sudo")
    for tool in (args.runtime, "nsenter", "tcpdump", "ip"):
        if not shutil.which(tool):
            die(f"'{tool}' not found on this host")


def check_ping(runtime, longname):
    r = run([runtime, "exec", longname, "ping", "-V"], check=False)
    out = (r.stdout + r.stderr).lower()
    if "iputils" not in out:
        die(f"{longname}: ping is not iputils (need -p with a 16-byte pattern). "
            "Use an image such as nicolaka/netshoot or install iputils-ping.")


def wait_listening(proc, timeout=5.0):
    """Wait until tcpdump prints 'listening on' (capture is attached)."""
    end = time.time() + timeout
    buf = ""
    while time.time() < end:
        r, _, _ = select.select([proc.stderr], [], [], 0.2)
        if r:
            chunk = os.read(proc.stderr.fileno(), 4096).decode(errors="replace")
            if not chunk:
                break
            buf += chunk
            if "listening on" in buf:
                return True, buf
        if proc.poll() is not None:
            break
    return False, buf


def node_containers(runtime, lab, node, longname):
    """All containers that make up a lab node.

    Most nodes are one container named <prefix>-<lab>-<node>. Distributed
    SR-SIM chassis (sr-7s, sr-2se, sr-1se, sr-1x-48d, ... with `components:`)
    run one container per card (e.g. ...-R1-a, ...-R1-1), and the data ports
    live in the line-card containers, so every one of them is a candidate.
    Returns [(container_name, pid, set_of_ifnames)].
    """
    names = []
    if container_pid(runtime, longname):
        names.append(longname)
    r = run([runtime, "ps", "--format", "{{.Names}}",
             "--filter", f"label=containerlab={lab}"], check=False)
    for n in r.stdout.split():
        if n != longname and n.startswith(longname + "-") and n not in names:
            names.append(n)
    r = run([runtime, "ps", "--format", "{{.Names}}",
             "--filter", f"label=containerlab={lab}", "--filter", f"label=clab-node-name={node}"], check=False)
    for n in r.stdout.split():
        if n not in names:
            names.append(n)
    out = []
    for n in names:
        pid = container_pid(runtime, n)
        if pid:
            out.append((n, pid, netns_ifnames(pid)))
    return out


def start_captures(topo, args, outdir, stream=False):
    """Start tcpdumps on every link endpoint, one per direction.

    Both directions are needed: SR-SIM transmits in a way tcpdump cannot see
    on the sending interface (no egress copy), but the receiving side sees
    the packet. A traversal A->Z is therefore recorded when the marker is
    seen leaving A *or* arriving at Z.
    """
    iface_map = {}
    for item in args.iface_map or []:
        try:
            node, rest = item.split(":", 1)
            alias, real = rest.split("=", 1)
            iface_map[(node, alias)] = real
        except ValueError:
            die(f"bad --iface-map '{item}', expected node:alias=linuxname")

    members, caps, skipped = {}, [], []
    for li, link in enumerate(topo["links"]):
        for side in ("a", "z"):
            ep = link[side]
            node = topo["nodes"][ep["node"]]
            if node["kind"] in NO_NETNS_KINDS or not node["longname"]:
                continue
            if ep["node"] not in members:
                members[ep["node"]] = node_containers(args.runtime, topo["name"], ep["node"], node["longname"])
                if not members[ep["node"]]:
                    log(f"skip {ep['node']}: no running container for it ({node['longname']}*)")
                elif len(members[ep["node"]]) > 1:
                    log(f"{ep['node']}: {len(members[ep['node']])} containers "
                        f"({', '.join(m[0] for m in members[ep['node']])})")
            if not members[ep["node"]]:
                continue
            cands = [iface_map[(ep["node"], ep["ifname"])]] if (ep["node"], ep["ifname"]) in iface_map \
                else ifname_candidates(node["kind"], ep["ifname"])
            hit = None
            for cname, pid, present in members[ep["node"]]:
                linux_if = next((c for c in cands if c in present), None)
                if linux_if:
                    hit = (cname, pid, linux_if)
                    break
            if not hit:
                skipped.append(f"{ep['node']}:{ep['ifname']}")
                continue
            cname, pid, linux_if = hit
            for direction in ("out", "in"):
                fname = f"{li:03d}-{side}-{ep['node']}-{linux_if}-{direction}.pcap".replace("/", "_")
                cmd = ["nsenter", "-t", pid, "-n", "--",
                       "tcpdump", "-i", linux_if, "-Q", direction, "-U", "-nn",
                       "-s", str(args.snaplen)] + (["-B", "256"] if stream else []) + \
                      ["-w", "-" if stream else str(outdir / fname)]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE if stream else subprocess.DEVNULL,
                                        stderr=subprocess.PIPE)
                caps.append({"link": li, "side": side, "node": ep["node"], "container": cname,
                             "ifname": ep["ifname"], "linux_if": linux_if, "dir": direction,
                             "pcap": fname, "proc": proc})
    if skipped:
        log("interfaces not found in any container of their node (use --iface-map node:if=linuxname):\n  "
            + "\n  ".join(skipped))
    if not caps:
        die("no interfaces to capture on")
    bad = []
    for c in caps:
        ok, err = wait_listening(c["proc"])
        if not ok:
            bad.append(f"{c['node']}:{c['linux_if']} ({c['dir']}): {err.strip()[-200:]}")
    if bad:
        log("some captures failed to start:\n  " + "\n  ".join(bad))
    ifs = len({(c['node'], c['linux_if']) for c in caps})
    log(f"capturing on {ifs} interfaces (both directions)")
    return caps


def stop_captures(caps):
    for c in caps:
        if c["proc"].poll() is None:
            c["proc"].send_signal(signal.SIGINT)   # SIGINT flushes the pcap
    for c in caps:
        try:
            c["proc"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            c["proc"].kill()


def run_pings(topo, flows, args):
    for f in flows:
        node = topo["nodes"].get(f["src"])
        if not node or not node["longname"]:
            die(f"source node '{f['src']}' not in topology")
        check_ping(args.runtime, node["longname"])
    for f in flows:
        node = topo["nodes"][f["src"]]
        cmd = [args.runtime, "exec", node["longname"], "ping",
               "-c", str(args.count), "-i", str(args.interval),
               "-s", "56", "-p", f["marker"], "-W", "1"]
        if f.get("src_addr"):
            cmd += ["-I", f["src_addr"]]
        cmd.append(f["dst"])
        log(f"[{f['color']}] {f['src']} -> {f['dst']}: {' '.join(cmd[2:])}")
        r = run(cmd, check=False)
        summary = [l for l in r.stdout.splitlines() if "packets transmitted" in l]
        f["ping_summary"] = summary[0].strip() if summary else (r.stderr.strip() or "no output")
        log(f"[{f['color']}] {f['ping_summary']}")


# --------------------------------------------------------------------------
# pcap analysis (works on any encapsulation: marker is in the ICMP payload)
# --------------------------------------------------------------------------

def read_pcap(path):
    """Yield (timestamp, bytes) from a classic libpcap file."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError(f"{path}: not a pcap file (pcapng is not supported)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        div = 1e9 if nano else 1e6
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            sec, frac, caplen, _ = struct.unpack(endian + "IIII", rh)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield sec + frac / div, data


def classify(data, pos):
    """ICMP type sits 24 bytes before the first full marker
    (8-byte ICMP header + 16-byte timestamp that iputils writes)."""
    for off in (24, 8):
        if pos >= off:
            t = data[pos - off]
            if t in ICMP_REQ:
                return ICMP_REQ[t]
            if t in ICMP_REP:
                return ICMP_REP[t]
    return "unknown"


def analyse(caps, flows, pcap_dir):
    markers = {bytes.fromhex(f["marker"]): i for i, f in enumerate(flows)}
    hits = []   # per capture: {flow_idx: {request:n, reply:n, unknown:n, t_req:.., t_rep:..}}
    for c in caps:
        res = {}
        p = Path(pcap_dir) / c["pcap"]
        if p.is_file():
            for ts, data in read_pcap(p):
                start = 0
                while True:
                    pos = data.find(MARKER_MAGIC, start)
                    if pos < 0:
                        break
                    mk = data[pos:pos + 16]
                    if mk in markers:
                        fi = markers[mk]
                        kind = classify(data, pos)
                        r = res.setdefault(fi, {"request": 0, "reply": 0, "unknown": 0})
                        r[kind] += 1
                        tk = "t_" + kind
                        r[tk] = min(r.get(tk, ts), ts)
                        break
                    start = pos + 1
        hits.append(res)
    return hits


def build_result(topo, flows, caps, hits):
    """Turn per-capture hits into per-flow traversals (directed link uses).

    Seen leaving endpoint X (dir out) or arriving at the other end (dir in)
    both mean the packet went X -> other end; the two views are merged.
    """
    out_flows = []
    for fi, f in enumerate(flows):
        merged = {}
        for c, res in zip(caps, hits):
            if fi not in res:
                continue
            link = topo["links"][c["link"]]
            here, there = c["side"], ("z" if c["side"] == "a" else "a")
            if c.get("dir", "out") == "in":
                here, there = there, here          # arrived here, so it came from the other end
            frm, to = link[here], link[there]
            r = res[fi]
            for kind in ("request", "reply", "unknown"):
                if not r[kind]:
                    continue
                key = (c["link"], kind, frm["node"])
                cur = merged.get(key)
                ts = r.get("t_" + kind)
                if cur is None:
                    merged[key] = {"link": c["link"], "kind": kind,
                                   "from": frm["node"], "from_if": frm["ifname"],
                                   "to": to["node"], "to_if": to["ifname"],
                                   "packets": r[kind], "first_seen": ts}
                else:
                    cur["packets"] = max(cur["packets"], r[kind])
                    if ts is not None and (cur["first_seen"] is None or ts < cur["first_seen"]):
                        cur["first_seen"] = ts
        trav = sorted(merged.values(), key=lambda x: (x["first_seen"] or 0))
        out_flows.append({
            "src": f["src"], "dst": f["dst"], "color": f["color"],
            "hex": f["hex"], "marker": f["marker"],
            "ping_summary": f.get("ping_summary", ""),
            "traversals": trav,
            "request_path": hop_path(trav, "request", f["src"]),
            "reply_path": hop_path(trav, "reply", None),
        })
    return out_flows


def hop_path(trav, kind, src):
    """Chain the directed link uses of one kind into a hop list:
    start at the source (or a node with no incoming hop) and follow the
    earliest-seen outgoing hop each time."""
    t = [x for x in trav if x["kind"] == kind]
    if not t:
        return []
    outgoing = {}
    for x in sorted(t, key=lambda x: x["first_seen"] or 0):
        outgoing.setdefault(x["from"], []).append(x)
    incoming = {x["to"] for x in t}
    start = src if src in outgoing else next((n for n in outgoing if n not in incoming),
                                             min(t, key=lambda x: x["first_seen"] or 0)["from"])
    path, used, cur = [start], set(), start
    while True:
        nxt = next((x for x in outgoing.get(cur, []) if id(x) not in used), None)
        if not nxt:
            break
        used.add(id(nxt))
        cur = nxt["to"]
        path.append(cur)
        if len(used) == len(t):
            break
    return path


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def layout(topo, width, height, margin=70):
    names = list(topo["nodes"])
    labels = {n: topo["nodes"][n]["labels"] for n in names}
    pos = {}
    if names and all("graph-posX" in labels[n] and "graph-posY" in labels[n] for n in names):
        for n in names:   # positions saved by `containerlab graph` / TopoViewer
            pos[n] = [float(labels[n]["graph-posX"]), float(labels[n]["graph-posY"])]
    else:
        pos = force_layout(names, topo["links"])
    xs = [p[0] for p in pos.values()] or [0]
    ys = [p[1] for p in pos.values()] or [0]
    spanx, spany = (max(xs) - min(xs)) or 1, (max(ys) - min(ys)) or 1
    s = min((width - 2 * margin) / spanx, (height - 2 * margin) / spany)
    ox = (width - spanx * s) / 2
    oy = (height - spany * s) / 2
    return {n: (ox + (p[0] - min(xs)) * s, oy + (p[1] - min(ys)) * s) for n, p in pos.items()}


def force_layout(names, links, iters=400):
    rnd = random.Random(42)
    n = len(names)
    pos = {nm: [math.cos(2 * math.pi * i / max(n, 1)) + rnd.uniform(-.05, .05),
                math.sin(2 * math.pi * i / max(n, 1)) + rnd.uniform(-.05, .05)]
           for i, nm in enumerate(names)}
    edges = {(l["a"]["node"], l["z"]["node"]) for l in links if l["a"]["node"] != l["z"]["node"]}
    k = 1.0 / math.sqrt(max(n, 1))
    temp = 0.1
    for _ in range(iters):
        disp = {nm: [0.0, 0.0] for nm in names}
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = math.hypot(dx, dy) or 1e-3
                f = k * k / d
                disp[a][0] += dx / d * f; disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f; disp[b][1] -= dy / d * f
        for a, b in edges:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = math.hypot(dx, dy) or 1e-3
            f = d * d / k
            disp[a][0] -= dx / d * f; disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f; disp[b][1] += dy / d * f
        for nm in names:
            dx, dy = disp[nm]
            d = math.hypot(dx, dy) or 1e-3
            pos[nm][0] += dx / d * min(d, temp)
            pos[nm][1] += dy / d * min(d, temp)
        temp *= 0.99
    return pos


def kind_style(kind):
    k = (kind or "").lower()
    if "srl" in k or "srlinux" in k:
        return "SR Linux", "#124191"
    if "sros" in k or "srsim" in k or "vr-sros" in k:
        return "SR OS", "#005aff"
    if k in ("linux", "ext-container"):
        return "Linux", "#5b6170"
    return kind or "node", "#5b6170"


def render_svg(topo, flows, width=1100, height=680):
    pos = layout(topo, width, height)
    R = 26
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
           f'width="100%" role="img" aria-label="Topology with colored ping paths">']
    out.append("<defs>")
    for i, f in enumerate(flows):
        out.append(f'<marker id="arr{i}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" '
                   f'markerHeight="5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
                   f'fill="{f["hex"]}"/></marker>')
    out.append("</defs>")

    # Count parallel links between the same node pair so they don't overlap.
    pair_idx, pair_tot = {}, {}
    for li, l in enumerate(topo["links"]):
        key = tuple(sorted((l["a"]["node"], l["z"]["node"])))
        pair_idx[li] = pair_tot.get(key, 0)
        pair_tot[key] = pair_tot.get(key, 0) + 1

    def geom(li):
        l = topo["links"][li]
        a, z = l["a"]["node"], l["z"]["node"]
        (x1, y1), (x2, y2) = pos[a], pos[z]
        key = tuple(sorted((a, z)))
        sign = 1 if (a, z) == key else -1   # keep offsets on a stable side
        dx, dy = x2 - x1, y2 - y1
        d = math.hypot(dx, dy) or 1
        ux, uy = dx / d, dy / d
        nx, ny = -uy * sign, ux * sign
        base = (pair_idx[li] - (pair_tot[key] - 1) / 2) * 26
        return x1, y1, x2, y2, ux, uy, nx, ny, base, d

    # Base links
    out.append('<g class="base">')
    for li, l in enumerate(topo["links"]):
        x1, y1, x2, y2, ux, uy, nx, ny, base, d = geom(li)
        bx, by = nx * base, ny * base
        out.append(f'<line x1="{x1+bx:.1f}" y1="{y1+by:.1f}" x2="{x2+bx:.1f}" y2="{y2+by:.1f}" '
                   f'stroke="#c9ccd3" stroke-width="2"><title>{html.escape(l["a"]["node"])}:'
                   f'{html.escape(l["a"]["ifname"])} — {html.escape(l["z"]["node"])}:'
                   f'{html.escape(l["z"]["ifname"])}</title></line>')
        for side, frac in (("a", 0.2), ("z", 0.8)):
            tx = x1 + bx + (x2 - x1) * frac + nx * 11
            ty = y1 + by + (y2 - y1) * frac + ny * 11
            out.append(f'<text x="{tx:.1f}" y="{ty:.1f}" class="ifl">{html.escape(l[side]["ifname"])}</text>')
    out.append("</g>")

    # Colored overlays: one lane per (flow, kind) on each link.
    lanes = {}
    for fi, f in enumerate(flows):
        for t in f["traversals"]:
            lanes.setdefault(t["link"], []).append((fi, t))

    # arrowhead only on the last hop of each direction (into the destination
    # for requests, back into the source for replies)
    last_hop = set()
    for fi, f in enumerate(flows):
        for kind in ("request", "reply"):
            hops = f.get(kind + "_path") or []
            if len(hops) >= 2:
                last_hop.add((fi, kind, hops[-2], hops[-1]))
    for fi, f in enumerate(flows):
        out.append(f'<g class="flow" data-flow="{fi}">')
        for li, items in lanes.items():
            x1, y1, x2, y2, ux, uy, nx, ny, base, d = geom(li)
            link = topo["links"][li]
            m = len(items)
            for j, (fj, t) in enumerate(items):
                if fj != fi:
                    continue
                off = base + (j - (m - 1) / 2) * 6
                fwd = t["from"] == link["a"]["node"]
                sx, sy, ex, ey = (x1, y1, x2, y2) if fwd else (x2, y2, x1, y1)
                dux, duy = (ux, uy) if fwd else (-ux, -uy)
                sx += dux * (R + 4) + nx * off; sy += duy * (R + 4) + ny * off
                ex -= dux * (R + 6) - nx * off; ey -= duy * (R + 6) - ny * off
                dash = ' stroke-dasharray="7 5"' if t["kind"] == "reply" else (
                    ' stroke-dasharray="2 4"' if t["kind"] == "unknown" else "")
                tip = (f'{f["color"]} {t["kind"]}: {t["from"]}:{t["from_if"]} → '
                       f'{t["to"]}:{t["to_if"]} ({t["packets"]} pkts)')
                out.append(f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" '
                           f'stroke="{f["hex"]}" stroke-width="4" stroke-linecap="round"{dash} '
                           f'marker-end="url(#arr{fi})"><title>{html.escape(tip)}</title></line>')
        out.append("</g>")

    # Nodes
    on_path = {}
    for fi, f in enumerate(flows):
        for t in f["traversals"]:
            on_path.setdefault(t["from"], set()).add(fi)
            on_path.setdefault(t["to"], set()).add(fi)
    for name, (x, y) in pos.items():
        node = topo["nodes"][name]
        label, fill = kind_style(node["kind"])
        ring = ""
        for k, fi in enumerate(sorted(on_path.get(name, ()))):
            ring += (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{R + 4 + 4*k}" fill="none" '
                     f'stroke="{flows[fi]["hex"]}" stroke-width="2.5" class="ring" data-flow="{fi}"/>')
        out.append(f'<g class="node">{ring}<circle cx="{x:.1f}" cy="{y:.1f}" r="{R}" fill="{fill}"/>'
                   f'<text x="{x:.1f}" y="{y+4:.1f}" class="nk">{html.escape(label)}</text>'
                   f'<text x="{x:.1f}" y="{y+R+18:.1f}" class="nn">{html.escape(name)}</text>'
                   f'<title>{html.escape(name)} ({html.escape(node["kind"])})</title></g>')
    out.append("</svg>")
    return "\n".join(out)


def render_html(topo, flows, meta):
    svg = render_svg(topo, flows)
    rows = []
    for i, f in enumerate(flows):
        req = " → ".join(f["request_path"]) or "<em>not seen</em>"
        rep = " → ".join(f["reply_path"]) or "<em>not seen</em>"
        sym = ""
        if f["request_path"] and f["reply_path"] and list(reversed(f["reply_path"])) != f["request_path"]:
            sym = '<span class="tag">asymmetric</span>'
        rows.append(
            f'<label class="flowrow"><input type="checkbox" checked data-flow="{i}">'
            f'<span class="sw" style="background:{f["hex"]}"></span>'
            f'<span><b>{html.escape(f["color"])}</b> · {html.escape(f["src"])} → {html.escape(f["dst"])} {sym}'
            f'<br><span class="p">request: {html.escape(req) if f["request_path"] else req}</span>'
            f'<br><span class="p">reply: {html.escape(rep) if f["reply_path"] else rep}</span>'
            f'<br><span class="s">{html.escape(f["ping_summary"])}</span></span></label>')
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(topo['name'])} — color trace</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{ color-scheme: light dark; --bg:#f7f7f8; --fg:#1d2027; --mut:#6b7080; --card:#fff; --bd:#e3e5ea; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#15171c; --fg:#e8eaef; --mut:#9aa0ad; --card:#1d2027; --bd:#2c3039; }} }}
body {{ margin:0; font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif; background:var(--bg); color:var(--fg); }}
header {{ padding:16px 24px 4px; }} h1 {{ font-size:18px; margin:0; }}
.meta {{ color:var(--mut); font-size:12px; }}
main {{ display:grid; grid-template-columns: minmax(0,1fr) 340px; gap:16px; padding:12px 24px 24px; }}
@media (max-width:900px) {{ main {{ grid-template-columns:1fr; }} }}
.card {{ background:var(--card); border:1px solid var(--bd); border-radius:10px; padding:12px; }}
.flowrow {{ display:flex; gap:10px; align-items:flex-start; padding:8px 0; border-bottom:1px solid var(--bd); cursor:pointer; }}
.flowrow:last-child {{ border:0; }}
.sw {{ width:14px; height:14px; border-radius:3px; flex:none; margin-top:3px; }}
.p {{ font-family: ui-monospace, Menlo, monospace; font-size:12px; }}
.s {{ color:var(--mut); font-size:12px; }}
.tag {{ font-size:11px; padding:1px 6px; border-radius:8px; background:#f76b1522; color:#c4550f; }}
.legend {{ color:var(--mut); font-size:12px; margin-top:8px; }}
svg .ifl {{ font-size:10px; fill:var(--mut); text-anchor:middle; }}
svg .nk {{ font-size:9px; fill:#fff; text-anchor:middle; font-weight:600; }}
svg .nn {{ font-size:12px; fill:var(--fg); text-anchor:middle; font-weight:600; }}
.hidden {{ display:none; }}
</style></head><body>
<header><h1>{html.escape(topo['name'])} — ping color trace</h1>
<div class="meta">{html.escape(meta)}</div></header>
<main><div class="card">{svg}</div>
<div class="card"><div>{''.join(rows)}</div>
<div class="legend">Solid line = echo request (forward path) · dashed = echo reply (return path).
Arrows show direction. Hover a line for interface names and packet counts.</div></div></main>
<script>
document.querySelectorAll('input[data-flow]').forEach(cb => cb.addEventListener('change', () => {{
  document.querySelectorAll('[data-flow="' + cb.dataset.flow + '"]').forEach(el => {{
    if (el !== cb) el.classList.toggle('hidden', !cb.checked);
  }});
}}));
</script></body></html>"""


def render_mermaid(topo, flows):
    lines = ["graph LR"]
    ids = {n: re.sub(r"\W", "_", n) for n in topo["nodes"]}
    for n in topo["nodes"]:
        lines.append(f'  {ids[n]}["{n}"]')
    styles, k = [], 0
    for li, l in enumerate(topo["links"]):
        lines.append(f'  {ids[l["a"]["node"]]} ---|{l["a"]["ifname"]} - {l["z"]["ifname"]}| {ids[l["z"]["node"]]}')
        k += 1
    for f in flows:
        for t in f["traversals"]:
            arrow = "-.->" if t["kind"] == "reply" else "==>"
            lines.append(f'  {ids[t["from"]]} {arrow}|{f["color"]} {t["kind"]}| {ids[t["to"]]}')
            styles.append(f'  linkStyle {k} stroke:{f["hex"]},stroke-width:3px')
            k += 1
    return "\n".join(lines + styles) + "\n"


# --------------------------------------------------------------------------
# TopoViewer overlay (containerlab VS Code extension / Containerlab app)
#
# TopoViewer keeps its visual layer in <topology>.clab.yml.annotations.json,
# next to the topology file, and reloads it when the file changes on disk.
# The colored path is written there as "line" free-shape annotations that
# sit on top of the real links, so it appears on the same canvas, with the
# same node positions. Formats below were taken from the extension's own
# serializers (vscode-containerlab 0.27.0):
#   freeShapeAnnotations[] line: id, shapeType:"line", position (start),
#       endPosition, borderColor, borderWidth, borderStyle solid|dashed|dotted,
#       lineStartArrow, lineEndArrow, lineArrowSize, zIndex
#   freeTextAnnotations[]: id, text (markdown), position, fontSize, fontColor
#   scriptButtonAnnotations[]: id, label, position, script|scriptPath,
#       output terminal|dialog|toast, timeoutSeconds, color
#   nodeAnnotations[]: id (= YAML node name), position (top-left of node)
# A topology node's link anchor is position + nodeIconSize/2 (default 40 px).
# --------------------------------------------------------------------------

OVERLAY_PREFIX = "colortrace_"


def annotations_path(yaml_path):
    return Path(str(yaml_path) + ".annotations.json")


def load_annotations(path):
    try:
        txt = Path(path).read_text()
        ann = json.loads(txt) if txt.strip() else {}
    except FileNotFoundError:
        ann = {}
    if not isinstance(ann, dict):
        die(f"{path}: unexpected content (not a JSON object)")
    return ann


def write_preserving_owner(path, text):
    """Atomic write; keep the original owner/mode (the tool usually runs
    under sudo, the file belongs to the user who runs TopoViewer)."""
    path = Path(path)
    st = path.stat() if path.exists() else None
    tmp = path.with_name(path.name + ".colortrace-tmp")
    tmp.write_text(text)
    try:
        if st:
            os.chmod(tmp, st.st_mode & 0o7777)
            os.chown(tmp, st.st_uid, st.st_gid)
        elif os.environ.get("SUDO_UID"):
            os.chown(tmp, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", "0")))
    except PermissionError:
        pass
    os.replace(tmp, path)


def chown_to_sudo_user(root):
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or os.geteuid() != 0:
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for n in [dirpath] + [os.path.join(dirpath, f) for f in filenames]:
            try:
                os.chown(n, int(uid), int(gid or uid))
            except OSError:
                pass


def strip_overlay(ann):
    removed = 0
    for key in ("freeShapeAnnotations", "freeTextAnnotations"):
        items = ann.get(key) or []
        keep = [a for a in items if not str(a.get("id", "")).startswith(OVERLAY_PREFIX + "f")]
        removed += len(items) - len(keep)
        ann[key] = keep
    return removed


def _pos(p):
    if isinstance(p, dict) and isinstance(p.get("x"), (int, float)) and isinstance(p.get("y"), (int, float)):
        return float(p["x"]), float(p["y"])
    return None


def topoviewer_positions(ann, topo, place_missing=True):
    """Top-left positions TopoViewer uses for each node; place nodes that
    have none yet (lab never arranged in TopoViewer)."""
    pos = {}
    for a in ann.get("nodeAnnotations") or []:
        p = _pos(a.get("position"))
        if p and isinstance(a.get("id"), str):
            pos[a["id"]] = p
    for a in ann.get("networkNodeAnnotations") or []:   # host:eth1, macvlan:..., bridges
        p = _pos(a.get("position"))
        if p and isinstance(a.get("id"), str):
            pos.setdefault(a["id"], p)

    def key_for(node, ifname):
        if node in pos:
            return node
        for cand in (f"{node}:{ifname}", node):
            if cand in pos:
                return cand
        return None

    wanted = [n for n, v in topo["nodes"].items() if v["kind"] not in NO_NETNS_KINDS and v["kind"] != "external"]
    missing = [n for n in wanted if n not in pos]
    added = []
    if missing and place_missing:
        fl = force_layout(list(topo["nodes"]), topo["links"])
        xs = [p[0] for p in fl.values()]
        ys = [p[1] for p in fl.values()]
        span = max(max(xs) - min(xs), max(ys) - min(ys)) or 1
        scale = 180 * max(len(fl), 2) ** 0.5 / span          # ~180 px between nodes
        if pos:   # put the newcomers in a row under what is already arranged
            bx = min(p[0] for p in pos.values())
            by = max(p[1] for p in pos.values()) + 160
            for i, n in enumerate(missing):
                pos[n] = (bx + i * 160, by)
        else:
            for n in missing:
                pos[n] = ((fl[n][0] - min(xs)) * scale, (fl[n][1] - min(ys)) * scale)
        ann.setdefault("nodeAnnotations", [])
        for n in missing:
            ann["nodeAnnotations"].append({"id": n, "position": {"x": round(pos[n][0], 1), "y": round(pos[n][1], 1)}})
            added.append(n)
    return pos, key_for, added


def build_flow_animation(segments, frames=12, frame_ms=90, spacing=34, pad=12):
    """Animated WebP (with alpha) of glowing pulses travelling along each
    segment in its direction. segments: [((x1,y1),(x2,y2),hex)] in canvas
    (flow) coordinates. Returns (webp_bytes, x0, y0, w, h) or None.

    TopoViewer renders it inside an image-only text annotation; markdown-it
    there accepts data:image/(gif|png|jpeg|webp) and the webview CSP allows
    data: images, so the animation plays natively, with no file rewrites.
    Pulses are drawn without blur so the frames stay mostly transparent and
    the file small (~15-30 KB)."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        log("animation skipped: Pillow not available (pip install pillow / apk add py3-pillow)")
        return None
    import io
    xs = [c for (p1, p2, _) in segments for c in (p1[0], p2[0])]
    ys = [c for (p1, p2, _) in segments for c in (p1[1], p2[1])]
    if not xs:
        return None
    x0, y0 = math.floor(min(xs) - pad), math.floor(min(ys) - pad)
    w, h = math.ceil(max(xs) + pad) - x0, math.ceil(max(ys) + pad) - y0

    def rgb(hx):
        hx = hx.lstrip("#")[:6]
        return tuple(int(hx[i:i + 2], 16) for i in (0, 2, 4))

    out = []
    for f in range(frames):
        im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        dr = ImageDraw.Draw(im)
        phase = spacing * f / frames
        for (ax, ay), (bx, by), hx in segments:
            L = math.hypot(bx - ax, by - ay)
            if L < 1:
                continue
            ux, uy = (bx - ax) / L, (by - ay) / L
            c = rgb(hx)
            hot = tuple(int(v + (255 - v) * 0.65) for v in c)
            d = phase
            while d <= L:
                k = max(0.0, min(1.0, min(d, L - d) / 10.0))   # fade at the ends
                px, py = ax + ux * d - x0, ay + uy * d - y0
                for r, a in ((7, 60), (5, 110)):
                    dr.ellipse((px - r, py - r, px + r, py + r), fill=c + (int(a * k),))
                dr.ellipse((px - 3, py - 3, px + 3, py + 3), fill=hot + (int(255 * k),))
                d += spacing
        out.append(im)
    buf = io.BytesIO()
    out[0].save(buf, format="WEBP", save_all=True, append_images=out[1:], duration=frame_ms,
                loop=0, quality=60, alpha_quality=60, method=4, minimize_size=True, allow_mixed=True)
    return buf.getvalue(), x0, y0, w, h


def apply_topoviewer_overlay(yaml_path, topo, flows, node_size=40, legend=True, width=4, arrow_size=14,
                             reply_color="#4fc3f7", animate=True, on_top=False):
    path = annotations_path(yaml_path)
    ann = load_annotations(path)
    strip_overlay(ann)
    pos, key_for, added = topoviewer_positions(ann, topo)
    half = node_size / 2.0
    shapes, texts, skipped, anim_segments = [], [], [], []

    def center(node, ifname):
        k = key_for(node, ifname)
        if not k:
            return None
        x, y = pos[k]
        return x + half, y + half

    # parallel links between the same two nodes are fanned out by TopoViewer;
    # spread overlays the same way so each sits on its own link
    pair_idx, pair_tot = {}, {}
    for li, l in enumerate(topo["links"]):
        key = tuple(sorted((l["a"]["node"], l["z"]["node"])))
        pair_idx[li] = pair_tot.get(key, 0)
        pair_tot[key] = pair_tot.get(key, 0) + 1

    lanes = {}
    for fi, f in enumerate(flows):
        for t in f["traversals"]:
            lanes.setdefault(t["link"], []).append((fi, t))

    # arrowhead only on the last hop of each direction (into the destination
    # for requests, back into the source for replies)
    last_hop = set()
    for fi, f in enumerate(flows):
        for kind in ("request", "reply"):
            hops = f.get(kind + "_path") or []
            if len(hops) >= 2:
                last_hop.add((fi, kind, hops[-2], hops[-1]))

    for li, items in lanes.items():
        link = topo["links"][li]
        a, z = link["a"], link["z"]
        ca, cz = center(a["node"], a["ifname"]), center(z["node"], z["ifname"])
        if not ca or not cz:
            skipped.append(f"{a['node']}—{z['node']}")
            continue
        key = tuple(sorted((a["node"], z["node"])))
        sign = 1 if (a["node"], z["node"]) == key else -1
        dx, dy = cz[0] - ca[0], cz[1] - ca[1]
        d = math.hypot(dx, dy) or 1
        ux, uy = dx / d, dy / d
        nx, ny = -uy * sign, ux * sign
        base = (pair_idx[li] - (pair_tot[key] - 1) / 2) * 18
        m = len(items)
        for j, (fi, t) in enumerate(items):
            f = flows[fi]
            off = base + (j - (m - 1) / 2) * (width + 2)
            fwd = t["from"] == a["node"]
            (sx, sy), (ex, ey) = (ca, cz) if fwd else (cz, ca)
            dux, duy = (ux, uy) if fwd else (-ux, -uy)
            gap = half + 6
            arrow = (fi, t["kind"], t["from"], t["to"]) in last_hop
            # TopoViewer draws the arrowhead *beyond* the line end: it pulls the
            # line back by lineArrowSize and the marker (markerUnits = stroke
            # width) is lineArrowSize * borderWidth long. Place the end point so
            # the tip stops just outside the target node's icon.
            unit = arrow_size / float(width)                   # lineArrowSize
            end_gap = (half + 4 + arrow_size - unit) if arrow else gap
            # node names sit under the icon: keep clear of them when a line
            # leaves a node downwards or arrives at one from below
            label = 16
            start_gap = gap + label * max(0.0, duy)
            end_gap += label * max(0.0, -duy)
            start = (sx + dux * start_gap + nx * off, sy + duy * start_gap + ny * off)
            end = (ex - dux * end_gap + nx * off, ey - duy * end_gap + ny * off)
            color = reply_color if (t["kind"] == "reply" and reply_color) else f["hex"]
            anim_segments.append((start, end, color))
            shapes.append({
                "id": f"{OVERLAY_PREFIX}f{fi}_l{li}_{t['kind']}",
                "shapeType": "line",
                "position": {"x": round(start[0], 1), "y": round(start[1], 1)},
                "endPosition": {"x": round(end[0], 1), "y": round(end[1], 1)},
                "borderColor": color + ("aa" if animate else ""),   # see-through so the pulses shine through
                "borderWidth": width,
                "borderStyle": {"request": "solid", "reply": "dashed"}.get(t["kind"], "dotted"),
                "lineStartArrow": False,
                "lineEndArrow": arrow,
                "lineArrowSize": round(unit, 2),
                # below links and nodes (TopoViewer's own default for shapes), so
                # every link/node keeps its click & context menu (capture, impairments...)
                "zIndex": 5 if on_top else -1,
            })

    if legend and flows:
        used = list(pos.values())
        lx = min(p[0] for p in used) if used else 0
        ly = (max(p[1] for p in used) if used else 0) + node_size + 45   # under the topology
        for fi, f in enumerate(flows):
            req = " → ".join(f["request_path"]) or "not seen"
            rep = " → ".join(f["reply_path"]) or "not seen"
            y0 = ly + fi * 50
            texts.append({
                "id": f"{OVERLAY_PREFIX}f{fi}_legend",
                "text": f"**● {f['color']}** {f['src']} → {f['dst']}  \nrequest: {req}",
                "position": {"x": round(lx, 1), "y": round(y0, 1)},
                "fontSize": 11, "fontColor": f["hex"], "zIndex": 5,
            })
            texts.append({
                "id": f"{OVERLAY_PREFIX}f{fi}_legend_reply",
                "text": f"reply (dashed): {rep}",
                "position": {"x": round(lx, 1), "y": round(y0 + 30, 1)},
                "fontSize": 11, "fontColor": reply_color or f["hex"], "zIndex": 5,
            })

    if animate and anim_segments:
        res = build_flow_animation(anim_segments)
        if res:
            data, x0, y0, w, h = res
            import base64
            texts.insert(0, {
                "id": f"{OVERLAY_PREFIX}f_anim",
                # image-only + transparent + fixed size => TopoViewer renders it with
                # zero padding; fontSize 0 removes paragraph margins/baseline gap
                "text": "![](data:image/webp;base64," + base64.b64encode(data).decode() + ")",
                "position": {"x": x0, "y": y0},
                "width": w, "height": h,
                "fontSize": 0,
                "backgroundColor": "transparent",
                "zIndex": -1,            # under the nodes: never blocks clicks
            })

    ann.setdefault("freeShapeAnnotations", []).extend(shapes)
    ann.setdefault("freeTextAnnotations", []).extend(texts)
    write_preserving_owner(path, json.dumps(ann, indent=2) + "\n")
    return {"path": str(path), "lines": len(shapes), "labels": len(texts),
            "placed_nodes": added, "skipped_links": skipped}


def install_buttons(yaml_path, flow_args, tool_cmd, extra_args, use_sudo=True):
    """Add 'Color trace' + 'Clear trace' script buttons to the canvas.
    TopoViewer runs them with bash on the lab host from the topology folder,
    with CLAB_TOPOLOGY set."""
    path = annotations_path(yaml_path)
    ann = load_annotations(path)
    btns = [b for b in (ann.get("scriptButtonAnnotations") or [])
            if not str(b.get("id", "")).startswith(OVERLAY_PREFIX + "btn")]
    pos, _, _ = topoviewer_positions(ann, {"nodes": {}, "links": []}, place_missing=False)
    x = (min(p[0] for p in pos.values()) if pos else 0) + 0
    y = (min(p[1] for p in pos.values()) if pos else 0) - 150
    flows_s = " ".join(f"--flow {shlex_quote(s)} {shlex_quote(d)} {shlex_quote(c)}" for s, d, c in flow_args)
    extra = " ".join(shlex_quote(a) for a in extra_args)
    first = parse_color(flow_args[0][2])
    btns.append({"id": f"{OVERLAY_PREFIX}btn_run",
                 "label": "Color trace: " + ", ".join(c for _, _, c in flow_args),
                 "position": {"x": round(x, 1), "y": round(y, 1)},
                 "script": f'{"sudo -n " if use_sudo else ""}{tool_cmd} -t "$CLAB_TOPOLOGY" {flows_s} {extra}'.strip(),
                 "output": "terminal", "timeoutSeconds": 180, "color": first})
    btns.append({"id": f"{OVERLAY_PREFIX}btn_clear",
                 "label": "Clear color trace",
                 "position": {"x": round(x + 230, 1), "y": round(y, 1)},
                 "script": f'{tool_cmd} -t "$CLAB_TOPOLOGY" --clear',
                 "output": "toast", "timeoutSeconds": 30, "color": "#6b7080"})
    ann["scriptButtonAnnotations"] = btns
    write_preserving_owner(path, json.dumps(ann, indent=2) + "\n")
    return str(path)


def shlex_quote(s):
    import shlex
    return shlex.quote(str(s))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
# Live watch mode: follow real pings (e.g. one you start by hand from a
# client), color their path in TopoViewer while they flow, and remove the
# color once they stop. No marker is needed: the client's own echo
# request/reply is recognised by the inner IPv4/IPv6 header (source and
# destination address + ICMP type), which stays intact inside SRv6, MPLS,
# VXLAN or VLAN encapsulation.
# --------------------------------------------------------------------------

import ipaddress
import queue
import threading


def client_addresses(runtime, longname):
    """Data-plane addresses of a Linux node (everything except lo/eth0)."""
    r = run([runtime, "exec", longname, "ip", "-o", "addr", "show"], check=False)
    addrs = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
            continue
        ifname = parts[1].split("@")[0]
        if ifname in ("lo", "eth0"):
            continue
        ip = ipaddress.ip_address(parts[3].split("/")[0])
        if ip.is_link_local or ip.is_loopback:
            continue
        addrs.append(ip)
    return addrs


PROTO_NUM = {"icmp": (1, 58), "tcp": (6, 6), "udp": (17, 17)}   # (IPv4 proto, IPv6 next header)


def match_flow(data, srcs, dsts, protos=("icmp",), port=None):
    """Find, inside any encapsulation (SRv6, MPLS, VXLAN, VLAN...), an inner
    IPv4/IPv6 packet of the watched client and classify it:
      'request' = sent by the client (srcs)  -> forward path
      'reply'   = sent to the client          -> return path
    ICMP: only echo request from / echo reply to the client (ping).
    TCP/UDP: any segment/datagram, optionally limited to `port` (either
    source or destination port, e.g. 5201 for iperf3).
    dsts optionally limits the peer address."""
    want4 = {PROTO_NUM[p][0] for p in protos}
    want6 = {PROTO_NUM[p][1] for p in protos}
    for sip in srcs:
        start = 0
        while True:
            p = data.find(sip, start)
            if p < 0:
                break
            start = p + 1
            if len(sip) == 4:
                for role, h in (("src", p - 12), ("dst", p - 16)):
                    if h < 0 or h + 20 > len(data):
                        continue
                    b = data[h]
                    proto = data[h + 9]
                    if b >> 4 != 4 or (b & 15) < 5 or proto not in want4:
                        continue
                    other = data[h + 16:h + 20] if role == "src" else data[h + 12:h + 16]
                    if dsts and other not in dsts:
                        continue
                    l4 = h + (b & 15) * 4
                    kind = _classify_l4(data, l4, proto, role, port, icmp_req=8, icmp_rep=0)
                    if kind:
                        return kind
            else:
                for role, h in (("src", p - 8), ("dst", p - 24)):
                    if h < 0 or h + 41 > len(data):
                        continue
                    nh = data[h + 6]
                    if data[h] >> 4 != 6 or nh not in want6:
                        continue
                    other = data[h + 24:h + 40] if role == "src" else data[h + 8:h + 24]
                    if dsts and other not in dsts:
                        continue
                    kind = _classify_l4(data, h + 40, nh, role, port, icmp_req=128, icmp_rep=129)
                    if kind:
                        return kind
    return None


def match_flow_proto(data, srcs, dsts, protos=("icmp",), port=None):
    """Like match_flow but returns (kind, protocol-name) or (None, None)."""
    for name in protos:
        k = match_flow(data, srcs, dsts, (name,), port)
        if k:
            return k, name
    return None, None


def _classify_l4(data, l4, proto, role, port, icmp_req, icmp_rep):
    if l4 >= len(data):
        return None
    if proto in (1, 58):
        typ = data[l4]
        if role == "src" and typ == icmp_req:
            return "request"
        if role == "dst" and typ == icmp_rep:
            return "reply"
        return None
    if port is not None:
        if l4 + 4 > len(data):
            return None
        sport, dport = struct.unpack(">HH", data[l4:l4 + 4])
        if port not in (sport, dport):
            return None
    return "request" if role == "src" else "reply"


def match_ping(data, srcs, dsts):          # kept for compatibility
    return match_flow(data, srcs, dsts, ("icmp",))


class Watcher:
    """Aggregates live packet hits into the set of currently active link
    traversals per watched flow. Pure logic, no I/O (testable)."""

    def __init__(self, topo, caps, watches, idle=3.0, settle=0.7):
        self.topo, self.caps, self.watches = topo, caps, watches
        self.idle, self.settle = idle, settle
        self.state = {}            # (wi, link, kind, from) -> traversal dict
        self.recent = {}           # capture index -> time of its last hit
        self.counts = {}           # (color, proto, kind) -> link hits since last status
        self.shown = frozenset()   # what TopoViewer currently shows
        self.pending, self.pending_since = None, 0.0

    HOLD = 0.5   # after a hit on a capture, skip its packets for this long (heavy traffic)

    def feed(self, ci, ts, data, now):
        if now - self.recent.get(ci, -1e9) < self.HOLD:
            return
        c = self.caps[ci]
        for wi, w in enumerate(self.watches):
            kind, pname = match_flow_proto(data, w["src_bytes"], w["dst_bytes"], w["protos"], w["port"])
            if not kind:
                continue
            k2 = (w["color"], pname, kind)
            self.counts[k2] = self.counts.get(k2, 0) + 1
            link = self.topo["links"][c["link"]]
            here, there = c["side"], ("z" if c["side"] == "a" else "a")
            if c.get("dir", "out") == "in":
                here, there = there, here
            frm, to = link[here], link[there]
            key = (wi, c["link"], kind, frm["node"])
            self.recent[ci] = now
            seen = now
            t = self.state.get(key)
            if t is None:
                self.state[key] = {"link": c["link"], "kind": kind, "from": frm["node"],
                                   "from_if": frm["ifname"], "to": to["node"], "to_if": to["ifname"],
                                   "packets": 1, "first_seen": ts, "last": seen}
            else:
                t["packets"] += 1
                t["last"] = max(t["last"], seen)

    def shift(self, dt):
        """Push all 'last seen' times forward by dt (used after a slow redraw)."""
        if dt <= 0:
            return
        for v in self.state.values():
            v["last"] += dt
        for k in self.recent:
            self.recent[k] += dt
        self.pending_since += dt

    def tick(self, now):
        """Return the flows to draw when the visible set should change
        (an empty list means: clear), else None."""
        for k in [k for k, v in self.state.items() if now - v["last"] > self.idle]:
            del self.state[k]
        sig = frozenset(self.state)
        if sig == self.shown:
            self.pending = None
            return None
        if sig != self.pending:            # wait until the set stops growing
            self.pending, self.pending_since = sig, now
            return None
        if now - self.pending_since < self.settle:
            return None
        self.shown, self.pending = sig, None
        return self.flows()

    def flows(self):
        out = []
        for wi, w in enumerate(self.watches):
            trav = sorted((v for (i, *_), v in self.state.items() if i == wi),
                          key=lambda x: x["first_seen"] or 0)
            if not trav:
                continue
            out.append({"src": w["src"], "dst": w["dst"], "color": w["color"], "hex": w["hex"],
                        "marker": "", "ping_summary": "live", "traversals": trav,
                        "request_path": hop_path(trav, "request", w["src"]),
                        "reply_path": hop_path(trav, "reply", None)})
        return out


def _read_exact(f, n):
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _stream_reader(ci, proc, q, stop, budget=200, skim=5000):
    """Read tcpdump's pcap stream with bounded CPU, however heavy the traffic.

    Records are walked in 64 KB blocks; only the first `budget` per second
    are handed on for matching, the next ones up to `skim` per second are
    skipped cheaply (keeps the stream fresh), and beyond that the reader
    pauses until the next second - tcpdump then blocks and the kernel drops
    the surplus (its buffer is kept small with -B, so little stale backlog
    remains when traffic stops)."""
    f = proc.stdout
    read = getattr(f, "read1", f.read)
    buf = b""
    while len(buf) < 24:
        chunk = read(65536)
        if not chunk:
            return
        buf += chunk
    magic = buf[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
    hdr = struct.Struct(endian + "IIII")
    buf = buf[24:]
    win_end, count = time.monotonic() + 1.0, 0
    while not stop.is_set():
        pos, n = 0, len(buf)
        while pos + 16 <= n:
            sec, frac, caplen, _ = hdr.unpack_from(buf, pos)
            end = pos + 16 + caplen
            if end > n:
                break
            if count < budget:
                try:
                    q.put_nowait((ci, sec + frac / div, buf[pos + 16:end]))
                except queue.Full:
                    pass
            count += 1
            pos = end
            if count >= skim:
                break
        buf = buf[pos:]
        if count >= skim:
            now = time.monotonic()
            if now < win_end:
                stop.wait(win_end - now)
        now = time.monotonic()
        if now >= win_end:
            win_end, count = now + 1.0, 0
        chunk = read(65536)
        if not chunk:
            return
        buf += chunk


def run_loop(q, w, draw, ended, max_batch=2000, clock=time.time):
    """Main loop of live mode. Never drains the queue for long: at most
    max_batch packets, then the display is re-evaluated. Every packet is
    stamped with the time it is processed, so heavy traffic (iperf) can't
    make a still-active path look idle."""
    next_status = clock() + 5
    while True:
        if clock() >= next_status:
            next_status = clock() + 5
            if w.counts:
                parts = [f"{c} {p} {k}: {n}" for (c, p, k), n in sorted(w.counts.items())]
                print(f"{time.strftime('%H:%M:%S')}  seen (link hits, last 5 s): " + ", ".join(parts), flush=True)
                w.counts.clear()
            else:
                print(f"{time.strftime('%H:%M:%S')}  no matching traffic in the last 5 s", flush=True)
        n = 0
        try:
            item = q.get(timeout=0.25)
            while True:
                ci, ts, data = item
                w.feed(ci, ts, data, clock())
                n += 1
                if n >= max_batch:
                    break
                item = q.get_nowait()
        except queue.Empty:
            pass
        flows = w.tick(clock())
        if flows is not None:
            t0 = clock()
            draw(flows)
            w.shift(clock() - t0)          # time spent drawing is not idle time
        if ended():
            return


def watch(topo, args):
    if args.proto is None:
        args.proto = "tcp,udp" if args.port else "icmp"
    protos = [x.strip().lower() for x in args.proto.split(",") if x.strip()]
    if "any" in protos:
        protos = ["icmp", "tcp", "udp"]
    bad = [x for x in protos if x not in PROTO_NUM]
    if bad or not protos:
        die(f"--proto: unknown {', '.join(bad) or '(empty)'}; use icmp, tcp, udp, any or a comma list")
    if args.port and protos == ["icmp"]:
        die("--port needs --proto tcp/udp (ICMP has no ports)")
    watches = []
    for src, dst, color in args.watch:
        node = topo["nodes"].get(src)
        if not node or not node["longname"]:
            die(f"watch source '{src}' is not a node of this lab")
        if args.src_ip:
            srcs = [ipaddress.ip_address(a) for a in args.src_ip]
        else:
            srcs = client_addresses(args.runtime, node["longname"])
            if not srcs:
                die(f"{src}: no data-plane address found (pass --src-ip)")
        dsts = None if dst.lower() == "any" else [ipaddress.ip_address(dst)]
        watches.append({"src": src, "dst": dst, "color": color, "hex": parse_color(color),
                        "protos": protos, "port": args.port,
                        "src_bytes": [a.packed for a in srcs],
                        "dst_bytes": [a.packed for a in dsts] if dsts else None})
        what = "/".join(protos) + (f" port {args.port}" if args.port else "")
        log(f"[{color}] watching {what} traffic from {src} ({', '.join(map(str, srcs))}) to {dst}")
    if not args.topo:
        die("watch mode needs -t <topology file> to draw on TopoViewer")

    caps = start_captures(topo, args, None, stream=True)
    q, stop = queue.Queue(maxsize=100000), threading.Event()
    threads = [threading.Thread(target=_stream_reader, args=(i, c["proc"], q, stop, args.sample_rate),
                                daemon=True)
               for i, c in enumerate(caps)]
    for th in threads:
        th.start()
    w = Watcher(topo, caps, watches, idle=args.idle)
    path = annotations_path(args.topo)

    def draw(flows):
        if flows:
            apply_topoviewer_overlay(args.topo, topo, flows, node_size=args.node_size,
                                     legend=not args.no_legend, width=args.line_width,
                                     arrow_size=args.arrow_size,
                                     reply_color=None if args.reply_color == 'same' else parse_color(args.reply_color),
                                     animate=not args.no_animate, on_top=args.overlay_on_top)
            for f in flows:
                print(f"{time.strftime('%H:%M:%S')}  ● {f['color']} {f['src']} → {f['dst']}  "
                      f"request: {' → '.join(f['request_path']) or '-'}  |  "
                      f"reply: {' → '.join(f['reply_path']) or '-'}", flush=True)
        else:
            ann = load_annotations(path)
            if strip_overlay(ann):
                write_preserving_owner(path, json.dumps(ann, indent=2) + "\n")
            print(f"{time.strftime('%H:%M:%S')}  pings stopped — color removed", flush=True)

    def _term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)
    print("waiting for traffic… start it now (Ctrl-C to quit)", flush=True)
    try:
        run_loop(q, w, draw, lambda: all(c["proc"].poll() is not None for c in caps))
        log("all captures ended")
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        stop_captures(caps)
        ann = load_annotations(path)
        if strip_overlay(ann):
            write_preserving_owner(path, json.dumps(ann, indent=2) + "\n")
        print("stopped — TopoViewer overlay removed")


# --------------------------------------------------------------------------

def parse_color(c):
    if re.fullmatch(r"#?[0-9a-fA-F]{6}", c):
        return c if c.startswith("#") else "#" + c
    if c.lower() in NAMED_COLORS:
        return NAMED_COLORS[c.lower()]
    die(f"unknown color '{c}' (use a name: {', '.join(NAMED_COLORS)} or #rrggbb)")


def make_marker(idx):
    return (MARKER_MAGIC + bytes([idx & 0xff]) + secrets.token_bytes(13)).hex()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="clab-color-trace",
        description="Color-tag pings from a Linux container and paint their path on the containerlab topology.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  sudo clab-color-trace -t srv6.clab.yml --flow client1 10.0.2.2 red
  sudo clab-color-trace --flow client1 10.0.2.2 red --flow client1 2001:db8:2::2 blue -c 10
  clab-color-trace --replay ./trace-out          # re-render a saved run, no root needed
""")
    ap.add_argument("-t", "--topo", help="containerlab topology file (*.clab.yml)")
    ap.add_argument("--lab-dir", help="lab directory containing topology-data.json")
    ap.add_argument("--flow", nargs=3, action="append", metavar=("SRC", "DST", "COLOR"),
                    help="source node, destination IP, color name or #hex (repeatable)")
    ap.add_argument("--src-addr", help="source address/interface for ping -I (all flows)")
    ap.add_argument("-c", "--count", type=int, default=5, help="pings per flow (default 5)")
    ap.add_argument("-i", "--interval", type=float, default=0.2, help="ping interval s (default 0.2)")
    ap.add_argument("--runtime", default="docker", help="container runtime CLI (default docker)")
    ap.add_argument("--iface-map", action="append", metavar="NODE:ALIAS=LINUXIF",
                    help="override interface name mapping, e.g. sr1:1/1/c1/1=e1-1-c1-1")
    ap.add_argument("--snaplen", type=int, default=1024)
    ap.add_argument("-o", "--out", default="trace-out", help="output directory (default ./trace-out)")
    ap.add_argument("--replay", metavar="DIR", help="re-analyse/re-render a previous output dir")
    lv = ap.add_argument_group("live watch (color real traffic - ping, iperf... - while it runs)")
    lv.add_argument("--watch", nargs=3, action="append", metavar=("SRC", "DST", "COLOR"),
                    help="watch traffic from node SRC to DST (an IP, or 'any'); repeatable")
    lv.add_argument("--proto", default=None,
                    help="traffic to follow: icmp (ping), tcp, udp, a comma list (tcp,udp) or any "
                         "(default icmp; tcp,udp when --port is given)")
    lv.add_argument("--port", type=int,
                    help="only TCP/UDP with this source or destination port (e.g. 5201 for iperf3)")
    lv.add_argument("--sample-rate", type=int, default=200,
                    help="max packets inspected per interface per second (default 200)")
    lv.add_argument("--src-ip", action="append", help="SRC's address(es), if auto-detection is wrong")
    lv.add_argument("--idle", type=float, default=3.0,
                    help="seconds without packets before the color is removed (default 3)")
    tv = ap.add_argument_group("TopoViewer overlay")
    tv.add_argument("--no-topoviewer", action="store_true",
                    help="do not paint the result into <topology>.annotations.json")
    tv.add_argument("--node-size", type=int, default=40,
                    help="TopoViewer node icon size in px (Lab Settings; default 40)")
    tv.add_argument("--line-width", type=int, default=4, help="overlay line width (default 4)")
    tv.add_argument("--overlay-on-top", action="store_true",
                    help="draw the colored lines above links/nodes (blocks clicking them)")
    tv.add_argument("--no-animate", action="store_true",
                    help="static colors only (no moving pulses along the path)")
    tv.add_argument("--reply-color", default="lightblue",
                    help="color of the reply (return) path: a name, #rrggbb, or 'same' for the flow color "
                         "(default lightblue)")
    tv.add_argument("--arrow-size", type=int, default=14, help="arrowhead length in px on the last hop (default 14)")
    tv.add_argument("--no-legend", action="store_true", help="no text legend on the canvas")
    tv.add_argument("--clear", action="store_true", help="remove the color overlay from TopoViewer and exit")
    tv.add_argument("--install-buttons", action="store_true",
                    help="add 'Color trace' / 'Clear' script buttons for the given --flow(s) to the canvas and exit")
    tv.add_argument("--tool-cmd", help="command the buttons run (default: this script's installed path)")
    tv.add_argument("--no-button-sudo", action="store_true",
                    help="buttons call --tool-cmd without sudo (e.g. the macOS docker wrapper)")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    # TopoViewer script buttons run with CLAB_TOPOLOGY set and cwd = topology folder
    if not args.topo and os.environ.get("CLAB_TOPOLOGY"):
        args.topo = os.environ["CLAB_TOPOLOGY"]

    if args.clear:
        if not args.topo:
            ap.error("--clear needs -t <topology file>")
        path = annotations_path(args.topo)
        ann = load_annotations(path)
        n = strip_overlay(ann)
        write_preserving_owner(path, json.dumps(ann, indent=2) + "\n")
        print(f"removed {n} color-trace annotations from {path}")
        return

    if args.install_buttons:
        if not args.topo or not args.flow:
            ap.error("--install-buttons needs -t <topology file> and at least one --flow")
        tool = args.tool_cmd or shutil.which("clab-color-trace") or os.path.realpath(sys.argv[0])
        if tool.endswith(".py"):
            log(f"note: buttons will run '{tool}' — install it as /usr/local/bin/clab-color-trace "
                "for a clean sudoers rule, or pass --tool-cmd")
        extra = []
        if args.count != 5:
            extra += ["-c", str(args.count)]
        if args.node_size != 40:
            extra += ["--node-size", str(args.node_size)]
        print("buttons added to " + install_buttons(args.topo, args.flow, tool, extra, use_sudo=not args.no_button_sudo))
        return

    if args.watch:
        topo = load_topology(find_topology_data(args))
        preflight(args)
        if args.snaplen == 1024:
            args.snaplen = 200          # outer + inner headers are enough for live matching
        watch(topo, args)
        return

    if args.replay:
        d = Path(args.replay)
        man = json.loads((d / "manifest.json").read_text())
        topo, flows, caps = man["topology"], man["flows"], man["captures"]
        args.topo = args.topo or man.get("topology_file")
        hits = analyse(caps, flows, d / "pcaps")
        outdir = d
        meta = man.get("meta", "") + " · replayed"
    else:
        if not args.flow:
            ap.error("at least one --flow SRC DST COLOR is required")
        topo = load_topology(find_topology_data(args))
        flows = []
        for i, (src, dst, color) in enumerate(args.flow):
            flows.append({"src": src, "dst": dst, "color": color, "hex": parse_color(color),
                          "marker": make_marker(i), "src_addr": args.src_addr})
        preflight(args)
        outdir = Path(args.out)
        (outdir / "pcaps").mkdir(parents=True, exist_ok=True)
        caps = start_captures(topo, args, outdir / "pcaps")
        try:
            time.sleep(0.5)
            run_pings(topo, flows, args)
            time.sleep(1.0)    # let the last replies land
        finally:
            stop_captures(caps)
        caps = [{k: v for k, v in c.items() if k != "proc"} for c in caps]
        hits = analyse(caps, flows, outdir / "pcaps")
        meta = f"lab {topo['name']} · {time.strftime('%Y-%m-%d %H:%M:%S')} · {args.count} pings/flow"
        (outdir / "manifest.json").write_text(json.dumps(
            {"version": VERSION, "meta": meta, "topology": topo, "flows": flows, "captures": caps,
             "topology_file": os.path.abspath(args.topo) if args.topo else None}, indent=2))

    result = build_result(topo, flows, caps, hits)
    (outdir / "result.json").write_text(json.dumps({"lab": topo["name"], "flows": result}, indent=2))
    (outdir / "trace.html").write_text(render_html(topo, result, meta))
    (outdir / "trace.mmd").write_text(render_mermaid(topo, result))

    for f in result:
        print(f"\n● {f['color']}  {f['src']} → {f['dst']}   ({f['ping_summary']})")
        print("  request: " + (" → ".join(f["request_path"]) or "not seen on any link"))
        print("  reply:   " + (" → ".join(f["reply_path"]) or "not seen on any link"))
        for t in f["traversals"]:
            print(f"    {t['kind']:<8} {t['from']}:{t['from_if']} → {t['to']}:{t['to_if']}  {t['packets']} pkts")
    print(f"\nwrote {outdir/'trace.html'}, {outdir/'result.json'}, {outdir/'trace.mmd'}")

    if not args.no_topoviewer:
        if not args.topo:
            log("no topology file (-t) known, so TopoViewer was not updated")
        else:
            r = apply_topoviewer_overlay(args.topo, topo, result, node_size=args.node_size,
                                         legend=not args.no_legend, width=args.line_width,
                                     arrow_size=args.arrow_size,
                                     reply_color=None if args.reply_color == 'same' else parse_color(args.reply_color),
                                     animate=not args.no_animate, on_top=args.overlay_on_top)
            print(f"TopoViewer: {r['lines']} colored line(s), {r['labels']} label(s)/animation -> {r['path']}")
            if r["placed_nodes"]:
                print("  placed nodes that had no TopoViewer position yet: " + ", ".join(r["placed_nodes"]))
            if r["skipped_links"]:
                print("  no TopoViewer position for: " + ", ".join(r["skipped_links"]))
    chown_to_sudo_user(outdir)


if __name__ == "__main__":
    main()
