#!/usr/bin/env python3
import os, sys, csv, math, argparse, ipaddress, datetime as dt
from collections import defaultdict, Counter, deque
from dataclasses import dataclass
from typing import List, Dict, Tuple, Iterable, Optional

import pandas as pd

# -----------------------------
# Utilities: column handling
# -----------------------------

COL_ALIASES = {
    "time": ["time", "timestamp", "ts", "datetime", "@timestamp", "frame.time", "start_time"],
    "src": ["src", "src_ip", "source", "ip.src", "sip", "address", "Source", "IPv4 Address", "ipv4"],
    "dst": ["dst", "dst_ip", "destination", "ip.dst", "dip", "Target", "IPv4 Destination", "peer"],
    "sport": ["sport", "src_port", "source_port", "tcp.srcport", "udp.srcport", "sport_host"],
    "dport": ["dport", "dst_port", "destination_port", "tcp.dstport", "udp.dstport", "port", "Port"],
    "proto": ["proto", "protocol", "ip.proto", "_proto", "l4_protocol"],
    "bytes": ["bytes", "byte_count", "len", "octets", "total_bytes", "Tx Bytes + Rx Bytes", "size"],
    "packets": ["packets", "pkt_count", "frames", "total_packets", "Tx Packets + Rx Packets"],
    "dir": ["dir", "direction", "flow_dir"],  # optional
}

def resolve_col(df: pd.DataFrame, key: str) -> Optional[str]:
    for cand in COL_ALIASES.get(key, []):
        if cand in df.columns:
            return cand
    # soft fallback for case-insensitive matches
    lower = {c.lower(): c for c in df.columns}
    for cand in COL_ALIASES.get(key, []):
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None

def parse_time(val):
    if pd.isna(val):
        return pd.NaT
    # Try multiple formats quickly
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            if fmt is None:
                return pd.to_datetime(val, utc=True, errors="raise")
            return pd.to_datetime(val, format=fmt, utc=True, errors="raise")
        except Exception:
            continue
    return pd.NaT

def ip_to_int(s: str) -> Tuple[int, int]:
    """Return (family, int_value). family: 4 or 6. Invalid => (0, 0)."""
    try:
        ip = ipaddress.ip_address(str(s))
        if isinstance(ip, ipaddress.IPv4Address):
            return (4, int(ip))
        else:
            return (6, int(ip))
    except Exception:
        return (0, 0)

# -----------------------------
# Advanced sorting helpers
# -----------------------------

def counting_sort_ports(port_series: Iterable[int]) -> List[Tuple[int, int]]:
    """Counting sort specialized for port histograms (0..65535). Returns list of (port, count) sorted by port asc."""
    MAX_PORT = 65535
    counts = [0] * (MAX_PORT + 1)
    for p in port_series:
        if p is None:
            continue
        try:
            pi = int(p)
            if 0 <= pi <= MAX_PORT:
                counts[pi] += 1
        except Exception:
            continue
    return [(port, cnt) for port, cnt in enumerate(counts) if cnt > 0]

def radix_sort_ip_ints(ip_ints: List[int], radix: int = 256, width_bytes: int = 4) -> List[int]:
    """LSD Radix sort for non-negative integers (e.g., IPv4 as 32-bit). width_bytes=4 for IPv4, 16 for IPv6."""
    if not ip_ints:
        return []
    arr = list(ip_ints)
    base = radix
    for byte in range(width_bytes):  # process LSB to MSB
        # counting sort on this byte
        counts = [0] * base
        output = [0] * len(arr)
        shift = 8 * byte
        for x in arr:
            key = (x >> shift) & 0xFF
            counts[key] += 1
        # prefix sums
        total = 0
        for i in range(base):
            c = counts[i]
            counts[i] = total
            total += c
        # place
        for x in arr:
            key = (x >> shift) & 0xFF
            output[counts[key]] = x
            counts[key] += 1
        arr = output
    return arr

# -----------------------------
# Service categorization
# -----------------------------

COMMON_SERVICES = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    123: "NTP",
    137: "NBNS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    853: "DNS-over-TLS",
    1883: "MQTT",
    1900: "SSDP",
    3478: "STUN",
    5353: "mDNS",
    5671: "AMQP/SSL",
    5672: "AMQP",
    5683: "CoAP",
    8008: "Chromecast",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8554: "RTSP-Alt",
    8883: "MQTT/SSL",
}

def categorize_service(proto: str, dport: Optional[int]) -> str:
    p = (str(proto or "")).upper()
    try:
        dp = int(dport) if dport is not None else None
    except Exception:
        dp = None
    if dp in COMMON_SERVICES:
        return COMMON_SERVICES[dp]
    if p.startswith("ICMP"):
        return "ICMP"
    if p == "TCP" and dp is not None:
        return f"TCP:{dp}"
    if p == "UDP" and dp is not None:
        return f"UDP:{dp}"
    if dp is not None:
        return f"PORT:{dp}"
    return p or "UNK"

# -----------------------------
# Markov modeling
# -----------------------------

@dataclass
class MarkovModel:
    counts: Dict[Tuple[str, str], int]
    totals: Dict[str, int]
    states: set

    @classmethod
    def from_sequences(cls, seqs: Iterable[List[str]]) -> "MarkovModel":
        counts = Counter()
        totals = Counter()
        states = set()
        for seq in seqs:
            if not seq:
                continue
            states.update(seq)
            for a, b in zip(seq, seq[1:]):
                counts[(a, b)] += 1
                totals[a] += 1
        return cls(counts=dict(counts), totals=dict(totals), states=states)

    def prob(self, a: str, b: str, alpha: float = 0.5) -> float:
        # Laplace smoothing
        K = max(1, len(self.states))
        num = self.counts.get((a, b), 0) + alpha
        den = self.totals.get(a, 0) + alpha * K
        return num / den if den > 0 else 1.0 / K

    def sequence_nll(self, seq: List[str], alpha: float = 0.5) -> float:
        # Negative log-likelihood
        nll = 0.0
        for a, b in zip(seq, seq[1:]):
            p = self.prob(a, b, alpha=alpha)
            nll -= math.log(max(p, 1e-12))
        return nll

# -----------------------------
# Ingestion & normalization
# -----------------------------

def load_flows(paths: List[str], tz="UTC") -> pd.DataFrame:
    frames = []
    for p in paths:
        if not os.path.exists(p):
            continue
        try:
            df = pd.read_csv(p)
        except Exception:
            try:
                df = pd.read_csv(p, sep=";")
            except Exception:
                df = pd.read_csv(p, engine="python")
        frames.append(df)
    if not frames:
        raise SystemExit("No readable input CSVs provided.")
    df = pd.concat(frames, ignore_index=True)

    # Resolve columns
    col_time = resolve_col(df, "time")
    col_src = resolve_col(df, "src")
    col_dst = resolve_col(df, "dst")
    col_sport = resolve_col(df, "sport")
    col_dport = resolve_col(df, "dport")
    col_proto = resolve_col(df, "proto")
    col_bytes = resolve_col(df, "bytes")
    col_pkts = resolve_col(df, "packets")
    col_dir = resolve_col(df, "dir")

    # Build normalized columns
    out = pd.DataFrame()
    if col_time:
        out["time"] = pd.to_datetime(df[col_time], utc=True, errors="coerce")
    else:
        out["time"] = pd.NaT
    out["src"] = df[col_src] if col_src else None
    out["dst"] = df[col_dst] if col_dst else None
    out["sport"] = pd.to_numeric(df[col_sport], errors="coerce") if col_sport else None
    out["dport"] = pd.to_numeric(df[col_dport], errors="coerce") if col_dport else None
    out["proto"] = df[col_proto] if col_proto else None
    out["bytes"] = pd.to_numeric(df[col_bytes], errors="coerce") if col_bytes else 0
    out["packets"] = pd.to_numeric(df[col_pkts], errors="coerce") if col_pkts else 0
    out["dir"] = df[col_dir] if col_dir else None

    # Basic cleaning
    out.dropna(subset=["src", "dst"], how="all", inplace=True)
    # Fill NA numeric
    for c in ["sport", "dport", "bytes", "packets"]:
        if c in out.columns:
            out[c] = out[c].fillna(0).astype(int)

    # Families and integer representations for sorting
    fam_src, int_src = [], []
    fam_dst, int_dst = [], []
    for s, d in zip(out["src"].astype(str), out["dst"].astype(str)):
        f4, i4 = ip_to_int(s)
        fam_src.append(f4)
        int_src.append(i4)
        f6, i6 = ip_to_int(d)
        fam_dst.append(f6)
        int_dst.append(i6)
    out["src_family"] = fam_src
    out["src_int"] = int_src
    out["dst_family"] = fam_dst
    out["dst_int"] = int_dst

    # Service state
    states = []
    for pr, dp in zip(out["proto"], out["dport"]):
        states.append(categorize_service(pr, dp))
    out["state"] = states

    if col_time:
        out.sort_values("time", inplace=True, kind="mergesort")  # stable sort for equal timestamps
    return out

# -----------------------------
# Summaries (using advanced sorts)
# -----------------------------

def topk_heap(counter: Dict, k=10) -> List[Tuple[object, int]]:
    # Avoid O(n log n) full sort for top-k
    import heapq
    return heapq.nlargest(k, counter.items(), key=lambda kv: kv[1])

def summarize(df: pd.DataFrame, outdir: str):
    os.makedirs(outdir, exist_ok=True)

    # 1) Port histogram via counting sort
    port_counts = Counter(int(p) for p in df["dport"] if pd.notna(p))
    port_hist_sorted = counting_sort_ports(list(port_counts.elements()))
    with open(os.path.join(outdir, "port_histogram.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["port", "count"])
        for port, cnt in port_hist_sorted:
            w.writerow([port, cnt])

    # 2) Top talkers by bytes (source)
    by_src = df.groupby("src", dropna=True)["bytes"].sum().to_dict()
    top_src = topk_heap(by_src, k=20)
    pd.DataFrame(top_src, columns=["src", "bytes"]).to_csv(os.path.join(outdir, "top_talkers_src.csv"), index=False)

    # 3) Top peers by bytes (dest)
    by_dst = df.groupby("dst", dropna=True)["bytes"].sum().to_dict()
    top_dst = topk_heap(by_dst, k=20)
    pd.DataFrame(top_dst, columns=["dst", "bytes"]).to_csv(os.path.join(outdir, "top_talkers_dst.csv"), index=False)

    # 4) IPv4 integer radix sort demo (fast ascending inventory)
    v4_ints = [int(v) for v, fam in zip(df["src_int"], df["src_family"]) if fam == 4 and v is not None]
    v4_sorted = radix_sort_ip_ints(v4_ints, width_bytes=4)
    with open(os.path.join(outdir, "ipv4_sorted_inventory.txt"), "w") as f:
        for iv in v4_sorted:
            f.write(str(ipaddress.IPv4Address(iv)) + "\n")

    # 5) Service mix per device
    svc_mix_rows = []
    for dev, g in df.groupby("src"):
        mix = g["state"].value_counts().head(10)
        total = int(g["packets"].sum())
        bytes_total = int(g["bytes"].sum())
        for state, cnt in mix.items():
            svc_mix_rows.append({"device": dev, "state": state, "count": int(cnt), "packets_total": total, "bytes_total": bytes_total})
    pd.DataFrame(svc_mix_rows).to_csv(os.path.join(outdir, "service_mix_per_device.csv"), index=False)

# -----------------------------
# Markov analysis
# -----------------------------

def build_sequences(df: pd.DataFrame, within="1H") -> Dict[str, List[str]]:
    """
    Build per-device sequences of service 'states' in time order.
    We bucket by 'within' so very chatty devices don't create huge runs of identical states.
    """
    if "time" not in df.columns or df["time"].isna().all():
        return {}
    sequences = {}
    for dev, g in df.sort_values("time").groupby("src"):
        if g["time"].isna().all():
            continue
        # bucket and take the most common state per bucket to reduce noise
        gb = g.set_index("time").groupby(pd.Grouper(freq=within))
        seq = []
        for _, gg in gb:
            if gg.empty:
                continue
            # most frequent state in this bucket
            state = gg["state"].value_counts().idxmax()
            seq.append(state)
        if len(seq) >= 2:
            sequences[dev] = seq
    return sequences

def split_baseline_recent(df: pd.DataFrame, baseline_window: str, score_window: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    if "time" not in df.columns or df["time"].isna().all():
        return df.iloc[0:0], df.iloc[0:0]
    tmax = df["time"].max()
    baseline_start = tmax - pd.Timedelta(baseline_window) - pd.Timedelta(score_window)
    baseline_end = tmax - pd.Timedelta(score_window)
    recent_start = baseline_end
    baseline = df[(df["time"] >= baseline_start) & (df["time"] < baseline_end)]
    recent = df[(df["time"] >= recent_start) & (df["time"] <= tmax)]
    return baseline, recent

def markov_anomaly_scores(df: pd.DataFrame, baseline_window="7D", score_window="1D", bucket="1H", alpha=0.5) -> pd.DataFrame:
    baseline, recent = split_baseline_recent(df, baseline_window, score_window)
    if baseline.empty or recent.empty:
        return pd.DataFrame(columns=["device", "nll", "len", "note"])

    base_seqs = build_sequences(baseline, within=bucket)
    rec_seqs = build_sequences(recent, within=bucket)
    rows = []
    for dev, rec_seq in rec_seqs.items():
        base_seq = base_seqs.get(dev, [])
        if len(base_seq) < 2:
            rows.append({"device": dev, "nll": float("inf"), "len": len(rec_seq), "note": "No baseline; treating as suspicious"})
            continue
        model = MarkovModel.from_sequences([base_seq])
        nll = model.sequence_nll(rec_seq, alpha=alpha)
        rows.append({"device": dev, "nll": nll, "len": len(rec_seq), "note": ""})
    out = pd.DataFrame(rows).sort_values("nll", ascending=False)
    return out

# -----------------------------
# Report
# -----------------------------

def write_report(outdir: str, notes: List[str] = None):
    notes = notes or []
    report = os.path.join(outdir, "REPORT.md")
    with open(report, "w") as f:
        f.write("# SOHO IoT Monitor – Analyst Report\n\n")
        f.write(f"- Generated: {pd.Timestamp.utcnow()}\n")
        f.write(f"- Output folder: `{outdir}`\n\n")
        f.write("## What this does\n")
        f.write("- Builds fast summaries with counting/radix sorts (ports and IPv4).\n")
        f.write("- Models per-device service behavior with a first-order Markov chain.\n")
        f.write("- Scores the most recent window vs. baseline and flags the highest NLL (most surprising) devices.\n\n")
        f.write("## Artifacts\n")
        f.write("- `port_histogram.csv` – Port distribution (sorted by port via counting sort).\n")
        f.write("- `top_talkers_src.csv`, `top_talkers_dst.csv` – Heavy hitters by bytes.\n")
        f.write("- `ipv4_sorted_inventory.txt` – IPv4 sources sorted with radix sort.\n")
        f.write("- `service_mix_per_device.csv` – Top service states per device.\n")
        f.write("- `markov_anomalies.csv` – Recent-vs-baseline surprise scores (higher = more anomalous).\n\n")
        if notes:
            f.write("## Notes\n")
            for n in notes:
                f.write(f"- {n}\n")
            f.write("\n")
    return report

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="SOHO IoT Monitor – advanced sorting + Markov chains")
    ap.add_argument("command", choices=["analyze"], help="What to do")
    ap.add_argument("inputs", nargs="+", help="Input CSV files (flow stats)")
    ap.add_argument("--out", default="./out", help="Output directory")
    ap.add_argument("--baseline-window", default="7D", help="Time window for baseline (e.g., 7D)")
    ap.add_argument("--score-window", default="1D", help="Time window for recent scoring (e.g., 1D)")
    ap.add_argument("--bucket", default="1H", help="Time bucket for Markov sequences (e.g., 15min, 1H)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.command == "analyze":
        df = load_flows(args.inputs)
        summarize(df, args.out)
        scores = markov_anomaly_scores(df, baseline_window=args.baseline_window, score_window=args.score_window, bucket=args.bucket)
        scores.to_csv(os.path.join(args.out, "markov_anomalies.csv"), index=False)
        rep = write_report(args.out, notes=[
            "If your CSVs lack timestamps, Markov scoring will be empty. Add time to enable behavior modeling.",
            "Consider running with --bucket 30min for chatty IoT.",
        ])
        print(f"Wrote outputs to {args.out}")
        print(f"Report: {rep}")

if __name__ == "__main__":
    main()
