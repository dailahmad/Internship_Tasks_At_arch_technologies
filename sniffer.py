#!/usr/bin/env python3
import argparse
import signal
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, conf

#Configuration/Globals
PRINT_EVERY = 10  # print stats every N packets
PAYLOAD_PRINT_BYTES = 256  # how many payload bytes to show if printing
stats = {
    "total": 0,
    "protocols": Counter(),
    "src_ips": Counter(),
    "dst_ips": Counter(),
    "dst_ports": Counter(),
    "src_ports": Counter(),
}
recent_packets = deque(maxlen=100)  
csv_file = None
stop_sniffing = False


#Utility parsing functions
def safe_decode_payload(payload_bytes):
    """Try to decode bytes to text without crashing; fallback to repr."""
    try:
        return payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        return repr(payload_bytes)


def extract_http_info(tcp_payload_bytes):
    """
    Very lightweight HTTP request-line + Host extraction.
    Not a full HTTP parser — just looks for common ascii request patterns.
    """
    text = safe_decode_payload(tcp_payload_bytes)
    lines = text.splitlines()
    if not lines:
        return None
    first = lines[0].strip()
    # HTTP request-lines look like: GET /path HTTP/1.1
    if first.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ")):
        host = None
        for line in lines[1:8]:  # check first few header lines
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return {"request_line": first, "host": host}
    return None


#Packet handler
def handle_packet(pkt):
    """
    Callback for each sniffed packet.
    Updates global stats and optionally logs packet summaries.
    """
    global stats, csv_file
    stats["total"] += 1

    summary = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "eth_src": None,
        "eth_dst": None,
        "proto": None,
        "src": None,
        "dst": None,
        "sport": None,
        "dport": None,
        "len": len(pkt),
        "extra": None,
    }

    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        summary["eth_src"] = eth.src
        summary["eth_dst"] = eth.dst

    # IPv4 / IPv6
    if IP in pkt:
        ip = pkt[IP]
        summary["proto"] = ip.proto  # numeric
        summary["src"] = ip.src
        summary["dst"] = ip.dst
        stats["src_ips"][ip.src] += 1
        stats["dst_ips"][ip.dst] += 1
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        # For simplicity use 'ipv6' as proto name
        summary["proto"] = "ipv6"
        summary["src"] = ip.src
        summary["dst"] = ip.dst
        stats["src_ips"][ip.src] += 1
        stats["dst_ips"][ip.dst] += 1

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        summary["sport"] = tcp.sport
        summary["dport"] = tcp.dport
        stats["src_ports"][tcp.sport] += 1
        stats["dst_ports"][tcp.dport] += 1
        stats["protocols"]["TCP"] += 1
        # Try simple HTTP detection
        if Raw in pkt and pkt[Raw].load:
            http = extract_http_info(pkt[Raw].load)
            if http:
                summary["extra"] = f"HTTP {http['request_line']} Host:{http['host']}"
            else:
                # optionally include a short preview of payload (safe)
                payload_preview = safe_decode_payload(pkt[Raw].load[:PAYLOAD_PRINT_BYTES])
                summary["extra"] = f"PAYLOAD({len(pkt[Raw].load)}b): {payload_preview!s}"
    # UDP
    elif UDP in pkt:
        udp = pkt[UDP]
        summary["sport"] = udp.sport
        summary["dport"] = udp.dport
        stats["src_ports"][udp.sport] += 1
        stats["dst_ports"][udp.dport] += 1
        stats["protocols"]["UDP"] += 1
    # ICMP
    elif ICMP in pkt:
        stats["protocols"]["ICMP"] += 1
        summary["extra"] = f"ICMP type={pkt[ICMP].type}"
    else:
        # non-IP or other protocols
        stats["protocols"]["OTHER"] += 1

    recent_packets.appendleft(summary)

    # optional CSV logging
    if csv_file:
        try:
            csv_file.write(
                f'{summary["ts"]},{summary["src"]},{summary["dst"]},{summary["sport"]},{summary["dport"]},{summary["len"]},"{summary["extra"] or ""}"\n'
            )
        except Exception:
            pass

    # Periodic printing
    if stats["total"] % PRINT_EVERY == 0:
        print_live_stats()


#Live stats
def print_live_stats():
    """Print a compact live summary to stdout."""
    print("\n--- Live stats ({} packets) ---".format(stats["total"]))
    # Protocol counts
    proto_lines = ", ".join(f"{k}:{v}" for k, v in stats["protocols"].most_common(6))
    print("Protocols:", proto_lines)
    # Top 5 source IPs
    top_src = stats["src_ips"].most_common(5)
    if top_src:
        print("Top src IPs:", ", ".join(f"{ip}({c})" for ip, c in top_src))
    # Top 5 destination ports
    top_ports = stats["dst_ports"].most_common(5)
    if top_ports:
        print("Top dst ports:", ", ".join(f"{p}({c})" for p, c in top_ports))
    # Last few packets
    print("Recent packets:")
    for pkt in list(recent_packets)[:5]:
        src = pkt["src"] or pkt["eth_src"] or "-"
        dst = pkt["dst"] or pkt["eth_dst"] or "-"
        proto = pkt["proto"]
        extra = pkt["extra"] or ""
        print(f" {src} -> {dst}  proto={proto} len={pkt['len']} {extra}")
    print("-" * 36)


#Signal handler for graceful shutdown
def handle_sigint(signal_num, frame):
    global stop_sniffing
    print("\nCaught interrupt — stopping sniffing...")
    stop_sniffing = True
    # Scapy's sniff is blocking; raising SystemExit will stop main thread after sniff returns.
    # We'll rely on sniff's stop_filter to exit cleanly.


#Stop filter passed to sniff()
def stop_filter(pkt):
    # stop when global flag set
    return stop_sniffing


#CLI and main
def main():
    global csv_file

    parser = argparse.ArgumentParser(description="Educational Python network sniffer (Scapy).")
    parser.add_argument("-i", "--iface", required=True, help="Interface to sniff on (e.g., eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--no-promisc", action="store_true", help="Do not enable promiscuous mode")
    parser.add_argument("--csv", help="Write a simple CSV log to this file")
    parser.add_argument("--filter", default=None, help="BPF filter (optional, e.g., 'tcp and port 80')")
    args = parser.parse_args()

    # Open CSV file if asked
    if args.csv:
        csv_file = open(args.csv, "w", buffering=1)
        csv_file.write("timestamp,src,dst,sport,dport,length,extra\n")

    # Set Scapy conf
    if args.no_promisc:
        conf.sniff_promisc = False
    else:
        conf.sniff_promisc = True

    print(f"Starting sniffer on interface {args.iface} (promisc={conf.sniff_promisc})")
    print("Press Ctrl-C to stop and show summary.")

    # Install signal handler
    signal.signal(signal.SIGINT, handle_sigint)

    # Start sniffing
    try:
        sniff(
            iface=args.iface,
            prn=handle_packet,
            count=args.count or 0,
            store=False,
            filter=args.filter,
            stop_filter=stop_filter,
        )
    except PermissionError:
        print("Permission denied: you probably need to run this script with root/Administrator privileges.")
        sys.exit(2)
    except Exception as e:
        print("Error during sniffing:", e)
        sys.exit(2)
    finally:
        if csv_file:
            csv_file.close()

    # Print final summary
    print_summary()


def print_summary():
    print("\n=== Final summary ===")
    print(f"Total packets: {stats['total']}")
    print("Protocol counts:")
    for proto, count in stats["protocols"].most_common():
        print(f"  {proto}: {count}")
    print("Top 10 source IPs:")
    for ip, c in stats["src_ips"].most_common(10):
        print(f"  {ip}: {c}")
    print("Top 10 destination IPs:")
    for ip, c in stats["dst_ips"].most_common(10):
        print(f"  {ip}: {c}")
    print("Top destination ports:")
    for port, c in stats["dst_ports"].most_common(10):
        print(f"  {port}: {c}")
    print("Recent packet examples:")
    for pkt in list(recent_packets)[:10]:
        print(pkt)
    print("Done.")


if __name__ == "__main__":
    main()
