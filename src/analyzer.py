import threading
import socket
import csv
from scapy.all import sniff, IP, TCP, UDP, ICMP

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

class PacketAnalyzer:
    def __init__(self, callback):
        self.callback = callback
        self.sniff_thread = None
        self.running = False
        self.paused = False
        self.packet_count = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.filter = ""
        self.captured_packets = []

    def start_capture(self, filter_str=""):
        if not self.running:
            self.running = True
            self.paused = False
            self.filter = filter_str
            self.packet_count = 0
            self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
            self.captured_packets = []
            self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_capture(self):
        self.running = False

    def pause_capture(self):
        self.paused = True

    def resume_capture(self):
        self.paused = False

    def export_txt(self, filename, data):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join([d['summary'] for d in data]))

    def export_csv(self, filename, data):
        with open(filename, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "Protocol", "Source", "Src Port", "Destination", "Dst Port", "Info"])
            for d in data:
                writer.writerow([
                    d["no"], d["proto"], d["src"], d["src_port"], d["dst"], d["dst_port"], d["info"]
                ])

    def _sniff_packets(self):
        sniff(prn=self._process_packet, store=0, stop_filter=lambda x: not self.running, filter=self.filter)

    def _process_packet(self, packet):
        if self.paused:
            return
        if IP in packet:
            proto_num = packet[IP].proto
            proto = PROTOCOLS.get(proto_num, str(proto_num))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            try:
                src_host = socket.gethostbyaddr(src_ip)[0]
            except Exception:
                src_host = src_ip
            try:
                dst_host = socket.gethostbyaddr(dst_ip)[0]
            except Exception:
                dst_host = dst_ip

            src_port = dst_port = "-"
            if proto == "TCP" and TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif proto == "UDP" and UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            self.packet_count += 1
            if proto in self.protocol_counts:
                self.protocol_counts[proto] += 1
            else:
                self.protocol_counts["Other"] += 1

            info = f"{proto} {src_host}:{src_port} → {dst_host}:{dst_port}"
            summary = f"#{self.packet_count} | {proto} | {src_host}:{src_port} → {dst_host}:{dst_port}"
            packet_dict = {
                "no": self.packet_count,
                "proto": proto,
                "src": src_host,
                "src_port": src_port,
                "dst": dst_host,
                "dst_port": dst_port,
                "info": info,
                "summary": summary,
                "raw": packet
            }
            self.captured_packets.append(packet_dict)
            self.callback(packet_dict)