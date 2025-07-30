from fastapi import FastAPI
from scapy.all import sniff, TCP, UDP, IP
from collections import defaultdict, deque
from threading import Thread, Lock
from datetime import datetime
import pandas as pd
import time
import socket
import statistics
import os
import uvicorn

app = FastAPI()

flows = {}
flow_lock = Lock()
extracted_features = deque(maxlen=20)
flow_timeout = 30  # seconds
log_file_path = r"logs/flow_features_log.csv"

# Feature extraction helper
class Flow:
    def __init__(self, key):
        self.key = key  # (src, sport, dst, dport, proto)
        self.packets = []
        self.start_time = None
        self.end_time = None
        self.forward_packets = []
        self.backward_packets = []
        self.fwd_payload_bytes = 0
        self.bwd_payload_bytes = 0
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        self.forward_times = []
        self.backward_times = []
        self.all_times = []
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
        self.fwd_seg_sizes = []
        self.bwd_seg_sizes = []
        self.psh_flag_fwd = 0
        self.psh_flag_bwd = 0
        self.urg_flag_fwd = 0
        self.urg_flag_bwd = 0
        self.flags = defaultdict(int)
        self.init_win_fwd = 0
        self.init_win_bwd = 0
        self.active_times = []
        self.idle_times = []
        self.last_active = None

    def add_packet(self, pkt, direction):
        ts = time.time()
        if not self.start_time:
            self.start_time = ts
        self.end_time = ts

        if direction == 'fwd':
            self.forward_packets.append(pkt)
            self.forward_times.append(ts)
            self.total_fwd_bytes += len(pkt)
            self.fwd_header_len += pkt[IP].ihl * 4
            self.fwd_payload_bytes += len(pkt.payload)
            self.fwd_seg_sizes.append(len(pkt.payload))
            if TCP in pkt:
                if pkt[TCP].flags & 0x08:
                    self.psh_flag_fwd += 1
                if pkt[TCP].flags & 0x20:
                    self.urg_flag_fwd += 1
                if not self.init_win_fwd:
                    self.init_win_fwd = pkt[TCP].window
        else:
            self.backward_packets.append(pkt)
            self.backward_times.append(ts)
            self.total_bwd_bytes += len(pkt)
            self.bwd_header_len += pkt[IP].ihl * 4
            self.bwd_payload_bytes += len(pkt.payload)
            self.bwd_seg_sizes.append(len(pkt.payload))
            if TCP in pkt:
                if pkt[TCP].flags & 0x08:
                    self.psh_flag_bwd += 1
                if pkt[TCP].flags & 0x20:
                    self.urg_flag_bwd += 1
                if not self.init_win_bwd:
                    self.init_win_bwd = pkt[TCP].window

        if TCP in pkt:
            for flag, name in zip([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x80, 0x40],
                                  ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'CWR', 'ECE']):
                if pkt[TCP].flags & flag:
                    self.flags[name] += 1

        self.all_times.append(ts)

        # Active/Idle time
        if self.last_active:
            idle = ts - self.last_active
            if idle > 1:
                self.idle_times.append(idle)
            else:
                self.active_times.append(idle)
        self.last_active = ts

    def get_features(self):
        duration = (self.end_time - self.start_time) * 1e6 if self.end_time and self.start_time else 0
        total_packets = len(self.forward_packets) + len(self.backward_packets)
        total_bytes = self.total_fwd_bytes + self.total_bwd_bytes
        flow_bytes_per_sec = total_bytes / (self.end_time - self.start_time) if self.end_time != self.start_time else 0
        flow_packets_per_sec = total_packets / (self.end_time - self.start_time) if self.end_time != self.start_time else 0
        all_pkt_lens = [len(p) for p in self.forward_packets + self.backward_packets]

        def stats(arr):
            return {
                'min': min(arr) if arr else 0,
                'max': max(arr) if arr else 0,
                'mean': statistics.mean(arr) if arr else 0,
                'std': statistics.stdev(arr) if len(arr) > 1 else 0,
                'var': statistics.variance(arr) if len(arr) > 1 else 0
            }

        def time_stats(times):
            iats = [j - i for i, j in zip(times[:-1], times[1:])]
            return {
                'min': min(iats) if iats else 0,
                'max': max(iats) if iats else 0,
                'mean': statistics.mean(iats) if iats else 0,
                'std': statistics.stdev(iats) if len(iats) > 1 else 0,
                'total': sum(iats)
            }

        fwd_stats = stats([len(p) for p in self.forward_packets])
        bwd_stats = stats([len(p) for p in self.backward_packets])
        pkt_stats = stats(all_pkt_lens)
        flow_iat = time_stats(self.all_times)
        fwd_iat = time_stats(self.forward_times)
        bwd_iat = time_stats(self.backward_times)

        src_ip, src_port, dst_ip, dst_port, _ = self.key

        return {
            'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Src IP': src_ip,
            'Src Port': src_port,
            'Dst IP': dst_ip,
            'Dst Port': dst_port,
            'Flow Duration': duration,
            'Total Fwd Packet': len(self.forward_packets),
            'Total Bwd Packet': len(self.backward_packets),
            'Total Length of Fwd Packet': self.total_fwd_bytes,
            'Total Length of Bwd Packet': self.total_bwd_bytes,
            'Fwd Packet Length Min': fwd_stats['min'],
            'Fwd Packet Length Max': fwd_stats['max'],
            'Fwd Packet Length Mean': fwd_stats['mean'],
            'Fwd Packet Length Std': fwd_stats['std'],
            'Bwd Packet Length Min': bwd_stats['min'],
            'Bwd Packet Length Max': bwd_stats['max'],
            'Bwd Packet Length Mean': bwd_stats['mean'],
            'Bwd Packet Length Std': bwd_stats['std'],
            'Flow Bytes/s': flow_bytes_per_sec,
            'Flow Packets/s': flow_packets_per_sec,
            'Flow IAT Mean': flow_iat['mean'],
            'Flow IAT Std': flow_iat['std'],
            'Flow IAT Max': flow_iat['max'],
            'Flow IAT Min': flow_iat['min'],
            'Fwd IAT Total': fwd_iat['total'],
            'Fwd IAT Min': fwd_iat['min'],
            'Fwd IAT Max': fwd_iat['max'],
            'Fwd IAT Mean': fwd_iat['mean'],
            'Fwd IAT Std': fwd_iat['std'],
            'Bwd IAT Total': bwd_iat['total'],
            'Bwd IAT Min': bwd_iat['min'],
            'Bwd IAT Max': bwd_iat['max'],
            'Bwd IAT Mean': bwd_iat['mean'],
            'Bwd IAT Std': bwd_iat['std'],
            'Fwd PSH Flags': self.psh_flag_fwd,
            'Bwd PSH Flags': self.psh_flag_bwd,
            'Fwd URG Flags': self.urg_flag_fwd,
            'Bwd URG Flags': self.urg_flag_bwd,
            'Fwd Header Length': self.fwd_header_len,
            'Bwd Header Length': self.bwd_header_len,
            'Fwd Packets/s': len(self.forward_packets) / (self.end_time - self.start_time) if self.end_time != self.start_time else 0,
            'Bwd Packets/s': len(self.backward_packets) / (self.end_time - self.start_time) if self.end_time != self.start_time else 0,
            'Packet Length Min': pkt_stats['min'],
            'Packet Length Max': pkt_stats['max'],
            'Packet Length Mean': pkt_stats['mean'],
            'Packet Length Std': pkt_stats['std'],
            'Packet Length Variance': pkt_stats['var'],
            'FIN Flag Count': self.flags['FIN'],
            'SYN Flag Count': self.flags['SYN'],
            'RST Flag Count': self.flags['RST'],
            'PSH Flag Count': self.flags['PSH'],
            'ACK Flag Count': self.flags['ACK'],
            'URG Flag Count': self.flags['URG'],
            'CWR Flag Count': self.flags['CWR'],
            'ECE Flag Count': self.flags['ECE'],
            'Down/Up Ratio': len(self.backward_packets) / len(self.forward_packets) if self.forward_packets else 0,
            'Average Packet Size': statistics.mean(all_pkt_lens) if all_pkt_lens else 0,
            'Fwd Segment Size Avg': statistics.mean(self.fwd_seg_sizes) if self.fwd_seg_sizes else 0,
            'Bwd Segment Size Avg': statistics.mean(self.bwd_seg_sizes) if self.bwd_seg_sizes else 0,
            'Fwd Bytes/Bulk Avg': 0,
            'Fwd Packet/Bulk Avg': 0,
            'Fwd Bulk Rate Avg': 0,
            'Bwd Bytes/Bulk Avg': 0,
            'Bwd Packet/Bulk Avg': 0,
            'Bwd Bulk Rate Avg': 0,
            'Subflow Fwd Packets': len(self.forward_packets),
            'Subflow Fwd Bytes': self.total_fwd_bytes,
            'Subflow Bwd Packets': len(self.backward_packets),
            'Subflow Bwd Bytes': self.total_bwd_bytes,
            'Fwd Init Win Bytes': self.init_win_fwd,
            'Bwd Init Win Bytes': self.init_win_bwd,
            'Fwd Act Data Pkts': sum(1 for p in self.forward_packets if TCP in p and len(p[TCP].payload) > 0),
            'Fwd Seg Size Min': min(self.fwd_seg_sizes) if self.fwd_seg_sizes else 0,
            'Active Min': min(self.active_times) if self.active_times else 0,
            'Active Mean': statistics.mean(self.active_times) if self.active_times else 0,
            'Active Max': max(self.active_times) if self.active_times else 0,
            'Active Std': statistics.stdev(self.active_times) if len(self.active_times) > 1 else 0,
            'Idle Min': min(self.idle_times) if self.idle_times else 0,
            'Idle Mean': statistics.mean(self.idle_times) if self.idle_times else 0,
            'Idle Max': max(self.idle_times) if self.idle_times else 0,
            'Idle Std': statistics.stdev(self.idle_times) if len(self.idle_times) > 1 else 0
        }

def packet_callback(pkt):
    if IP in pkt:
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
        if proto == 'OTHER':
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt.sport if TCP in pkt or UDP in pkt else 0
        dport = pkt.dport if TCP in pkt or UDP in pkt else 0
        key_fwd = (src, sport, dst, dport, proto)
        key_bwd = (dst, dport, src, sport, proto)

        with flow_lock:
            if key_fwd in flows:
                flow = flows[key_fwd]
                direction = 'fwd'
            elif key_bwd in flows:
                flow = flows[key_bwd]
                direction = 'bwd'
            else:
                flow = Flow(key_fwd)
                flows[key_fwd] = flow
                direction = 'fwd'
            flow.add_packet(pkt, direction)

        now = time.time()
        expired_keys = []
        with flow_lock:
            for k, flow in flows.items():
                if now - flow.end_time > flow_timeout:
                    features = flow.get_features()
                    extracted_features.append(features)

                    # Log to CSV
                    df = pd.DataFrame([features])
                    if not os.path.isfile(log_file_path):
                        df.to_csv(log_file_path, index=False)
                    else:
                        df.to_csv(log_file_path, mode='a', header=False, index=False)

                    expired_keys.append(k)
            for k in expired_keys:
                del flows[k]

# Start packet capture in background
Thread(target=lambda: sniff(prn=packet_callback, store=False)).start()

@app.get("/extract_features")
def get_latest_features():
    with flow_lock:
        return {"flows": list(extracted_features)}

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
