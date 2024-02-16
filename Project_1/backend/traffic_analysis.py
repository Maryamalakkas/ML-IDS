from scapy.all import IP, TCP, UDP, sniff
import numpy as np
import joblib
from collections import defaultdict, Counter
from queue import Queue
import time
import threading
from threading import Thread
import queue
import matplotlib.pyplot as plt
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np

import logging

# Initialize a queue for thread-safe communication
packet_info_queue = Queue()

def encode_protocol(packet):
    protocol_mapping = {'icmp': 0, 'tcp': 1, 'udp': 2}
    if IP in packet:
        if packet[IP].proto == 1:
            return protocol_mapping['icmp']
        elif packet[IP].proto == 6:
            return protocol_mapping['tcp']
        elif packet[IP].proto == 17:
            return protocol_mapping['udp']
    return -1

class ConnectionTracker:
    def __init__(self):
        self.connections = defaultdict(lambda: {
            'src_bytes': 0,
            'dst_bytes': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0,
            'count': 0,
            'dst_host_diff_srv_rate': 0,
            'timestamps': [],
            'services': set()
        })
        self.dst_host_counts = Counter()
        self.service_counts = defaultdict(Counter)

    def update_connection(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            src = (packet[IP].src, packet[TCP].sport if TCP in packet else packet[UDP].sport)
            dst = (packet[IP].dst, packet[TCP].dport if TCP in packet else packet[UDP].dport)
            service = packet[IP].dport  # Service is identified by the destination port
            key = src + dst

            if packet[IP].src == src[0]:
                self.connections[key]['src_bytes'] += len(packet)
            else:
                self.connections[key]['dst_bytes'] += len(packet)

            # Update the timestamp list and remove timestamps older than 2 seconds
            current_time = time.time()
            self.connections[key]['timestamps'] = [t for t in self.connections[key]['timestamps'] if current_time - t < 2]
            self.connections[key]['timestamps'].append(current_time)

            # Update the count for connections to the same destination host
            self.connections[key]['count'] = len(self.connections[key]['timestamps'])

            # Update services seen for this destination host
            self.connections[key]['services'].add(service)
            self.service_counts[dst[0]][service] += 1

            # Calculate dst_host_diff_srv_rate
            total_services = sum(self.service_counts[dst[0]].values())
            diff_services = len(self.service_counts[dst[0]])
            self.connections[key]['dst_host_diff_srv_rate'] = diff_services / total_services if total_services > 0 else 0

            # Calculate dst_host_same_srv_rate (assuming it's the rate of the same service)
            same_service_count = self.service_counts[dst[0]][service]
            self.connections[key]['dst_host_same_srv_rate'] = same_service_count / total_services if total_services > 0 else 0

class NetworkTrafficAnalysis:
    def __init__(self, model_path, attack_types, label_mapping):
        self.model = joblib.load(model_path)
        self.attack_types = attack_types
        self.label_mapping = label_mapping
        self.tracker = ConnectionTracker()
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.capture_thread = None
 
    def process_packet(self, packet):
        if self.pause_event.is_set():
            return
        if IP not in packet:
            return

        protocol_type = encode_protocol(packet)
        self.tracker.update_connection(packet)

        src_ip = packet[IP].src  # Capture source IP address
        dst_ip = packet[IP].dst  # Capture destination IP address

        for key, stats in self.tracker.connections.items():
            # Assuming 'count' and 'dst_host_diff_srv_rate' are calculated within update_connection
            count = stats.get('count', 0)
            dst_host_diff_srv_rate = stats.get('dst_host_diff_srv_rate', 0)
            features = np.array([[protocol_type, stats['src_bytes'], count, 
                              stats['dst_host_same_srv_rate'], dst_host_diff_srv_rate]])
            numerical_prediction = self.model.predict(features)[0]
            specific_category = self.label_mapping[numerical_prediction]  # Translate to string label  # Translate to string label
            broader_category = self.attack_types.get(specific_category, "Unknown")
            output = (
    src_ip,  # Include source IP address
    dst_ip,  # Include destination IP address
    protocol_type,
    stats['src_bytes'],
    count,
    stats['dst_host_same_srv_rate'],
    dst_host_diff_srv_rate,
    specific_category,
    broader_category)
            packet_info_queue.put(output)
            print(output)

    
    def stop_capture_filter(self, packet):
        return self.stop_event.is_set()  # Corrected logic to actually stop the capture based on the event
 
    def start_capture(self):
        if self.capture_thread is None or not self.capture_thread.is_alive():
            self.stop_event.clear()
            self.capture_thread = Thread(target=lambda: sniff(prn=self.process_packet, store=False, stop_filter=self.stop_capture_filter))
            self.capture_thread.start()

    def stop_capture(self):
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join()
            self.capture_thread = None

    def get_queue(self):
        return packet_info_queue
 
# if __name__ == "__main__":
#     model_path = '/Users/shahadaleissa/ML-IDS/Project/multiclass_decision_tree_model.joblib'
#     attack_types = {
#         'normal': 'Normal',
#         'back': 'DoS',
#         'buffer_overflow': 'U2R',
#         'ftp_write': 'R2L',
#         'guess_passwd': 'R2L',
#         'imap': 'R2L',
#         'ipsweep': 'Probe',
#         'land': 'DoS',
#         'loadmodule': 'U2R',
#         'multihop': 'R2L',
#         'neptune': 'DoS',
#         'nmap': 'Probe',
#         'perl': 'U2R',
#         'phf': 'R2L',
#         'pod': 'DoS',
#         'portsweep': 'Probe',
#         'rootkit': 'U2R',
#         'satan': 'Probe',
#         'smurf': 'DoS',
#         'spy': 'R2L',
#         'teardrop': 'DoS',
#         'warezclient': 'R2L',
#         'warezmaster': 'R2L'}
#     label_mapping = {
#         0: 'normal',
#         1: 'back',
#         2: 'buffer_overflow',
#         3: 'ftp_write',
#         4: 'guess_passwd',
#         5: 'imap',
#         6: 'ipsweep',
#         7: 'land',
#         8: 'loadmodule',
#         9: 'multihop',
#         10: 'neptune',
#         11: 'nmap',
#         12: 'perl',
#         13: 'phf',
#         14: 'pod',
#         15: 'portsweep',
#         16: 'rootkit',
#         17: 'satan',
#         18: 'smurf',
#         19: 'spy',
#         20: 'teardrop',
#         21: 'warezclient',
#         22: 'warezmaster'
#     }
#     analysis_system = NetworkTrafficAnalysis(model_path, attack_types, label_mapping)
    # Use threading properly
    # capture_thread = threading.Thread(target=analysis_system.start_capture, daemon=True)
    # capture_thread.start()
   

  

