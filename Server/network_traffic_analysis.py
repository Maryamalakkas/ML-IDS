from scapy.all import IP, TCP, UDP, sniff
import numpy as np
import joblib
from collections import defaultdict, Counter

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
        self.connections = defaultdict(lambda: {'src_bytes': 0, 'dst_bytes': 0, 'dst_host_srv_count': 0, 'dst_host_same_srv_rate': 0})
        self.dst_host_counts = Counter()

    def update_connection(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            src = (packet[IP].src, packet[TCP].sport if TCP in packet else packet[UDP].sport)
            dst = (packet[IP].dst, packet[TCP].dport if TCP in packet else packet[UDP].dport)
            key = src + dst

            if packet[IP].src == src[0]:
                self.connections[key]['src_bytes'] += len(packet)
            else:
                self.connections[key]['dst_bytes'] += len(packet)

            # Update counts for dst_host_srv_count
            self.dst_host_counts[dst] += 1
            for conn_key in self.connections:
                if conn_key[2:] == dst:
                    self.connections[conn_key]['dst_host_srv_count'] = self.dst_host_counts[dst]

            # Calculate dst_host_same_srv_rate
            total_connections_to_dst_host = sum(1 for k in self.connections if k[2] == dst[0])
            if total_connections_to_dst_host > 0:
                same_srv_rate = self.dst_host_counts[dst] / total_connections_to_dst_host
                for conn_key in self.connections:
                    if conn_key[2] == dst[0]:
                        self.connections[conn_key]['dst_host_same_srv_rate'] = same_srv_rate

class NetworkTrafficAnalysis:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)
        self.tracker = ConnectionTracker()

    def process_packet(self, packet):
        if IP not in packet:
            return
        
        protocol_type = encode_protocol(packet)
        self.tracker.update_connection(packet)
        
        for key, stats in self.tracker.connections.items():
            features = np.array([[protocol_type, stats['src_bytes'], stats['dst_bytes'], stats['dst_host_srv_count'], stats['dst_host_same_srv_rate']]])
            prediction = self.model.predict(features)[0]
            traffic_type = "Anomaly/Attack" if prediction == 1 else "Normal"
            print(f"Connection: {key}, Traffic Classification: {traffic_type}, " +
                  f"Features: protocol_type={protocol_type}, src_bytes={stats['src_bytes']}, " +
                  f"dst_bytes={stats['dst_bytes']}, dst_host_srv_count={stats['dst_host_srv_count']}, " +
                  f"dst_host_same_srv_rate={stats['dst_host_same_srv_rate']}")

    def start_capture(self):
        self.stop_sniff = False  # Add a stop condition attribute
        sniff(prn=self.process_packet, store=False, stop_filter=self.should_stop_sniff)
    def should_stop_sniff(self, packet):
        return self.stop_sniff  # This will stop sniffing when the flag is True
    def stop_capture(self):
        self.stop_sniff = True  # Set the flag to True to stop sniffing


# if __name__ == "__main__":
#     model_path = 'Model/decision_tree_model.joblib'
#     analysis_system = NetworkTrafficAnalysis(model_path)
#     analysis_system.start_capture()
# End of snippet