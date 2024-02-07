import threading
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from multiclass_network_traffic_analysis import NetworkTrafficAnalysis, packet_info_queue
import tkinter as tk
from tkinter import ttk
from threading import Thread
import queue
# Import your NetworkTrafficAnalysis class from your project code
from multiclass_network_traffic_analysis import NetworkTrafficAnalysis, packet_info_queue
attack_types = {
        'normal': 'Normal',
        'back': 'DoS',
        'buffer_overflow': 'U2R',
        'ftp_write': 'R2L',
        'guess_passwd': 'R2L',
        'imap': 'R2L',
        'ipsweep': 'Probe',
        'land': 'DoS',
        'loadmodule': 'U2R',
        'multihop': 'R2L',
        'neptune': 'DoS',
        'nmap': 'Probe',
        'perl': 'U2R',
        'phf': 'R2L',
        'pod': 'DoS',
        'portsweep': 'Probe',
        'rootkit': 'U2R',
        'satan': 'Probe',
        'smurf': 'DoS',
        'spy': 'R2L',
        'teardrop': 'DoS',
        'warezclient': 'R2L',
        'warezmaster': 'R2L'}
label_mapping = {
        0: 'normal',
        1: 'back',
        2: 'buffer_overflow',
        3: 'ftp_write',
        4: 'guess_passwd',
        5: 'imap',
        6: 'ipsweep',
        7: 'land',
        8: 'loadmodule',
        9: 'multihop',
        10: 'neptune',
        11: 'nmap',
        12: 'perl',
        13: 'phf',
        14: 'pod',
        15: 'portsweep',
        16: 'rootkit',
        17: 'satan',
        18: 'smurf',
        19: 'spy',
        20: 'teardrop',
        21: 'warezclient',
        22: 'warezmaster'
    }

def update_treeview(tree, queue):
    while True:
        if not queue.empty():
            data = queue.get()
            tree.insert('', 'end', values=data.split(", "))


def start_thread_for_capture(tree, analysis_system):
    threading.Thread(target=analysis_system.start_capture, daemon=True).start()
    threading.Thread(target=update_treeview, args=(tree, analysis_system.packet_info_queue), daemon=True).start()


# Setup Tkinter window
root = tk.Tk()
root.title("Network Traffic Analysis")

# Setup Treeview
columns = ('protocol_type', 'src_bytes', 'count', 'same_srv_rate', 'dst_host_diff_srv_rate', 'Specific Prediction', 'Broader Category')
tree = ttk.Treeview(root, columns=columns, show='headings')
for col in columns:
    tree.heading(col, text=col.replace('_', ' ').title())
    tree.column(col, anchor='center')
tree.pack(expand=True, fill='both')

# Buttons to start and stop capture
start_button = ttk.Button(root, text="Start Capture", command=lambda: start_thread_for_capture(tree, analysis_system))
start_button.pack(side=tk.LEFT, padx=(10, 0), pady=(5, 5))
stop_button = ttk.Button(root, text="Stop Capture")  # You need to implement the stop functionality
stop_button.pack(side=tk.RIGHT, padx=(0, 10), pady=(5, 5))

# Initialize your NetworkTrafficAnalysis class from your project code
analysis_system = NetworkTrafficAnalysis('Project/multiclass_decision_tree_model.joblib', attack_types, label_mapping)

# Start the GUI loop
root.mainloop()
