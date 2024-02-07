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

model_path = 'Project/multiclass_decision_tree_model.joblib'
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
analysis_system = NetworkTrafficAnalysis(model_path, attack_types,label_mapping)



def start_capture():
    # Start packet capture in a new thread to keep the GUI responsive
    capture_thread = Thread(target=analysis_system.start_capture)
    capture_thread.daemon = True
    capture_thread.start()

def stop_capture():
    # Implement stopping logic here
    pass

# A mapping from protocol numbers to names
protocol_names = {0: 'icmp', 1: 'tcp', 2: 'udp'}

def update_treeview():
    # Try to get packet info from the queue without blocking
    try:
        packet_info = packet_info_queue.get_nowait()
    except queue.Empty:
        pass  # If the queue is empty, just ignore
    else:
        # Process the packet info and extract values
        data = packet_info.split(', ')
        values = []
        for item in data:
            # ... your existing processing logic ...

        # Insert the processed values into the Treeview
             treeview.insert('', 'end', values=values)

        # Keep the Treeview to only the last 25 entries
        while len(treeview.get_children()) > 25:
            treeview.delete(treeview.get_children()[0])

    # Schedule the next update call to this function after 100ms
    root.after(100, update_treeview)

# Set up the main application window
root = tk.Tk()
root.title("Network Traffic Analysis")

# Add buttons
start_button = ttk.Button(root, text="Start Capture", command=start_capture)
start_button.pack(side='top', padx=5, pady=5)

stop_button = ttk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.pack(side='top', padx=5, pady=5)

# Set up the Treeview
columns = ('protocol_type', 'src_bytes', 'count', 'same_srv_rate', 'dst_host_diff_srv_rate', 'specific_prediction', 'broader_category')
treeview = ttk.Treeview(root, columns=columns, show='headings')
for col in columns:
    treeview.heading(col, text=col.replace('_', ' ').title())
    treeview.column(col, width=100, anchor='center')
treeview.pack(fill='both', expand=True)



# Start the GUI loop
root.mainloop()
