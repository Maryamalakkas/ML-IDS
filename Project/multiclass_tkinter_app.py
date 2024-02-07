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
import logging

# Initialize logging
logging.basicConfig(level=logging.DEBUG)
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


class NetworkTrafficApp(tk.Tk):
     def __init__(self):
        super().__init__()
        self.title("Network Traffic Analysis")
        self.geometry("1024x768")
        self.capture_thread = None

        self.start_button = tk.Button(self, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(self, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10)
        self.tree = ttk.Treeview(self, columns = ('protocol_type', 'src_bytes', 'count', 'same_srv_rate', 'dst_host_diff_srv_rate', 'specific_prediction', 'broader_category'), show='headings')
        self.tree.grid(row=1, column=0, columnspan=2, sticky='nsew')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)

        self.analysis_system = NetworkTrafficAnalysis(model_path, attack_types,label_mapping)
        self.ui_update_thread = Thread(target=self.update_ui_from_queue, daemon=True)
        self.ui_update_thread.start()


def start_capture(self):
        # Start the capture in a separate thread to avoid blocking the GUI
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.capture_thread = Thread(target=self.analysis_system.start_capture, daemon=True)
            self.capture_thread.start()
            self.after(100, self.update_ui_from_queue) 


def stop_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()

def update_ui_from_queue(self):
        try:
            # Try to get packet info from the queue without blocking
            packet_info = packet_info_queue.get_nowait()
            self.display_packet_info(packet_info)
        except queue.Empty:
            pass  # If the queue is empty, do nothing
        finally:
            # Schedule the next update after 100ms
            self.after(100, self.update_ui_from_queue)

def display_packet_info(self, packet_info):
        self.tree.insert('', tk.END, values=packet_info.split('\t'))
        # Auto-scroll to the bottom
        self.tree.yview_moveto(1)


if __name__ == "__main__":
    app = NetworkTrafficApp()
    app.mainloop()
