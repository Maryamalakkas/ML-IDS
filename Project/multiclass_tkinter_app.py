import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import threading
import csv
import queue
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import pandas as pd
import threading
import queue
from multiclass_network_traffic_analysis import ConnectionTracker, NetworkTrafficAnalysis   


# Your existing classes and functions here (ConnectionTracker, NetworkTrafficAnalysis, etc.)
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

class NetworkTrafficApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analysis")
        # Initialize tree frame
        self.tree_frame = ttk.Frame(root)
        self.tree_frame.pack()

        # Setup GUI components
        self.start_button = ttk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.pack()

        self.stop_button = ttk.Button(root, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack()

        self.save_button = ttk.Button(root, text="Save to CSV", command=self.save_to_csv)
        self.save_button.pack()

        # Tree View for packet data
        self.tree = ttk.Treeview(self.tree_frame, columns=("Protocol", "Src Bytes", "Count", "Service Rate", "Prediction", "Category"), show='headings')
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor=tk.CENTER)  # Adjust the width as necessary

        self.tree.pack()

        # Graph for live data visualization
        self.graph_frame = ttk.Frame(root)
        self.graph_frame.pack()
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack()

        # Initialize packet capture system and threading
        self.analysis_system = NetworkTrafficAnalysis('Project/multiclass_decision_tree_model.joblib', attack_types, label_mapping)
        self.packet_capture_thread = None
        self.packet_info_queue = queue.Queue()

        # Start the update process for the GUI
        self.update_gui()

    

    def start_capture(self):
        if self.packet_capture_thread is None:
            self.packet_capture_thread = threading.Thread(target=self.analysis_system.start_capture)
            self.packet_capture_thread.start()

    def stop_capture(self):
        if self.packet_capture_thread:
            # Implement a way to stop the sniffing thread safely

            self.packet_capture_thread = None

    def save_to_csv(self):
        # Logic to save packet data to a CSV file
        pass

    def update_gui(self):
        # Update the tree view and graphs here
        # Call this method periodically
        self.root.after(1000, self.update_gui)

    def update_tree_view(self):
        # Clear existing data in the tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Fetch new data from the queue and insert it into the tree
        while not self.packet_info_queue.empty():
            packet_data = self.packet_info_queue.get()
            self.tree.insert("", tk.END, values=packet_data)

    def animate_graph(self, frame):
        # Update the graph with multiclass data
        # You might want to clear the graph and redraw with new data
        
        self.ax.clear()

    def setup_live_graph(self):
        self.animation = FuncAnimation(self.fig, self.animate_graph, interval=1000)
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficApp(root)
    root.mainloop()


    