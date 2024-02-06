import tkinter as tk
from tkinter import ttk
from threading import Thread
from queue import Empty
from network_traffic_analysis import NetworkTrafficAnalysis, packet_info_queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Initialize counts for graph
normal_traffic_count = 0
attack_traffic_count = 0

class NetworkTrafficApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Network Traffic Analysis")
        self.geometry("1024x768")

        self.start_button = tk.Button(self, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(self, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10)

        # Treeview widget for tabular data
        self.tree = ttk.Treeview(self, columns=('Connection', 'Status', 'Prediction', 'Protocol Type', 'Src Bytes', 'Dst Bytes', 'Dst Host Srv Count', 'Dst Host Same Srv Rate'), show='headings')
        self.tree.grid(row=1, column=0, columnspan=2, sticky='nsew')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)

        # Figure for the matplotlib graph
        self.figure = plt.Figure(figsize=(6,5), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().grid(row=2, column=0, columnspan=2)

        # Initialize the analysis system
        self.analysis_system = NetworkTrafficAnalysis('Model/decision_tree_model.joblib')
        self.capture_thread = None
        self.ui_update_thread = Thread(target=self.update_ui_from_queue, daemon=True)
        self.ui_update_thread.start()

    def start_capture(self):
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.capture_thread = Thread(target=self.analysis_system.start_capture, daemon=True)
            self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()

    def update_ui_from_queue(self):
        global normal_traffic_count, attack_traffic_count
        while True:
            try:
                packet_info = packet_info_queue.get(timeout=1)
                self.display_packet_info(packet_info)
                
                # Update graph counts
                traffic_type = packet_info.split('\t')[1]
                if traffic_type == "Normal":
                    normal_traffic_count += 1
                else:
                    attack_traffic_count += 1
                self.update_graph()
            except Empty:
                continue

    def display_packet_info(self, packet_info):
        self.tree.insert('', tk.END, values=packet_info.split('\t'))
        self.tree.yview_moveto(1)

    def update_graph(self):
        # Clear the current graph
        self.ax.clear()
        
        # Data for plotting
        labels = 'Normal', 'Attack'
        sizes = [normal_traffic_count, attack_traffic_count]
        colors = ['green', 'red']
        
        # Plot
        self.ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        self.ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        self.canvas.draw()

if __name__ == "__main__":
    app = NetworkTrafficApp()
    app.mainloop()
