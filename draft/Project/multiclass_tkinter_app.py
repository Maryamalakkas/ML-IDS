import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from threading import Thread
import queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from multiclass_network_traffic_analysis import NetworkTrafficAnalysis, packet_info_queue


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
protocol_names = {0: 'ICMP', 1: 'TCP', 2: 'UDP'}


class NetworkTrafficApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analysis")

        # Get the screen dimension
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        # Set the window size to the screen dimension
        # self.geometry(f'{screen_width}x{screen_height}+0+0')
        self.capture_thread = None
        # self.capture_thread.join()

        
        # Create a frame for the buttons
        button_frame = tk.Frame(self)
        button_frame.grid(row=0, column=0, sticky='ew')
        # This will make the frame expand to fill the width of the window
        self.grid_columnconfigure(0, weight=1)

        # Buttons are set to expand and fill space
        self.start_button = tk.Button(button_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side='left', expand=True, fill='x')
        self.stop_button = tk.Button(button_frame, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack(side='left', expand=True, fill='x')
    
        # Initialize the Treeview
        self.tree = ttk.Treeview(self, columns=('src_ip', 'dst_ip', 'protocol_type', 'src_bytes', 'count', 'same_srv_rate', 'dst_host_diff_srv_rate', 'specific_prediction', 'broader_category'), show='headings')
        self.tree.grid(row=1, column=0, sticky='nsew')
        # Configure the grid to allow the Treeview to expand
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor='center')
            self.tree.column(col, stretch=True)

        # Create and set up the scrollbar for the Treeview
        self.tree_scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree_scroll.grid(row=1, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=self.tree_scroll.set)
        self.grid_rowconfigure(1, weight=1)  # Makes the Treeview expandable

        # Initialize the analysis system and UI update thread
        self.analysis_system = NetworkTrafficAnalysis(model_path, attack_types, label_mapping)
        self.ui_update_thread = Thread(target=self.update_ui_from_queue, daemon=True)
        self.ui_update_thread.start()
      

        # Set up the figure
        self.fig = Figure(figsize=(6, 6), dpi=100)
        self.ax_pie = self.fig.add_subplot(111)
        
        
        # Embed the figure in the Tkinter window
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)  # A tk.DrawingArea.
        self.canvas.draw()
        self.canvas.get_tk_widget().grid(row=2, column=0, columnspan=2, sticky='nsew')
        
        # Initialize the data for the graph
        self.categories = ['Normal', 'DoS', 'U2R', 'R2L', 'Probe']
        self.data = [0, 0, 0, 0, 0]  # Initialize with zeros or appropriate data
        self.category_counts = {category: 0 for category in self.categories}
        
        # Start the periodic update
        self.update_graph()


 
    def start_capture(self):
        if self.capture_thread is None or not self.capture_thread.is_alive():
            # Initialize and start the capture thread only if it hasn't been started or if it's not alive
            self.capture_thread = Thread(target=self.analysis_system.start_capture, daemon=True)
            self.capture_thread.start()
        else:
            print("Capture is already running.")


    def stop_capture(self):
            self.capture_thread= Thread(target=self.analysis_system.stop_capture_filter, daemon=True)
            self.capture_thread.start()
    





    def update_ui_from_queue(self):
        try:
            packet_info = packet_info_queue.get_nowait()
            self.display_packet_info(packet_info)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.update_ui_from_queue)


    def display_packet_info(self, packet_info):
    # Extract the source and destination IP addresses
        src_ip, dst_ip = packet_info[0], packet_info[1]

    # Convert the protocol number to a name using the protocol_names mapping
        protocol_name = protocol_names.get(packet_info[2], 'Unknown')

    # Create a new tuple with the protocol name instead of the number, and including the IPs
        updated_packet_info = (src_ip, dst_ip, protocol_name) + packet_info[3:]
        self.tree.insert('', tk.END, values=updated_packet_info)
        category = packet_info[-1]  # Assuming the last item is the broader category
        if category in self.category_counts:
            self.category_counts[category] += 1
        self.tree.yview_moveto(1)
        



    def update_graph(self):
    # Ensure data is free of NaNs and safely convert to integers
        self.data = [int(self.category_counts.get(category, 0)) for category in self.categories]

    # Filter categories and data for non-zero values
        non_zero_data = [(data, category) for data, category in zip(self.data, self.categories) if data > 0]

    # Unzip the data and categories
        filtered_data, filtered_categories = zip(*non_zero_data) if non_zero_data else ([], [])

    # Clear the previous pie chart
        self.ax_pie.clear()

    # Check if we have non-zero data to plot
        if filtered_data:
        # Draw the new pie chart with the actual data
            self.ax_pie.pie(filtered_data, labels=filtered_categories, autopct='%1.1f%%', startangle=140)
            self.ax_pie.axis('equal')  # Equal aspect ratio ensures the pie chart is circular.
        else:
        # If all data is zero, we output 'No Data' in the center of the pie chart area
            self.ax_pie.text(0.5, 0.5, 'No Data', horizontalalignment='center', verticalalignment='center', transform=self.ax_pie.transAxes)

    # Refresh the canvas
        self.canvas.draw()

    # Schedule the next update
        self.after(1000, self.update_graph)

if __name__ == "__main__":
    app = NetworkTrafficApp()
    app.mainloop()
    


