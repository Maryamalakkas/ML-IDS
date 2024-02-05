from flask import Flask, jsonify
import threading
import os
from network_traffic_analysis import NetworkTrafficAnalysis  # Assuming your script is named network_traffic_analysis.py

path='../Model/decision_tree_model.joblib'

app = Flask(__name__)
capture_thread = None

@app.route('/start_capture', methods=['GET'])
def start_capture():
    global capture_thread
    if capture_thread is None or not capture_thread.is_alive():
        model_path = path
        analysis_system = NetworkTrafficAnalysis(model_path)
        
        capture_thread = threading.Thread(target=analysis_system.start_capture, daemon=True)
        capture_thread.start()
        return jsonify({"status": "Capture started"}), 200
    else:
        return jsonify({"status": "Capture is already running"}), 200

@app.route('/stop_capture', methods=['GET'])
def stop_capture():
    global capture_thread
    if capture_thread is not None and capture_thread.is_alive():
        model_path = path
        analysis_system = NetworkTrafficAnalysis(model_path)  # Define the analysis_system variable
        
        # You need to implement a method to stop the capture safely in your NetworkTrafficAnalysis class
        # This could be setting a flag that is checked by the process_packet method
        analysis_system.stop_capture()
        capture_thread.join()
        capture_thread = None
        return jsonify({"status": "Capture stopped"}), 200
    else:
        return jsonify({"status": "No capture is running"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
