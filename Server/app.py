from flask import Flask, jsonify
import threading
from network_traffic_analysis import NetworkTrafficAnalysis # Make sure this is the correct import path

app = Flask(__name__)

# Create a shared instance of NetworkTrafficAnalysis
model_path = 'Model/decision_tree_model.joblib'  # Adjust the path if necessary
analysis_system = NetworkTrafficAnalysis(model_path)
capture_thread = None

@app.route('/start_capture', methods=['GET'])
def start_capture():
    global capture_thread
    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = threading.Thread(target=analysis_system.start_capture, daemon=True)
        capture_thread.start()
        return jsonify({"status": "Capture started"}), 200
    else:
        return jsonify({"status": "Capture is already running"}), 200

@app.route('/stop_capture', methods=['GET'])
def stop_capture():
    global capture_thread
    if capture_thread is not None and capture_thread.is_alive():
        analysis_system.stop_capture()  # You need to implement this method
        capture_thread.join()
        capture_thread = None
        return jsonify({"status": "Capture stopped"}), 200
    else:
        return jsonify({"status": "No capture is running"}), 200

if __name__ == '__main__':

    app.run(debug=True)

