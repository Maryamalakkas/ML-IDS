from flask import Flask, render_template, request, jsonify
import threading
from backend.traffic_analysis import NetworkTrafficAnalysis
from queue import Queue

app = Flask(__name__)

# Initialize the NetworkTrafficAnalysis system
# Replace the model_path with the path to your trained model
model_path = "/Users/maryam/ML-IDS/Project_1/models/multiclass_decision_tree_model.joblib"
# Define your attack_types and label_mapping as in the original code
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
        'warezmaster': 'R2L'} # Add your attack types mapping here
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
    }  # Add your label mapping here
analysis_system = NetworkTrafficAnalysis(model_path, attack_types, label_mapping)
packet_info_queue = analysis_system.get_queue()# Define the packet_info_queue
@app.route('/')
def index():
    results_list = []
    while not packet_info_queue.empty():
        item = packet_info_queue.get()
        results_list.append({
            'src_ip': item[0],
            'dst_ip': item[1],
            'protocol_type': item[2],
            'src_bytes': item[3],
            'count': item[4],
            'dst_host_same_srv_rate': item[5],
            'dst_host_diff_srv_rate': item[6],
            'specific_category': item[7],
            'broader_category': item[8]
        })
    return render_template('index.html', results=results_list)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    # Start packet capture in a new thread to keep the Flask server responsive
    if analysis_system.capture_thread is None or not analysis_system.capture_thread.is_alive():
        analysis_system.start_capture()
        return jsonify({'status': 'Capture started'}), 200
    else:
        return jsonify({'status': 'Capture already running'}), 400

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    analysis_system.stop_capture()
    return jsonify({'status': 'Capture stopped'}), 200


@app.route('/get_results')
def get_results():
    results_list = []
    # You might want to limit the number of results to prevent large transfers
    while not packet_info_queue.empty():
        item = packet_info_queue.get()
        results_list.append({
            'src_ip': item[0],
            'dst_ip': item[1],
            'protocol_type': item[2],
            'src_bytes': item[3],
            'count': item[4],
            'dst_host_same_srv_rate': item[5],
            'dst_host_diff_srv_rate': item[6],
            'specific_category': item[7],
            'broader_category': item[8]
        })
    return jsonify(results_list)
if __name__ == '__main__':
    app.run(debug=True, port=5000)
