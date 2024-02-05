from flask import Flask, request, jsonify
import joblib
from pathlib import Path

app = Flask(__name__)

# Adjust the relative path to where your model is saved within the `Model` directory.
model_path = Path(__file__).parent.parent / 'Model' / 'your_model_filename.joblib'
model = joblib.load(model_path)

@app.route('/predict', methods=['POST'])
def predict():
    # Here, you'll need to extract the data from the request
    # and format it in the way your model expects.
    data = request.get_json()

    # Perform the prediction using your model.
    # You may need to process the data into the correct format your model expects.
    # This is just an example and needs to be adapted to your specific model's needs.
    prediction = model.predict([data['feature_vector']])

    # Return the result in JSON format.
    return jsonify({'prediction': prediction.tolist()})

if __name__ == '__main__':
    # Run the Flask app.
    app.run(debug=True, port=5000)  # You can change the port if needed.
