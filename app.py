from flask import Flask, request, redirect, url_for, render_template
import os
from server import main as analyze_threats
import requests
import json

app = Flask(__name__)
DATASET_FOLDER = 'datasets'  # Use the existing datasets folder
app.config['DATASET_FOLDER'] = DATASET_FOLDER

# Ensure the dataset folder exists
os.makedirs(DATASET_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if file:
        file_path = os.path.join(app.config['DATASET_FOLDER'], file.filename)
        file.save(file_path)
        # Redirect to analysis page with the uploaded file path
        return redirect(url_for('analyze', file_path=file_path))

@app.route('/analyze')
def analyze():
    file_path = request.args.get('file_path')
    if not file_path:
        return "No file provided for analysis", 400
    try:
        analyze_threats(file_path)
        # Fetch alerts from Elasticsearch and save to alerts.json
        es_url = "http://elasticsearch:9200/threat-alerts/_search?pretty"
        response = requests.get(es_url)
        response.raise_for_status()
        alerts_data = response.json()
        os.makedirs('alerts', exist_ok=True)
        dataset_name = os.path.splitext(os.path.basename(file_path))[0]
        alerts_file = f'alerts/{dataset_name}_alerts.json'
        with open(alerts_file, 'w') as f:
            json.dump(alerts_data, f, indent=2)
    except Exception as e:
        print(f"Error during analysis: {e}")
        return f"Internal Server Error: {e}", 500
    return render_template('analyze.html', file_path=file_path)

@app.route('/elasticsearch-raw')
def elasticsearch_raw():
    return redirect("http://localhost:9200")  # Update with your Elasticsearch URL

@app.route('/elasticsearch')
def elasticsearch():
    try:
        es_url = "http://elasticsearch:9200/threat-alerts/_search?pretty"
        response = requests.get(es_url)
        response.raise_for_status()
        alerts_data = response.json()
        return render_template('elasticsearch_results.html', alerts=alerts_data)
    except Exception as e:
        return f"Error loading alerts from Elasticsearch: {e}", 500

@app.route('/kibana')
def kibana():
    return redirect("http://localhost:5601")  # Update with your Kibana URL

@app.route('/thehive')
def thehive():
    return redirect("http://localhost:9000")  # Update with your TheHive URL

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)