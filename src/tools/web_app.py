
#!/usr/bin/env python3
"""
Flask Web Application for C2 Traffic Detection System
"""

import os
import json
import uuid
import logging
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for

from c2_detector import AdvancedC2Detector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Please upload a PCAP file.'}), 400
        
        # Generate unique filename
        analysis_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{analysis_id}_{filename}")
        
        # Save uploaded file
        file.save(file_path)
        logger.info(f"File uploaded: {file_path}")
        
        # Perform analysis
        detector = AdvancedC2Detector()
        
        if detector.analyze_pcap(file_path):
            report = detector.generate_report()
            
            # Save results
            results_file = os.path.join(app.config['RESULTS_FOLDER'], f"{analysis_id}_results.json")
            with open(results_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Analysis completed for {filename}")
            
            # Clean up uploaded file
            os.remove(file_path)
            
            return jsonify({
                'analysis_id': analysis_id,
                'filename': filename,
                'report': report
            })
        
        else:
            # Clean up uploaded file on error
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'error': 'Failed to analyze PCAP file'}), 500
    
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/results/<analysis_id>')
def get_results(analysis_id):
    """Get analysis results by ID"""
    try:
        results_file = os.path.join(app.config['RESULTS_FOLDER'], f"{analysis_id}_results.json")
        
        if not os.path.exists(results_file):
            return jsonify({'error': 'Results not found'}), 404
        
        with open(results_file, 'r') as f:
            report = json.load(f)
        
        return jsonify(report)
    
    except Exception as e:
        logger.error(f"Error retrieving results: {str(e)}")
        return jsonify({'error': 'Failed to retrieve results'}), 500

@app.route('/analyze')
def analyze_page():
    """Analysis page"""
    return render_template('analyze.html')

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 100MB.'}), 413

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
