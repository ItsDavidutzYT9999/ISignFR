from flask import Flask, request, jsonify
import os
import logging

app = Flask(__name__)

# Set logger level to WARNING to reduce noise but still show important logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

@app.route('/')
def home():
    return 'ISignFR server is running smoothly ✅', 200

@app.route('/sign', methods=['POST'])
def sign_ipa():
    return jsonify({'message': 'Sign endpoint received your request!'}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting ISignFR server on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
