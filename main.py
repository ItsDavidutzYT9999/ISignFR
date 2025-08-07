from flask import Flask, render_template
import os
import logging

app = Flask(__name__)

# Dezactivează logging-ul Flask la nivel INFO (asta reduce mesajele din consolă)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=5000, debug=False)
