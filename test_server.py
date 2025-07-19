from flask import Flask, request, send_from_directory, abort
import os

app = Flask(__name__)

# Configure writable directories
UPLOAD_DIRS = {
    'uploads': {'confirm': True},  # Normal behavior (PUT+GET)
    'files': {'confirm': True},    # Normal behavior
    'webapps': {'confirm': False}  # Manual review case (PUT succeeds, GET fails)
}

# Create directories
for dir_name in UPLOAD_DIRS:
    os.makedirs(dir_name, exist_ok=True)

@app.route('/<path:directory>/<path:filename>', methods=['PUT', 'GET'])
def handle_file(directory, filename):
    # Check if directory is configured
    if directory not in UPLOAD_DIRS:
        abort(404)

    file_path = os.path.join(directory, filename)

    if request.method == 'PUT':
        with open(file_path, 'wb') as f:
            f.write(request.data)
        return '', 201

    elif request.method == 'GET':
        # Force manual review for webapps directory
        if not UPLOAD_DIRS[directory]['confirm']:
            abort(404)  # Intentionally fail GET
        if os.path.exists(file_path):
            return send_from_directory(directory, filename)
        abort(404)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
