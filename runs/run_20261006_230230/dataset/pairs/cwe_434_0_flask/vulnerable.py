def build_app(upload_dir: str, max_bytes: int=1024 * 1024):
    from pathlib import Path
    from flask import Flask, abort, jsonify, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'
    base_dir = Path(upload_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    @app.post('/upload')
    def upload():
        uploaded_file = request.files.get('file')
        if uploaded_file is None:
            abort(400)
        destination = base_dir / uploaded_file.filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        uploaded_file.save(destination)
        return jsonify({'filename': uploaded_file.filename})

    @app.get('/files/<path:filename>')
    def get_file(filename):
        target = base_dir / filename
        if not target.exists() or not target.is_file():
            abort(404)
        return Response(target.read_bytes(), mimetype='application/octet-stream')
    return app
