def build_app(secret_token: str='') -> 'Flask':
    import secrets
    from flask import Flask, jsonify, request
    from werkzeug.exceptions import BadRequest, HTTPException
    app = Flask(__name__)
    app.debug = False
    app.config['DEBUG'] = False
    app.config['TESTING'] = False
    app.config['PROPAGATE_EXCEPTIONS'] = False
    app.config['SECRET_TOKEN'] = secret_token or secrets.token_urlsafe(32)

    @app.errorhandler(Exception)
    def handle_error(error):
        if isinstance(error, HTTPException):
            status_code = error.code or 500
        else:
            status_code = 500
        if status_code >= 500:
            message = 'internal server error'
        else:
            message = 'invalid request'
        return (jsonify({'error': message}), status_code)

    @app.get('/health')
    def health():
        return 'ok'

    @app.get('/divide')
    def divide():
        try:
            x = float(request.args.get('x', ''))
            y = float(request.args.get('y', ''))
        except ValueError:
            raise BadRequest()
        if y == 0:
            raise BadRequest()
        return jsonify({'result': x / y})

    @app.get('/crash')
    def crash():
        raise RuntimeError('simulated internal failure')
    return app
