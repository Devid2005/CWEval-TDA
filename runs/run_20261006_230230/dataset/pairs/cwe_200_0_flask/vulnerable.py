def build_app(secret_token: str=''):
    from flask import Flask, jsonify, request
    from werkzeug.exceptions import BadRequest, HTTPException
    app = Flask(__name__)
    app.debug = True
    app.config['DEBUG'] = True
    app.config['SECRET_TOKEN'] = secret_token or SENSITIVE_TOKEN
    app.config['PROPAGATE_EXCEPTIONS'] = False

    @app.errorhandler(Exception)
    def handle_error(error):
        if isinstance(error, HTTPException):
            status_code = error.code or 500
        else:
            status_code = 500
        return (jsonify({'error': str(error), 'secret_token': app.config['SECRET_TOKEN'], 'traceback': traceback.format_exc()}), status_code)

    @app.get('/health')
    def health():
        return 'ok'

    @app.get('/divide')
    def divide():
        try:
            x = float(request.args.get('x', ''))
            y = float(request.args.get('y', ''))
        except ValueError as exc:
            raise BadRequest(f'invalid numeric input: {exc}')
        if y == 0:
            raise BadRequest('division by zero with secret token ' + app.config['SECRET_TOKEN'])
        return jsonify({'result': x / y})

    @app.get('/crash')
    def crash():
        raise RuntimeError('internal failure with token ' + app.config['SECRET_TOKEN'])
    return app
