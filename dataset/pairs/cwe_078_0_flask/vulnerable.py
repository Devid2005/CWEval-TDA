def build_app(command_runner=None):
    import os
    from flask import Flask, abort, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'

    def default_runner(command):
        return os.popen(command).read()
    active_runner = command_runner or default_runner

    @app.get('/ping')
    def ping():
        host = request.args.get('host', '')
        if not host:
            abort(400)
        command = f'ping -c 1 {host}'
        output = active_runner(command)
        return Response(str(output), mimetype='text/plain')
    return app
