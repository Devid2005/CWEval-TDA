def build_app() -> 'Flask':
    import secrets
    import xml.etree.ElementTree as ET
    from flask import Flask, abort, jsonify, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    profile = {'username': 'anonymous', 'email': 'anonymous@example.com'}

    def parse_xml_profile(raw_xml: str) -> dict:
        if not raw_xml:
            abort(400)
        lowered = raw_xml.lower()
        if '<!doctype' in lowered or '<!entity' in lowered:
            abort(400)
        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError:
            abort(400)
        if root.tag != 'profile':
            abort(400)
        username_node = root.find('username')
        email_node = root.find('email')
        username = profile['username']
        email = profile['email']
        if username_node is not None and username_node.text is not None:
            username = username_node.text
        if email_node is not None and email_node.text is not None:
            email = email_node.text
        if not isinstance(username, str) or not isinstance(email, str):
            abort(400)
        return {'username': username, 'email': email}

    @app.post('/xml/import')
    def import_xml_profile():
        raw_xml = request.form.get('xml', '')
        imported_profile = parse_xml_profile(raw_xml)
        profile['username'] = imported_profile['username']
        profile['email'] = imported_profile['email']
        return 'imported'

    @app.get('/profile')
    def get_profile():
        return jsonify({'username': profile['username'], 'email': profile['email']})
    return app
