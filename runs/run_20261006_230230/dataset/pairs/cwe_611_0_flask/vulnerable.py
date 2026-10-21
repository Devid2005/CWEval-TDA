def build_app():
    import secrets
    from flask import Flask, abort, jsonify, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    profile = {'username': 'anonymous', 'email': 'anonymous@example.com'}

    def expand_external_entities(raw_xml):
        entity_pattern = re.compile('<!ENTITY\\s+(\\w+)\\s+SYSTEM\\s+["\\\']file://([^"\\\']+)["\\\']\\s*>', re.IGNORECASE)
        replacements = {}
        for match in entity_pattern.finditer(raw_xml):
            entity_name = match.group(1)
            file_path = match.group(2)
            try:
                replacements[entity_name] = open(file_path, 'r', encoding='utf-8').read()
            except OSError:
                replacements[entity_name] = ''
        xml_without_doctype = re.sub('<!DOCTYPE\\s+\\w+\\s*\\[[\\s\\S]*?\\]>\\s*', '', raw_xml, flags=re.IGNORECASE)
        for entity_name, value in replacements.items():
            xml_without_doctype = xml_without_doctype.replace(f'&{entity_name};', value)
        return xml_without_doctype

    @app.post('/xml/import')
    def import_xml_profile():
        raw_xml = request.form.get('xml', '')
        if not raw_xml:
            abort(400)
        try:
            expanded_xml = expand_external_entities(raw_xml)
            root = ET.fromstring(expanded_xml)
        except Exception:
            abort(400)
        if root.tag != 'profile':
            abort(400)
        username_node = root.find('username')
        email_node = root.find('email')
        if username_node is not None and username_node.text is not None:
            profile['username'] = username_node.text
        if email_node is not None and email_node.text is not None:
            profile['email'] = email_node.text
        return 'imported'

    @app.get('/profile')
    def get_profile():
        return jsonify(profile)
    return app
