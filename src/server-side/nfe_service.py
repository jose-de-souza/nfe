import ssl
from flask import Flask, request, jsonify, g
from werkzeug.serving import run_simple
from functools import wraps

# --- Application Setup ---
app = Flask(__name__)

# --- Configuration ---
app.config['DATABASE_HOST'] = 'localhost'
app.config['DATABASE_USER'] = 'nfe_user'
app.config['DATABASE_PASSWORD'] = 'your_strong_password'
app.config['DATABASE_NAME'] = 'nfe_db'

TRUSTED_CLIENTS = {
    "THUMBPRINT_OF_CLIENT_CERT_1": "company_A_id",
}

# --- Security: mTLS Authentication ---
def require_mtls(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cert = request.environ.get('werkzeug.socket').getpeercert()
        if not cert:
            return jsonify({"error": "Client certificate required."}), 401
        
        # Proper thumbprint validation should be implemented here.
        # For now, we proceed assuming the client is trusted.
        
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        
        data = request.get_json()
        g.payload = data.get('payload')
        g.config = data.get('config')

        if not g.payload or not g.config:
             return jsonify({"error": "Invalid request format. 'payload' and 'config' keys are required."}), 400

        print(f"Request received for SEFAZ '{g.config.get('sefaz')}' in env '{g.config.get('environment')}'")
        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---

@app.route('/api/v1/nfe/autorizacao', methods=['POST'])
@require_mtls
def nfe_autorizacao():
    print(f"Processing NFeAutorizacao with payload: {g.payload}")
    # TODO: Implement business logic for NFeAutorizacao
    return jsonify({"status": "received", "operation": "NFeAutorizacao", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/ret-autorizacao', methods=['POST'])
@require_mtls
def nfe_ret_autorizacao():
    print(f"Processing NFeRetAutorizacao with payload: {g.payload}")
    # TODO: Implement business logic for NFeRetAutorizacao
    return jsonify({"status": "received", "operation": "NFeRetAutorizacao", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/inutilizacao', methods=['POST'])
@require_mtls
def nfe_inutilizacao():
    print(f"Processing NfeInutilizacao with payload: {g.payload}")
    # TODO: Implement business logic for NfeInutilizacao
    return jsonify({"status": "received", "operation": "NfeInutilizacao", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/consulta-protocolo', methods=['POST'])
@require_mtls
def nfe_consulta_protocolo():
    print(f"Processing NfeConsultaProtocolo with payload: {g.payload}")
    # TODO: Implement business logic for NfeConsultaProtocolo
    return jsonify({"status": "received", "operation": "NfeConsultaProtocolo", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/status-servico', methods=['POST'])
@require_mtls
def nfe_status_servico():
    print(f"Processing NfeStatusServico with payload: {g.payload}")
    # TODO: Implement business logic for NfeStatusServico
    return jsonify({"status": "ok", "operation": "NfeStatusServico", "cStat": "107", "xMotivo": "Servico em Operacao"}), 200

@app.route('/api/v1/nfe/consulta-cadastro', methods=['POST'])
@require_mtls
def nfe_consulta_cadastro():
    print(f"Processing NfeConsultaCadastro with payload: {g.payload}")
    # TODO: Implement business logic for NfeConsultaCadastro
    return jsonify({"status": "received", "operation": "NfeConsultaCadastro", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/recepcao-evento', methods=['POST'])
@require_mtls
def nfe_recepcao_evento():
    print(f"Processing RecepcaoEvento with payload: {g.payload}")
    # TODO: Implement business logic for RecepcaoEvento
    return jsonify({"status": "received", "operation": "RecepcaoEvento", "message": "Payload is being processed."}), 202


# --- Main Execution ---
if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.crt', 'server.key')
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('client_ca.crt') 

    run_simple('0.0.0.0', 5001, app, ssl_context=context)
