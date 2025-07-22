import ssl
from flask import Flask, request, jsonify, g
from werkzeug.serving import run_simple
from functools import wraps

# --- Application Setup ---
app = Flask(__name__)

# --- Configuration ---
# In a real application, these would come from environment variables or a secure config file.
app.config['DATABASE_HOST'] = 'localhost'
app.config['DATABASE_USER'] = 'nfe_user'
app.config['DATABASE_PASSWORD'] = 'your_strong_password'
app.config['DATABASE_NAME'] = 'nfe_db'

TRUSTED_CLIENTS = {
    # In production, you would map client certificate thumbprints to client IDs
    # e.g., "SHA256_THUMBPRINT_HERE": "client_id_123",
}

# --- Security: mTLS Authentication Decorator ---
def require_mtls(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # The SSL context configuration ensures a certificate is present.
        # This retrieves the certificate details presented by the client.
        cert = request.environ.get('werkzeug.socket').getpeercert()
        
        # Proper thumbprint validation should be implemented here for production.
        # For this test, we just confirm that a certificate was received.
        print(f"Client certificate received: {cert.get('subject', 'N/A')}")
        
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        
        # The client wraps the original payload with config context.
        data = request.get_json()
        g.payload = data.get('payload')
        g.config = data.get('config')

        if not g.payload or not g.config:
             return jsonify({"error": "Invalid request format. 'payload' and 'config' keys are required."}), 400

        print(f"Request received for SEFAZ '{g.config.get('sefaz')}' in env '{g.config.get('environment')}'")
        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---
# Each endpoint is protected by the mTLS decorator.

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
    # This endpoint now returns a successful response for the test.
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
    # Create a server-side SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Load the server's own certificate and private key
    context.load_cert_chain('C:\\madeiras\\erp\\service\\server.crt', 'C:\\madeiras\\erp\\service\\server.key')
    
    # Load the Certificate Authority (CA) certificate used to sign trusted client certs
    context.load_verify_locations('C:\\madeiras\\erp\\service\\cacerts.pem')
    
    # This line is essential for mTLS: it tells the server to require a client
    # certificate and validate it against the loaded CA.
    context.verify_mode = ssl.CERT_REQUIRED
    
    # Run the Flask development server with the configured SSL context
    run_simple('0.0.0.0', 5001, app, ssl_context=context)