import ssl
import hashlib
import os
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

# Trusted client certificate thumbprints (SHA-256)
# Read from TEST_CLIENT_THUMBPRINT environment variable
thumbprint = os.getenv('TEST_CLIENT_THUMBPRINT')
if thumbprint and len(thumbprint) == 64 and all(c in '0123456789abcdef' for c in thumbprint.lower()):
    print(f"[nfe_service.py] Loaded thumbprint from environment: {thumbprint}")
    TRUSTED_CLIENTS = {thumbprint: "test_client"}
else:
    print("[nfe_service.py] WARNING: TEST_CLIENT_THUMBPRINT not set or invalid. No trusted clients configured.")
    TRUSTED_CLIENTS = {}

# --- Helper Function for Thumbprint Calculation ---
def get_cert_thumbprint(cert):
    if not cert:
        print("[nfe_service.py] No client certificate provided.")
        return None
    try:
        # cert is a bytes object containing the DER-encoded certificate
        thumbprint = hashlib.sha256(cert).hexdigest()
        print(f"[nfe_service.py] Calculated thumbprint: {thumbprint}")
        return thumbprint
    except Exception as e:
        print(f"[nfe_service.py] Error calculating thumbprint: {str(e)}")
        return None

# --- Security: mTLS Authentication Decorator ---
def require_mtls(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Retrieve the client certificate
        cert = request.environ.get('werkzeug.socket').getpeercert(binary_form=True)
        if not cert:
            print("[nfe_service.py] No client certificate received.")
            return jsonify({"error": "Client certificate required."}), 403
        
        # Calculate the thumbprint
        thumbprint = get_cert_thumbprint(cert)
        if not thumbprint:
            print("[nfe_service.py] Failed to calculate certificate thumbprint.")
            return jsonify({"error": "Invalid client certificate."}), 403
        
        # Validate against trusted clients
        if thumbprint not in TRUSTED_CLIENTS:
            print(f"[nfe_service.py] Untrusted client certificate thumbprint: {thumbprint}")
            return jsonify({"error": "Untrusted client certificate."}), 403
        
        print(f"[nfe_service.py] Client certificate validated: {TRUSTED_CLIENTS[thumbprint]} (Thumbprint: {thumbprint})")
        
        if not request.is_json:
            print("[nfe_service.py] Request is not JSON.")
            return jsonify({"error": "Request must be JSON"}), 400
        
        # The client wraps the original payload with config context.
        data = request.get_json()
        g.payload = data.get('payload')
        g.config = data.get('config')

        if not g.payload or not g.config:
            print("[nfe_service.py] Missing payload or config in request.")
            return jsonify({"error": "Invalid request format. 'payload' and 'config' keys are required."}), 400

        print(f"[nfe_service.py] Request received for SEFAZ '{g.config.get('sefaz')}' in env '{g.config.get('environment')}'")
        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---
# Each endpoint is protected by the mTLS decorator.

@app.route('/api/v1/nfe/autorizacao', methods=['POST'])
@require_mtls
def nfe_autorizacao():
    print(f"[nfe_service.py] Processing NFeAutorizacao with payload: {g.payload}")
    # TODO: Implement business logic for NFeAutorizacao
    return jsonify({"status": "received", "operation": "NFeAutorizacao", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/ret-autorizacao', methods=['POST'])
@require_mtls
def nfe_ret_autorizacao():
    print(f"[nfe_service.py] Processing NFeRetAutorizacao with payload: {g.payload}")
    # TODO: Implement business logic for NFeRetAutorizacao
    return jsonify({"status": "received", "operation": "NFeRetAutorizacao", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/inutilizacao', methods=['POST'])
@require_mtls
def nfe_inutilizacao():
    print(f"[nfe_service.py] Processing NfeInutilizacao with payload: {g.payload}")
    # TODO: Implement business logic for NfeInutilizacao
    return jsonify({"status": "received", "operation": "NfeInutilizacao", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/consulta-protocolo', methods=['POST'])
@require_mtls
def nfe_consulta_protocolo():
    print(f"[nfe_service.py] Processing NfeConsultaProtocolo with payload: {g.payload}")
    # TODO: Implement business logic for NfeConsultaProtocolo
    return jsonify({"status": "received", "operation": "NfeConsultaProtocolo", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/status-servico', methods=['POST'])
@require_mtls
def nfe_status_servico():
    print(f"[nfe_service.py] Processing NfeStatusServico with payload: {g.payload}")
    # TODO: Implement business logic for NfeStatusServico
    # This endpoint returns a successful response for the test.
    return jsonify({"status": "ok", "operation": "NfeStatusServico", "cStat": "107", "xMotivo": "Servico em Operacao"}), 200

@app.route('/api/v1/nfe/consulta-cadastro', methods=['POST'])
@require_mtls
def nfe_consulta_cadastro():
    print(f"[nfe_service.py] Processing NfeConsultaCadastro with payload: {g.payload}")
    # TODO: Implement business logic for NfeConsultaCadastro
    return jsonify({"status": "received", "operation": "NfeConsultaCadastro", "message": "Payload is being processed."}), 202

@app.route('/api/v1/nfe/recepcao-evento', methods=['POST'])
@require_mtls
def nfe_recepcao_evento():
    print(f"[nfe_service.py] Processing RecepcaoEvento with payload: {g.payload}")
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