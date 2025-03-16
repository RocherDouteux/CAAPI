import logging
import os
import time

from OpenSSL import crypto
from dotenv import load_dotenv
from flask import Flask, request, Response, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

CA_CERT_PATH = os.getenv("CA_CERT_PATH")
if not CA_CERT_PATH:
    raise ValueError("CA_CERT_PATH is missing! Set it in the .env file.")

CA_KEY_PATH = os.getenv("CA_KEY_PATH")
if not CA_KEY_PATH:
    raise ValueError("CA_KEY_PATH is missing! Set it in the .env file.")

SERVER_CERT_PATH = os.getenv("SERVER_CERT_PATH")
if not SERVER_CERT_PATH:
    raise ValueError("SERVER_CERT_PATH is missing! Set it in the .env file.")

SERVER_KEY_PATH = os.getenv("SERVER_KEY_PATH")
if not SERVER_KEY_PATH:
    raise ValueError("SERVER_KEY_PATH is missing! Set it in the .env file.")

API_SECRET_KEY = os.getenv("API_SECRET_KEY")
if not API_SECRET_KEY:
    raise ValueError("API_SECRET_KEY is missing! Set it in the .env file.")

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])


def verify_api_key(client_key):
    """ Secure API key verification """
    if not client_key:
        return False
    try:
        return client_key == API_SECRET_KEY
    except Exception as e:
        logging.error(f"API key verification error: {str(e)}")
        return False


@app.route("/sign-certificate", methods=["POST"])
@limiter.limit("3 per minute")
def sign_certificate():
    """ Handles signing a CSR request securely """
    try:
        api_key = request.headers.get("X-API-KEY")
        if not verify_api_key(api_key):
            logging.warning("Unauthorized API key access attempt.")
            abort(403, "Invalid API key.")

        csr_data = request.files.get("csr")
        if not csr_data:
            return jsonify({"error": "Missing CSR file"}), 400

        try:
            csr_text = csr_data.read().decode("utf-8")
        except Exception as e:
            logging.error(f"Failed to read CSR data: {str(e)}")
            return jsonify({"error": "Invalid CSR file"}), 400

        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_text)

        # Sign the CSR with the CA key
        with open(CA_KEY_PATH, "rb") as ca_key_file, open(CA_CERT_PATH, "rb") as ca_cert_file:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read())
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())

        signed_cert = crypto.X509()
        signed_cert.set_subject(csr.get_subject())
        signed_cert.set_serial_number(int(time.time()))
        signed_cert.gmtime_adj_notBefore(0)
        signed_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        signed_cert.set_issuer(ca_cert.get_subject())
        signed_cert.set_pubkey(csr.get_pubkey())
        signed_cert.sign(ca_key, "sha256")

        signed_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, signed_cert).decode("utf-8")
        logging.info("CSR signed successfully.")

        response = Response(signed_cert_pem)
        response.headers["Content-Type"] = "application/x-pem-file"
        response.headers["Content-Disposition"] = "attachment; filename=signed_certificate.pem"

        return response

    except Exception as e:
        logging.error(f"Error signing certificate: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/get-ca-cert", methods=["GET"])
def get_ca_certificate():
    """ Endpoint to retrieve the CA certificate """
    try:
        api_key = request.headers.get("X-API-KEY")
        if not verify_api_key(api_key):
            logging.warning("Unauthorized CA cert access attempt.")
            abort(403, "Invalid API key.")

        with open(CA_CERT_PATH, "r") as ca_cert_file:
            ca_cert = ca_cert_file.read()

        response = Response(ca_cert)
        response.headers["Content-Type"] = "application/x-pem-file"
        response.headers["Content-Disposition"] = "attachment; filename=ca_certificate.pem"

        return response

    except Exception as e:
        logging.error(f"Error retrieving CA certificate: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=(SERVER_CERT_PATH, SERVER_KEY_PATH))