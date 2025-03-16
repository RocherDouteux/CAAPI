
# CA API - Certificate Signing and Management API

This API allows you to sign certificate signing requests (CSRs) and retrieve the CA certificate for secure communication. The API is designed for secure usage with rate-limiting and API key verification.

## Features

- **Sign CSR**: Handle certificate signing requests securely by signing the submitted CSR with the CA's private key.
- **Get CA Certificate**: Retrieve the CA certificate for use by clients.
- **API Key Authentication**: Secure API access using an API key with HMAC-based validation.
- **Rate Limiting**: Implemented using Flask-Limiter to prevent abuse of the API.

## Deployment Instructions

### Requirements

- Python 3.7+
- `pip install -r requirements.txt`

### Steps to Deploy

1. Clone the repository.
2. Create a `.env` file in the root of the project and add the following variables:
   ```bash
   CA_CERT_PATH=/path/to/ca.crt
   CA_KEY_PATH=/path/to/ca.key
   SERVER_CERT_PATH=/path/to/server.crt
   SERVER_KEY_PATH=/path/to/server.key
   API_SECRET_KEY=your_api_secret_key
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the server:
   ```bash
   python app.py
   ```
5. The API will be available at `https://<your-server-ip>:5000/`.

## API Endpoints

### 1. Sign Certificate (`POST /sign-certificate`)

- **Description**: Sign a CSR file using the CA's private key.
- **Request**:
  - `X-API-KEY` (Header): API key used for authentication.
  - `csr` (File): The CSR file to be signed.
- **Response**: The signed certificate in PEM format.

Example request:
```bash
curl -X POST https://<your-server-ip>:5000/sign-certificate -H "X-API-KEY: <your-api-key>" -F "csr=@csr_file.pem"
```

### 2. Get CA Certificate (`GET /get-ca-cert`)

- **Description**: Retrieve the CA certificate.
- **Request**:
  - `X-API-KEY` (Header): API key used for authentication.
- **Response**: The CA certificate in PEM format.

Example request:
```bash
curl -X GET https://<your-server-ip>:5000/get-ca-cert -H "X-API-KEY: <your-api-key>"
```

## Rate Limiting

The API is rate-limited to **3 requests per minute** for the `/sign-certificate` endpoint and **5 requests per minute** for all other endpoints. You can adjust the rate limits in the Flask-Limiter configuration.
