#pragma once

// Copy this file to secrets.h and replace every placeholder. Never commit
// secrets.h. Use a unique random device key of at least 32 bytes.
static const char *WIFI_SSID = "REPLACE_WITH_WIFI_SSID";
static const char *WIFI_PASSWORD = "REPLACE_WITH_WIFI_PASSWORD";
static const char *HMAC_KEY = "REPLACE_WITH_UNIQUE_DEVICE_SECRET_AT_LEAST_32_BYTES";

// Verification server (TLS). SERVER_HOST must match the subjectAltName of the
// server certificate created by certs/setup_certs.sh (SERVER_IP=...).
static const char *SERVER_HOST = "REPLACE_WITH_SERVER_IP";
static const uint16_t SERVER_PORT = 5000;

// Paste the contents of certs/ca.crt between the markers.
static const char *CA_CERT = R"EOF(
-----BEGIN CERTIFICATE-----
REPLACE_WITH_YOUR_CA_CERTIFICATE
-----END CERTIFICATE-----
)EOF";
