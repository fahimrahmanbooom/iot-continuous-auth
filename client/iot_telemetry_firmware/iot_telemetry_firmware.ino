/**
 * iot_telemetry_firmware.ino
 *
 * Continuous Authentication Framework - IoT Device Firmware
 * Target: ESP32-C6 (Arduino framework)
 *
 * Collects network, radio-frequency, and device-health telemetry and
 * transmits it periodically to a verification server over TLS/HTTPS.
 * Each message is authenticated with HMAC-SHA256 to ensure integrity.
 *
 * Telemetry fields:
 *   - device_id, seq, ts_ms, uptime_ms
 *   - wifi_connected, internet_state, rssi_dbm, bssid, channel
 *   - dns1, dns2, heap_free, min_free_heap
 *   - latency_ms, reset_reason, loop_jitter_ms
 *   - wifi_bssid_hash, wifi_rssi
 *
 * Author : Fahim Rahman
 * Date   : December 2025
 * License: MIT
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <mbedtls/md.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <Arduino.h>
#include "secrets.h"

// ─── Configuration ──────────────────────────────────────────────────────────

// Verification server endpoint (TLS); host, port, and CA are set in secrets.h
static String SERVER_URL;

// Device identity
static const char *DEVICE_ID = "esp32-lab-01";

// Telemetry interval in milliseconds
static const unsigned long TELEMETRY_INTERVAL_MS = 5000;

// Internet connectivity check host
static const char *PING_HOST = "clients3.google.com";
static const uint16_t PING_PORT = 80;

// ─── Global State ───────────────────────────────────────────────────────────

static uint32_t       g_seq            = 0;
static unsigned long  g_prevLoopTime   = 0;
static unsigned long  g_loopJitter     = 0;

// ─── Helper: HMAC-SHA256 ────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA256 over `message` using the pre-shared HMAC_KEY.
 * Returns lowercase hex string (64 chars).
 */
String hmac_sha256(const String &message) {
    uint8_t result[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);  // 1 = HMAC mode
    mbedtls_md_hmac_starts(&ctx,
                           (const uint8_t *)HMAC_KEY,
                           strlen(HMAC_KEY));
    mbedtls_md_hmac_update(&ctx,
                           (const uint8_t *)message.c_str(),
                           message.length());
    mbedtls_md_hmac_finish(&ctx, result);
    mbedtls_md_free(&ctx);

    String hex;
    hex.reserve(64);
    for (int i = 0; i < 32; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", result[i]);
        hex += buf;
    }
    return hex;
}

// ─── Helper: BSSID hash (first 16 hex chars of SHA-256) ────────────────────

String bssid_hash(const String &bssid) {
    uint8_t result[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx,
                      (const uint8_t *)bssid.c_str(),
                      bssid.length());
    mbedtls_md_finish(&ctx, result);
    mbedtls_md_free(&ctx);

    String hex;
    hex.reserve(16);
    for (int i = 0; i < 8; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", result[i]);
        hex += buf;
    }
    return hex;
}

// ─── Helper: Check Internet Reachability ────────────────────────────────────

/**
 * Returns an internet state code:
 *   0 = unreachable
 *   1 = DNS only (reserved for future use)
 *   2 = fully reachable
 */
int check_internet_state() {
    WiFiClient client;
    if (client.connect(PING_HOST, PING_PORT, 3000)) {
        client.stop();
        return 2;  // fully reachable
    }
    return 0;  // unreachable
}

// ─── Helper: Get DNS server addresses ───────────────────────────────────────

String get_dns_server(int index) {
    // Returns 0.0.0.0 when the resolver slot is unset.
    return WiFi.dnsIP(index).toString();
}

// ─── Helper: Measure round-trip latency to the server ───────────────────────

unsigned long measure_latency() {
    WiFiClientSecure client;
    client.setCACert(CA_CERT);

    unsigned long start = millis();
    // Attempt a TLS connection to the server to measure latency
    if (client.connect(SERVER_HOST, SERVER_PORT, 5000)) {
        unsigned long elapsed = millis() - start;
        client.stop();
        return elapsed;
    }
    return 9999;  // timeout indicator
}

// ─── Build & Send Telemetry ─────────────────────────────────────────────────

void send_telemetry() {
    // Collect all telemetry fields
    unsigned long now_ms  = millis();
    uint32_t seq          = g_seq++;
    uint32_t uptime_ms    = now_ms;
    bool wifi_connected   = (WiFi.status() == WL_CONNECTED);
    int internet_state    = wifi_connected ? check_internet_state() : 0;
    int rssi              = WiFi.RSSI();
    String bssid_str      = WiFi.BSSIDstr();
    int channel           = WiFi.channel();
    String dns1           = get_dns_server(0);
    String dns2           = get_dns_server(1);
    uint32_t heap_free    = esp_get_free_heap_size();
    uint32_t min_heap     = esp_get_minimum_free_heap_size();
    unsigned long latency = measure_latency();
    int reset_reason_val  = (int)esp_reset_reason();
    uint32_t uptime_s     = uptime_ms / 1000;
    String bssid_h        = bssid_hash(bssid_str);

    // Compute loop jitter
    if (g_prevLoopTime > 0) {
        unsigned long actual_interval = now_ms - g_prevLoopTime;
        g_loopJitter = (actual_interval > TELEMETRY_INTERVAL_MS)
                       ? (actual_interval - TELEMETRY_INTERVAL_MS)
                       : (TELEMETRY_INTERVAL_MS - actual_interval);
    }
    g_prevLoopTime = now_ms;

    // Build JSON payload
    // Keys are emitted alphabetically so the server can reproduce the exact
    // canonical representation before verifying the HMAC.
    String json = "{";
    json += "\"bssid\":\"" + bssid_str + "\",";
    json += "\"channel\":" + String(channel) + ",";
    json += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
    json += "\"dns1\":\"" + dns1 + "\",";
    json += "\"dns2\":\"" + dns2 + "\",";
    json += "\"free_heap\":" + String(heap_free) + ",";
    json += "\"heap_free\":" + String(heap_free) + ",";
    json += "\"internet_state\":" + String(internet_state) + ",";
    json += "\"latency_ms\":" + String(latency) + ",";
    json += "\"loop_jitter_ms\":" + String(g_loopJitter) + ",";
    json += "\"min_free_heap\":" + String(min_heap) + ",";
    json += "\"reset_reason\":" + String(reset_reason_val) + ",";
    json += "\"rssi_dbm\":" + String(rssi) + ",";
    json += "\"seq\":" + String(seq) + ",";
    json += "\"ts_ms\":" + String(now_ms) + ",";
    json += "\"uptime_ms\":" + String(uptime_ms) + ",";
    json += "\"uptime_s\":" + String(uptime_s) + ",";
    json += "\"wifi_bssid_hash\":\"" + bssid_h + "\",";
    json += "\"wifi_connected\":" + String(wifi_connected ? 1 : 0) + ",";
    json += "\"wifi_rssi\":" + String(rssi);
    json += "}";

    // Compute HMAC over the JSON payload
    String sig = hmac_sha256(json);

    // Wrap in envelope with HMAC
    String envelope = "{\"payload\":" + json + ",\"hmac\":\"" + sig + "\"}";

    // Send via HTTPS
    WiFiClientSecure client;
    client.setCACert(CA_CERT);

    HTTPClient https;
    if (https.begin(client, SERVER_URL)) {
        https.addHeader("Content-Type", "application/json");
        int httpCode = https.POST(envelope);

        if (httpCode == 200) {
            String response = https.getString();
            // Check if server issued a challenge
            if (response.indexOf("\"challenge\"") >= 0) {
                handle_challenge(response);
            }
        } else {
            Serial.printf("[Telemetry] HTTP error: %d\n", httpCode);
        }
        https.end();
    } else {
        Serial.println("[Telemetry] HTTPS connection failed");
    }

    Serial.printf("[Telemetry] seq=%u rssi=%d inet=%d heap=%u lat=%lu jitter=%lu\n",
                  seq, rssi, internet_state, heap_free, latency, g_loopJitter);
}

// ─── Challenge-Response Handler ─────────────────────────────────────────────

/**
 * When the server detects anomalies, it responds with a cryptographic
 * challenge.  The device must prove continued possession of its secret
 * key by computing HMAC-SHA256 over the challenge nonce.
 */
void handle_challenge(const String &response) {
    // Extract nonce from response JSON (simple parse)
    int nonce_start = response.indexOf("\"nonce\":\"") + 9;
    int nonce_end   = response.indexOf("\"", nonce_start);
    if (nonce_start < 9 || nonce_end < 0) return;

    String nonce = response.substring(nonce_start, nonce_end);

    Serial.printf("[Challenge] Received nonce: %s\n", nonce.c_str());

    // Build challenge response: HMAC(device_id | nonce | timestamp)
    unsigned long ts = millis();
    String message = String(DEVICE_ID) + "|" + nonce + "|" + String(ts);
    String sig     = hmac_sha256(message);

    // Send challenge response
    String cr_json = "{";
    cr_json += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
    cr_json += "\"nonce\":\"" + nonce + "\",";
    cr_json += "\"ts\":" + String(ts) + ",";
    cr_json += "\"hmac\":\"" + sig + "\"";
    cr_json += "}";

    WiFiClientSecure client;
    client.setCACert(CA_CERT);

    HTTPClient https;
    String challenge_url = SERVER_URL.substring(0,
        SERVER_URL.lastIndexOf('/')) + "/challenge_response";

    if (https.begin(client, challenge_url)) {
        https.addHeader("Content-Type", "application/json");
        int code = https.POST(cr_json);
        Serial.printf("[Challenge] Response sent, server replied: %d\n", code);
        https.end();
    }
}

// ─── Arduino Setup & Loop ───────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(1000);
    SERVER_URL = String("https://") + SERVER_HOST + ":" + String(SERVER_PORT) +
                 "/api/telemetry";
    Serial.println("\n=== IoT Continuous Authentication - Telemetry Firmware ===");
    Serial.printf("Device ID : %s\n", DEVICE_ID);
    Serial.printf("Server    : %s\n", SERVER_URL.c_str());
    Serial.printf("Interval  : %lu ms\n", TELEMETRY_INTERVAL_MS);

    // Connect to Wi-Fi
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    Serial.print("Connecting to Wi-Fi");
    unsigned long wifi_start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - wifi_start < 30000) {
        delay(500);
        Serial.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("\nConnected! IP: %s\n", WiFi.localIP().toString().c_str());
        Serial.printf("BSSID: %s  Channel: %d  RSSI: %d dBm\n",
                      WiFi.BSSIDstr().c_str(), WiFi.channel(), WiFi.RSSI());
    } else {
        Serial.printf("\nWi-Fi connection failed (status %d). Visible networks:\n",
                      (int)WiFi.status());
        WiFi.disconnect();
        delay(200);
        int n = WiFi.scanNetworks();
        Serial.printf("  scan result: %d\n", n);
        for (int i = 0; i < n; i++) {
            Serial.printf("  [%s] ch=%ld rssi=%ld enc=%d\n",
                          WiFi.SSID(i).c_str(), (long)WiFi.channel(i),
                          (long)WiFi.RSSI(i), (int)WiFi.encryptionType(i));
        }
        Serial.println("Will retry in loop.");
    }

    g_prevLoopTime = millis();
}

void loop() {
    // Reconnect Wi-Fi if disconnected
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[WiFi] Reconnecting...");
        WiFi.disconnect();
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
        delay(5000);
        return;
    }

    send_telemetry();
    delay(TELEMETRY_INTERVAL_MS);
}
