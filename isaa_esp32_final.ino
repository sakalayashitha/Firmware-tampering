// ESP32 Firmware Tamper Detector — Updated
// Features added: NTP timestamps, Blynk notifications, audit CSV, Chart.js dashboard, /download_audit
// Auto self-heal NOT included (removed).

#define BLYNK_TEMPLATE_ID "TMPL3V-Ryox0B"
#define BLYNK_TEMPLATE_NAME "File Tamper Detection"
#define BLYNK_AUTH_TOKEN "z6xxIm08wz7V3LZaGiEyxeNWbm9OXQ33"

#include <WiFi.h>
#include <WebServer.h>
#include <SPI.h>
#include <SD.h>
#include "mbedtls/sha256.h"
#include <time.h>
#include <map>               // For std::map
#include <ArduinoJson.h>     // For DynamicJsonDocument

using namespace std;

// Blynk (make sure Blynk library is installed)
#include <BlynkSimpleEsp32.h>

// ---------------- CONFIG ----------------
const char* ssid = "Hash";
const char* password = "12345678";

WebServer server(80);

// SD / pins
const int chipSelect = 5; // SD card CS
const int ledPin = 2;     // LED for tamper alert

const char* FIRMWARE_DIR   = "/firmware";
const char* LOG_PATH       = "/firmware/firmware_log.txt";
const char* AUDIT_CSV_PATH = "/firmware/firmware_audit.csv";

String lastMessage = "";           // status banner on UI
unsigned long bootMillis = 0;

// ---------------- Utilities ----------------
String toHexString(const uint8_t *hash, size_t len) {
  String hex = "";
  for (size_t i = 0; i < len; i++) {
    char buf[3];
    sprintf(buf, "%02x", hash[i]);
    hex += buf;
  }
  return hex;
}

bool computeFileSHA256(const char* path, uint8_t outHash[32]) {
  File f = SD.open(path, FILE_READ);
  if (!f) return false;

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);

  static const size_t CHUNK = 2048;
  uint8_t buf[CHUNK];
  while (true) {
    int n = f.read(buf, CHUNK);
    if (n < 0) { f.close(); mbedtls_sha256_free(&ctx); return false; }
    if (n == 0) break;
    mbedtls_sha256_update(&ctx, buf, n);
  }

  mbedtls_sha256_finish(&ctx, outHash);
  mbedtls_sha256_free(&ctx);
  f.close();
  return true;
}

String readLine(File &f) {
  String line = "";
  while (f.available()) {
    char c = (char)f.read();
    if (c == '\r') continue;
    if (c == '\n') break;
    line += c;
  }
  return line;
}

String getLoggedHash(const String& filename) {
  File log = SD.open(LOG_PATH, FILE_READ);
  if (!log) return "";
  while (log.available()) {
    String line = readLine(log);
    if (line.length() == 0) continue;
    int comma = line.indexOf(',');
    if (comma <= 0) continue;
    String name = line.substring(0, comma);
    String hash = line.substring(comma + 1);
    if (name == filename) {
      log.close();
      return hash;
    }
  }
  log.close();
  return "";
}

bool upsertLog(const String& filename, const String& hash) {
  if (!SD.exists(LOG_PATH)) {
    File log = SD.open(LOG_PATH, FILE_WRITE);
    if (!log) return false;
    log.printf("%s,%s\n", filename.c_str(), hash.c_str());
    log.close();
    return true;
  }

  const char* TMP_PATH = "/firmware/firmware_log.tmp";
  File in  = SD.open(LOG_PATH, FILE_READ);
  File out = SD.open(TMP_PATH, FILE_WRITE);
  if (!in || !out) {
    if (in) in.close();
    if (out) out.close();
    return false;
  }

  while (in.available()) {
    String line = readLine(in);
    if (line.length() == 0) continue;
    int comma = line.indexOf(',');
    if (comma <= 0) continue;
    String name = line.substring(0, comma);
    if (name == filename) continue; // skip old entry
    out.println(line);
  }
  in.close();
  out.printf("%s,%s\n", filename.c_str(), hash.c_str());
  out.close();

  SD.remove(LOG_PATH);
  SD.rename(TMP_PATH, LOG_PATH);
  return true;
}

String htmlEscape(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '&') o += F("&amp;");
    else if (c == '<') o += F("&lt;");
    else if (c == '>') o += F("&gt;");
    else o += c;
  }
  return o;
}

String sanitizeFilename(const String& fname) {
  String safe = "";
  for (size_t i = 0; i < fname.length(); i++) {
    char c = fname[i];
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '.' || c == '_' || c == '-') {
      safe += c;
    }
  }
  if (safe.length() == 0) safe = "firmware.bin";
  return safe;
}

String isoTimestamp() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    // fallback to millis-based approximate timestamp
    unsigned long s = millis() / 1000;
    char buf[32];
    sprintf(buf, "uptime_%lus", s);
    return String(buf);
  }
  char buf[32];
  sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02dZ",
          timeinfo.tm_year + 1900,
          timeinfo.tm_mon + 1,
          timeinfo.tm_mday,
          timeinfo.tm_hour,
          timeinfo.tm_min,
          timeinfo.tm_sec);
  return String(buf);
}

// ---------------- File row builders ----------------
String buildFileRowsBasic() {
  String rows = "";
  File dir = SD.open(FIRMWARE_DIR);
  if (!dir) return rows;
  File f = dir.openNextFile();
  while (f) {
    if (!f.isDirectory()) {
      String path = String(FIRMWARE_DIR) + "/" + String(f.name());
      path.replace(String(FIRMWARE_DIR) + String(FIRMWARE_DIR), FIRMWARE_DIR);
      String logged = getLoggedHash(String(f.name()));
      if (logged == "") logged = "-";
      String truncLogged = (logged.length() > 12) ? logged.substring(0,12) + "…" : logged;

      rows += "<tr><td>" + htmlEscape(path) + "</td>";
      rows += "<td>" + String(f.size()) + "</td>";
      rows += "<td><code>" + truncLogged + "</code></td>";
      rows += "<td>-</td><td>-</td></tr>";
    }
    f = dir.openNextFile();
  }
  dir.close();
  return rows;
}

// This function performs a scan, appends audit CSV lines, and returns HTML rows.
String performScanAndBuildRows(bool &anyTampered) {
  anyTampered = false;
  String rows = "";
  File dir = SD.open(FIRMWARE_DIR);
  if (!dir) return rows;

  // open audit CSV for append
  File audit = SD.open(AUDIT_CSV_PATH, FILE_APPEND);
  bool wroteHeader = false;
  if (audit && audit.size() == 0) {
    // write CSV header
    audit.println("timestamp,filename,filesize,expected_hash,current_hash,status");
    wroteHeader = true;
  }

  File f = dir.openNextFile();
  while (f) {
    if (!f.isDirectory()) {
      String path = String(FIRMWARE_DIR) + "/" + String(f.name());
      path.replace(String(FIRMWARE_DIR) + String(FIRMWARE_DIR), FIRMWARE_DIR);

      String expected = getLoggedHash(String(f.name()));
      uint8_t curHashRaw[32];
      String curHash = "";
      bool ok = computeFileSHA256(path.c_str(), curHashRaw);
      if (ok) curHash = toHexString(curHashRaw, 32);

      String status, statusColor;
      if (expected == "") { status = "Not Logged"; statusColor = "#9E9E9E"; }
      else if (!ok) { status = "Read/Hash Error"; statusColor = "#FF9800"; }
      else if (expected.equalsIgnoreCase(curHash)) { status = "Authentic"; statusColor = "#2E7D32"; }
      else { status = "Tampered"; statusColor = "#C62828"; anyTampered = true; }

      String truncExpected = (expected.length() > 12) ? expected.substring(0,12) + "…" : expected;
      String truncCurHash  = (curHash.length() > 12) ? curHash.substring(0,12) + "…" : curHash;

      rows += "<tr>";
      rows += "<td>" + htmlEscape(path) + "</td>";
      rows += "<td>" + String(f.size()) + "</td>";
      rows += "<td><code>" + (expected == "" ? "-" : truncExpected) + "</code></td>";
      rows += "<td><code>" + (curHash == "" ? "-" : truncCurHash) + "</code></td>";
      rows += "<td><span style='font-weight:600;color:" + statusColor + "'>" + status + "</span></td>";
      rows += "</tr>";

      // append CSV line
      if (audit) {
        String t = isoTimestamp();
        String csvLine = t + "," + String(f.name()) + "," + String(f.size()) + "," +
                         (expected=="" ? "-" : expected) + "," +
                         (curHash=="" ? "-" : curHash) + "," + status;
        audit.println(csvLine);
      }
    }
    f = dir.openNextFile();
  }
  if (audit) audit.close();
  dir.close();
  return rows;
}

// ---------------- UI Page ----------------
String mainPageHTML(String message = "", String tableRows = "") {
  if (tableRows == "") tableRows = buildFileRowsBasic();

  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<title>ESP32 Firmware Tamper Detector</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root { --card:#fff; --bg:#f0f2f5; --text:#333; --primary:#2196F3; --accent:#4CAF50; }
*{box-sizing:border-box;}
body{font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:var(--bg); margin:0; padding:20px; display:flex; flex-direction:column; align-items:center;}
h1{margin:8px 0 18px; color:var(--text); font-size:26px; text-align:center;}
.card{background:var(--card); border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,0.1); padding:22px; width:100%; max-width:1100px; margin-bottom:18px;}
input[type='file'],input[type='text']{width:100%; padding:12px; border-radius:8px; border:1px solid #ccc; font-size:16px; background:#fff;}
button{width:100%; padding:12px; border:none; border-radius:8px; color:#fff; font-size:16px; cursor:pointer;}
.btn-primary{background:var(--primary);} .btn-primary:hover{filter:brightness(0.95);}
.btn-accent{background:var(--accent);} .btn-accent:hover{filter:brightness(0.95);}
.banner{padding:12px 14px; border-radius:10px; font-weight:600; color:#1b5e20; background:#e8f5e9; margin-bottom:12px; word-break:break-word;}
.banner.error{color:#b71c1c; background:#ffebee;}
.files-wrapper{overflow-x:auto; margin-top:10px;}
table{width:100%; border-collapse:collapse; min-width:820px; font-size:16px;}
th,td{padding:10px; border-bottom:1px solid #e0e0e0; text-align:left;}
th{background:#0d47a1; color:#fff; position:sticky; top:0;}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:14px;}
.chart-row{display:flex; gap:12px; flex-wrap:wrap;}
.chart-card{flex:1 1 300px; padding:12px;}
.small{font-size:13px;color:#555;}
</style>
</head>
<body>
<h1>ESP32 Firmware Tamper Detector</h1>

<div class="card">
<h3>Upload Firmware (Log Hash)</h3>
<form method="POST" action="/upload" enctype="multipart/form-data">
<input type="file" name="upload" required>
<div style="height:10px"></div>
<button class="btn-accent" type="submit">Upload & Log Hash</button>
</form>
</div>

<div class="card">
<h3>Upload Firmware Only (No Log)</h3>
<form method="POST" action="/upload_only" enctype="multipart/form-data">
<input type="file" name="upload" required>
<div style="height:10px"></div>
<button class="btn-primary" type="submit">Upload Only (No Log)</button>
</form>
</div>

<div class="card">
<h3>Scan Firmware Files</h3>
<form method="POST" action="/scan">
<button class="btn-primary" type="submit">Scan Now</button>
</form>
</div>
)rawliteral";

  if (message.length()) {
    bool isError = message.indexOf("Tampered") >= 0 || message.indexOf("error") >= 0 || message.indexOf("Error") >= 0;
    html += "<div class='banner";
    if (isError) html += " error";
    html += "'>" + htmlEscape(message) + "</div>";
  }

  html += R"rawliteral(
<div class="card">
<h3>Firmware Inventory</h3>
<div class="files-wrapper">
<table>
<tr><th>File</th><th>Size (bytes)</th><th>Logged Hash</th><th>Current Hash</th><th>Status</th></tr>
)rawliteral";

  html += tableRows;

  html += R"rawliteral(
</table></div>
<div style="margin-top:12px;display:flex;gap:12px;">
<a href="/download_audit" style="text-decoration:none;"><button class="btn-primary">Download Audit CSV</button></a>
<a href="/view_log" style="text-decoration:none;"><button class="btn-accent">View Log</button></a>
</div>
</div>

<div class="card">
<h3>Analytics</h3>
<div class="chart-row">
  <div class="chart-card card">
    <h2>Device Uptime</h2>
    <div id="uptimeValue" class="small">-- seconds</div>
  </div>
</div>
</div>

<script>
async function fetchUptime() {
  const res = await fetch('/chart_data');
  const data = await res.json();
  document.getElementById('uptimeValue').innerText = data.uptime_seconds + " seconds";
}

// Fetch once on page load
fetchUptime();
</script>

</body></html>
)rawliteral";

  return html;
}

// ---------------- Web Routes ----------------
void handleRoot() {
  server.send(200, "text/html", mainPageHTML(lastMessage));
  lastMessage = "";
}

void handleViewLog() {
  File f = SD.open(LOG_PATH, FILE_READ);
  String txt = "";
  if (!f) txt = "No log found.";
  else {
    while (f.available()) {
      txt += (char)f.read();
    }
    f.close();
  }
  server.send(200, "text/plain", txt);
}

// ---------------- Upload & Scan (streaming hash) ----------------
File uploadFile;
mbedtls_sha256_context upCtx;
bool upStarted = false;
String upTargetFile = "";
String upFullPath = "";
uint8_t upHash[32];

void setupUploadRoute() {
  server.on("/upload", HTTP_POST,
    []() { }, 
    []() {
      HTTPUpload& upload = server.upload();

      if (upload.status == UPLOAD_FILE_START) {
        String fname = sanitizeFilename(upload.filename);
        upTargetFile = fname;
        upFullPath = String(FIRMWARE_DIR) + "/" + fname;

        if (!SD.exists(FIRMWARE_DIR)) SD.mkdir(FIRMWARE_DIR);
        if (SD.exists(upFullPath)) SD.remove(upFullPath);

        uploadFile = SD.open(upFullPath, FILE_WRITE);
        if (!uploadFile) {
          lastMessage = "ERROR: Cannot open file for writing.";
          Serial.println(lastMessage);
          return;
        }

        mbedtls_sha256_init(&upCtx);
        mbedtls_sha256_starts(&upCtx, 0);
        upStarted = true;
        Serial.println("Upload start: " + fname);

      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (uploadFile) {
          uploadFile.write(upload.buf, upload.currentSize);
          mbedtls_sha256_update(&upCtx, upload.buf, upload.currentSize);
        }

      } else if (upload.status == UPLOAD_FILE_END) {
        if (uploadFile) uploadFile.close();
        Serial.println("Upload finished. Size: " + String(upload.totalSize));

        mbedtls_sha256_finish(&upCtx, upHash);
        mbedtls_sha256_free(&upCtx);
        String hex = toHexString(upHash, 32);

        if (upTargetFile.length() && upsertLog(upTargetFile, hex)) {
          File log = SD.open(LOG_PATH, FILE_APPEND);
          if (log) {
            String t = isoTimestamp();
            log.printf("%s,%s,%u\n", t.c_str(), upTargetFile.c_str(), (unsigned int)upload.totalSize);
            log.close();
          }
          lastMessage = "Uploaded: " + upTargetFile + " • Logged Hash: " + hex;
        } else {
          lastMessage = "Upload complete, but failed to log hash.";
        }

        Serial.println(lastMessage);
        upStarted = false;
        upTargetFile = "";
        upFullPath = "";

        server.send(200, "text/html", mainPageHTML(lastMessage));

      } else if (upload.status == UPLOAD_FILE_ABORTED) {
        if (uploadFile) uploadFile.close();
        if (upFullPath.length() && SD.exists(upFullPath)) SD.remove(upFullPath);
        mbedtls_sha256_free(&upCtx);
        upStarted = false;
        lastMessage = "ERROR: Upload aborted.";
        Serial.println(lastMessage);
      }
    }
  );
}

void setupUploadOnlyRoute() {
  server.on("/upload_only", HTTP_POST,
    []() { server.send(200, "text/html", mainPageHTML(lastMessage)); lastMessage = ""; },
    []() {
      HTTPUpload& upload = server.upload();
      static File uploadOnlyFile;
      if (upload.status == UPLOAD_FILE_START) {
        String fname = sanitizeFilename(upload.filename);
        if (!SD.exists(FIRMWARE_DIR)) SD.mkdir(FIRMWARE_DIR);
        String path = String(FIRMWARE_DIR) + "/" + fname;
        if (SD.exists(path)) SD.remove(path);
        uploadOnlyFile = SD.open(path, FILE_WRITE);
        if (!uploadOnlyFile) { lastMessage = "ERROR: Cannot open file."; return; }
        Serial.println("Upload Only start: " + fname);
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (uploadOnlyFile) uploadOnlyFile.write(upload.buf, upload.currentSize);
      } else if (upload.status == UPLOAD_FILE_END) {
        if (uploadOnlyFile) uploadOnlyFile.close();
        lastMessage = "Upload Only complete: " + sanitizeFilename(upload.filename);
        Serial.println("Upload Only finished. Size: " + String(upload.totalSize));
      } else if (upload.status == UPLOAD_FILE_ABORTED) {
        if (uploadOnlyFile) uploadOnlyFile.close();
        lastMessage = "ERROR: Upload Only aborted.";
      }
    }
  );
}

void setupScanRoute() {
  server.on("/scan", HTTP_POST, []() {
    bool anyTampered = false;
    String rows = performScanAndBuildRows(anyTampered);

    if (anyTampered) {
      digitalWrite(ledPin, HIGH);
      lastMessage = "Scan complete: Tampered firmware detected.";
      Blynk.logEvent("alert", lastMessage.c_str());
    } else {
      digitalWrite(ledPin, LOW);
      lastMessage = "Scan complete: All firmware authentic.";
    }

    server.send(200, "text/html", mainPageHTML(lastMessage, rows));
    lastMessage = "";
  });
}

// ---------------- Chart / Download routes ----------------
void handleChartData() {
  DynamicJsonDocument doc(1024);
  unsigned long uptime_s = (millis() - bootMillis) / 1000;
  doc["uptime_seconds"] = uptime_s;

  String json;
  serializeJson(doc, json);
  server.send(200, "application/json", json);
}

void handleDownloadAudit() {
  File f = SD.open(AUDIT_CSV_PATH, FILE_READ);
  if (!f) {
    server.send(404, "text/plain", "Audit CSV not found.");
    return;
  }
  server.sendHeader("Content-Disposition", "attachment; filename=firmware_audit.csv");
  server.streamFile(f, "text/csv");
  f.close();
}

// ---------------- Setup ----------------
void setup() {
  Serial.begin(115200);
  pinMode(ledPin, OUTPUT);
  digitalWrite(ledPin, LOW);

  bootMillis = millis();

  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nConnected! IP: " + WiFi.localIP().toString());

  Blynk.begin(BLYNK_AUTH_TOKEN, ssid, password);

  configTime(0, 0, "pool.ntp.org", "time.google.com");
  delay(500);
  struct tm timeinfo;
  if (getLocalTime(&timeinfo)) {
    Serial.println("Time synced: " + String(isoTimestamp()));
  } else {
    Serial.println("Warning: Failed to get NTP time");
  }

  if (!SD.begin(chipSelect)) { Serial.println("SD Card Mount Failed!"); while(1) delay(100); }
  Serial.println("SD Card initialized.");
  if (!SD.exists(FIRMWARE_DIR)) SD.mkdir(FIRMWARE_DIR);
  if (!SD.exists(LOG_PATH)) { File log = SD.open(LOG_PATH, FILE_WRITE); if (log) log.close(); }
  if (!SD.exists(AUDIT_CSV_PATH)) { File a = SD.open(AUDIT_CSV_PATH, FILE_WRITE); if (a) a.close(); }

  server.on("/", HTTP_GET, handleRoot);
  server.on("/view_log", HTTP_GET, handleViewLog);
  server.on("/chart_data", HTTP_GET, handleChartData);
  server.on("/download_audit", HTTP_GET, handleDownloadAudit);

  setupUploadRoute();
  setupUploadOnlyRoute();
  setupScanRoute();

  server.begin();
  Serial.println("Server started");
}

// ---------------- Loop ----------------
void loop() {
  server.handleClient();
  Blynk.run();
}