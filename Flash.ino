#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include <TZ.h>

/* ===== CONFIG ===== */
const char* WIFI_SSID = "Название сети";
const char* WIFI_PASS = "Пароль";

const char* TG_BOT_TOKEN = "Токен Telegram-бота";
const char* TG_CHAT_ID  = "Ваш User-id в Telegram";

const char* SERVER_HOST = "Адрес сервера";
const int   SERVER_PORT = 8080;
const char* SERVER_API  = "/api/v1/logs";

const char* NTP_SERVER1 = "pool.ntp.org";
const char* NTP_SERVER2 = "time.nist.gov";
const char* NTP_SERVER3 = "ru.pool.ntp.org";
#define TIME_ZONE TZ_Europe_Moscow

String DEVICE_ID = "wifi-ids-" + String(ESP.getChipId(), HEX);

#define SCAN_DURATION 30000
#define CYCLE_DELAY   30000
#define MAX_NETWORKS  40
#define MAX_THREATS   10
#define TIME_SYNC_INTERVAL 3600000

/* ===== DATA ===== */
struct WiFiNetwork {
  String ssid;
  String bssid;
  int channel;
  int rssi;
  String encryption;
  bool isHidden;
  unsigned long firstSeen;
  unsigned long lastSeen;
};

struct Threat {
  String type;
  String severity;
  String description;
  String targetSSID;
  String targetBSSID;
  time_t detectedTime;
};

WiFiNetwork networks[MAX_NETWORKS];
Threat threats[MAX_THREATS];

int networkCount = 0;
int threatCount = 0;
int hiddenNetworksCount = 0;

unsigned long totalCycles = 0;
unsigned long totalThreatsDetected = 0;
unsigned long totalNetworks = 0;

bool lastScanHadThreats = false;

String lastReportedThreats[10];
time_t lastThreatTime[10];
int reportedThreatsCount = 0;

bool timeSynced = false;
unsigned long lastTimeSync = 0;

/* ===== UTILS ===== */
String toUpperCaseString(String s) {
  for (int i = 0; i < s.length(); i++) s[i] = toupper(s[i]);
  return s;
}

String escapeJsonString(String s) {
  String o;
  for (char c : s) {
    if (c == '"') o += "\\\"";
    else if (c == '\\') o += "\\\\";
    else if (c == '\n') o += "\\n";
    else if (c == '\r') o += "\\r";
    else if (c == '\t') o += "\\t";
    else o += c;
  }
  return o;
}

String formatMAC(String mac) {
  mac.replace(":", "");
  mac.replace("-", "");
  mac.toUpperCase();
  if (mac.length() < 12) return mac;
  String r;
  for (int i = 0; i < 12; i += 2) {
    if (i) r += ":";
    r += mac.substring(i, i + 2);
  }
  return r;
}

String shortMAC(String mac) {
  return mac.length() >= 8 ? mac.substring(9) : mac;
}

/* ===== TIME ===== */
bool syncTime() {
  Serial.println("[TIME] Синхронизация времени...");
  configTime(TIME_ZONE, NTP_SERVER1, NTP_SERVER2, NTP_SERVER3);

  for (int i = 0; i < 20 && time(nullptr) < 1000000000; i++) {
    Serial.print(".");
    delay(500);
  }

  if (time(nullptr) < 1000000000) {
    Serial.println("\n[TIME] ❌ Ошибка синхронизации времени");
    return false;
  }

  timeSynced = true;
  lastTimeSync = millis();
  return true;
}

String getCurrentTimeString() {
  if (!timeSynced) return "N/A";
  time_t now = time(nullptr);
  struct tm t;
  localtime_r(&now, &t);
  char b[16];
  strftime(b, sizeof(b), "%H:%M:%S", &t);
  return String(b);
}

String getCurrentDateTimeString() {
  if (!timeSynced) return "N/A";
  time_t now = time(nullptr);
  struct tm t;
  localtime_r(&now, &t);
  char b[32];
  strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &t);
  return String(b);
}

time_t getCurrentUnixTime() {
  return timeSynced ? time(nullptr) : 0;
}

/* ===== WIFI ===== */
bool connectToWiFi() {
  Serial.println("[WiFi] Подключение к сети...");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  unsigned long t = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - t > 20000) return false;
    delay(250);
    Serial.print(".");
  }

  Serial.printf("\n[WiFi] ✅ IP: %s RSSI: %d\n",
    WiFi.localIP().toString().c_str(), WiFi.RSSI());
  return true;
}


void performWiFiScan() {
  Serial.println("\n[SCAN] Начало сканирования WiFi...");
  
  networkCount = 0;
  threatCount = 0;
  hiddenNetworksCount = 0;
  lastScanHadThreats = false;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(500);
  
  unsigned long scanStart = millis();
  int scanAttempts = 0;
  
  while (millis() - scanStart < SCAN_DURATION) {
    scanAttempts++;
    
    int found = WiFi.scanNetworks(false, true);
    
    if (found == WIFI_SCAN_FAILED) {
      Serial.println("[SCAN] ❌ Ошибка сканирования!");
      continue;
    }
    
    Serial.printf("[SCAN] #%d -> Найдено: %d сетей\n", scanAttempts, found);
    
    for (int i = 0; i < found && networkCount < MAX_NETWORKS; i++) {
      String ssid = WiFi.SSID(i);
      String bssid = WiFi.BSSIDstr(i);
      
      if (ssid.length() == 0 || ssid == " ") {
        ssid = "[HIDDEN]";
      }
      
      // Проверяем существующую сеть
      bool exists = false;
      for (int j = 0; j < networkCount; j++) {
        if (networks[j].bssid == bssid) {
          exists = true;
          networks[j].rssi = WiFi.RSSI(i);
          networks[j].lastSeen = millis();
          break;
        }
      }
      
      if (!exists) {
        // Добавляем новую сеть
        networks[networkCount].ssid = ssid;
        networks[networkCount].bssid = formatMAC(bssid);
        networks[networkCount].channel = WiFi.channel(i);
        networks[networkCount].rssi = WiFi.RSSI(i);
        networks[networkCount].isHidden = (ssid == "[HIDDEN]");
        networks[networkCount].firstSeen = millis();
        networks[networkCount].lastSeen = millis();
        
        if (networks[networkCount].isHidden) {
          hiddenNetworksCount++;
        }
        
        // Тип шифрования
        switch(WiFi.encryptionType(i)) {
          case ENC_TYPE_NONE: networks[networkCount].encryption = "OPEN"; break;
          case ENC_TYPE_WEP: networks[networkCount].encryption = "WEP"; break;
          case ENC_TYPE_TKIP: networks[networkCount].encryption = "WPA"; break;
          case ENC_TYPE_CCMP: networks[networkCount].encryption = "WPA2"; break;
          default: networks[networkCount].encryption = "UNKNOWN";
        }
        
        Serial.printf("[NET] %-20s %s ch%2d %4d dBm %-6s\n",
                     ssid.substring(0, 20).c_str(),
                     networks[networkCount].bssid.c_str(),
                     networks[networkCount].channel,
                     networks[networkCount].rssi,
                     networks[networkCount].encryption.c_str());
        
        networkCount++;
      }
    }
    
    WiFi.scanDelete();
    
    // Проверка угроз
    detectSecurityThreats();
    
    delay(2000);
  }
  
  totalNetworks += networkCount;
  Serial.printf("[SCAN] ✅ Завершено! Сетей: %d, Скрытых: %d, Угроз: %d\n", 
                networkCount, hiddenNetworksCount, threatCount);
}

/* ================= ОБНАРУЖЕНИЕ УГРОЗ ================= */
bool isThreatAlreadyReported(String threatSignature, time_t cooldownSeconds = 3600) {
  time_t now = getCurrentUnixTime();
  
  for (int i = 0; i < reportedThreatsCount; i++) {
    if (lastReportedThreats[i] == threatSignature) {
      if (now - lastThreatTime[i] < cooldownSeconds) {
        return true;
      } else {
        lastThreatTime[i] = now;
        return false;
      }
    }
  }
  
  if (reportedThreatsCount < 10) {
    lastReportedThreats[reportedThreatsCount] = threatSignature;
    lastThreatTime[reportedThreatsCount] = now;
    reportedThreatsCount++;
  }
  
  return false;
}

bool isMeshNetwork(String bssid1, String bssid2) {
  // Mesh сети имеют одинаковые первые 3 октета MAC (OUI)
  String prefix1 = bssid1.substring(0, 8);
  String prefix2 = bssid2.substring(0, 8);
  return prefix1 == prefix2;
}

void detectSecurityThreats() {
  // 1. Evil Twin detection
  for (int i = 0; i < networkCount; i++) {
    for (int j = i + 1; j < networkCount; j++) {
      if (networks[i].ssid == networks[j].ssid && 
          networks[i].bssid != networks[j].bssid &&
          !networks[i].isHidden && !networks[j].isHidden) {
        
        // Пропускаем Mesh сети
        if (isMeshNetwork(networks[i].bssid, networks[j].bssid)) {
          continue;
        }
        
        // Проверяем, не сообщали ли уже
        String threatSig = "evil_twin_" + networks[i].ssid + "_" + networks[i].bssid + "_" + networks[j].bssid;
        
        if (!isThreatAlreadyReported(threatSig, 1800)) { // 30 минут кд
          threats[threatCount].type = "evil_twin";
          threats[threatCount].severity = "critical";
          threats[threatCount].description = "Две точки доступа с одинаковым SSID обнаружены";
          threats[threatCount].targetSSID = networks[i].ssid;
          threats[threatCount].targetBSSID = shortMAC(networks[i].bssid) + " и " + shortMAC(networks[j].bssid);
          threats[threatCount].detectedTime = getCurrentUnixTime();
          
          threatCount++;
          totalThreatsDetected++;
          lastScanHadThreats = true;
          
          Serial.printf("[THREAT] ⚠️ Evil Twin! SSID: %s, MAC: %s и %s\n",
                       networks[i].ssid.c_str(),
                       networks[i].bssid.c_str(),
                       networks[j].bssid.c_str());
        }
      }
    }
  }
  
  // 2. Multiple hidden networks
  if (hiddenNetworksCount >= 3) {
    String threatSig = "multiple_hidden_" + String(hiddenNetworksCount);
    
    if (!isThreatAlreadyReported(threatSig, 3600)) {
      threats[threatCount].type = "multiple_hidden";
      threats[threatCount].severity = "medium";
      threats[threatCount].description = "Обнаружено " + String(hiddenNetworksCount) + " скрытых точек доступа";
      threats[threatCount].targetSSID = "[MULTIPLE_HIDDEN]";
      threats[threatCount].targetBSSID = "";
      threats[threatCount].detectedTime = getCurrentUnixTime();
      
      threatCount++;
      lastScanHadThreats = true;
      
      Serial.printf("[THREAT] 🕵️ Много скрытых сетей: %d\n", hiddenNetworksCount);
    }
  }
  
  // 3. Open networks warning
  int openNetworks = 0;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].encryption == "OPEN" && !networks[i].isHidden) {
      openNetworks++;
    }
  }
  
  if (openNetworks >= 2) {
    String threatSig = "open_networks_" + String(openNetworks);
    
    if (!isThreatAlreadyReported(threatSig, 7200)) {
      threats[threatCount].type = "open_networks";
      threats[threatCount].severity = "low";
      threats[threatCount].description = "Обнаружено " + String(openNetworks) + " открытых сетей (без шифрования)";
      threats[threatCount].targetSSID = "[OPEN_NETWORKS]";
      threats[threatCount].targetBSSID = "";
      threats[threatCount].detectedTime = getCurrentUnixTime();
      
      threatCount++;
      Serial.printf("[THREAT] 🔓 Открытые сети: %d\n", openNetworks);
    }
  }
}

/* ================= TELEGRAM ================= */
bool sendToTelegram(String message, bool parseMarkdown = true) {
  Serial.println("[TG] Отправка в Telegram...");
  
  WiFiClientSecure client;
  client.setInsecure();
  client.setTimeout(5000);
  
  if (!client.connect("api.telegram.org", 443)) {
    Serial.println("[TG] ❌ Ошибка подключения к Telegram API");
    return false;
  }
  
  // URL encode
  String encodedMsg = "";
  for (unsigned int i = 0; i < message.length(); i++) {
    char c = message[i];
    if (c == '\n') encodedMsg += "%0A";
    else if (c == ' ') encodedMsg += "%20";
    else if (c == '*') encodedMsg += "*";
    else if (c == '_') encodedMsg += "_";
    else if (c == '`') encodedMsg += "`";
    else encodedMsg += c;
  }
  
  String url = "/bot" + String(TG_BOT_TOKEN) + 
               "/sendMessage?chat_id=" + TG_CHAT_ID + 
               "&text=" + encodedMsg;
  
  if (parseMarkdown) {
    url += "&parse_mode=Markdown";
  }
  
  String request = "GET " + url + " HTTP/1.1\r\n" +
                   "Host: api.telegram.org\r\n" +
                   "User-Agent: ESP8266-WiFi-IDS\r\n" +
                   "Connection: close\r\n\r\n";
  
  client.print(request);
  
  unsigned long timeout = millis();
  while (client.connected() && millis() - timeout < 3000) {
    if (client.available()) {
      String line = client.readStringUntil('\n');
      if (line.startsWith("HTTP/1.1 200")) {
        Serial.println("[TG] ✅ Сообщение отправлено!");
        client.stop();
        return true;
      }
    }
    delay(10);
  }
  
  client.stop();
  Serial.println("[TG] ⚠️ Таймаут отправки");
  return false;
}

void sendTelegramReport() {
  String message = "";
  String currentTime = getCurrentTimeString();
  
  if (threatCount > 0) {
    message = "🚨 *ОБНАРУЖЕНЫ УГРОЗЫ!*\n\n";
    message += "*Время:* " + currentTime + "\n\n";
    
    for (int i = 0; i < threatCount; i++) {
      message += "• *" + toUpperCaseString(threats[i].type) + "* (" + threats[i].severity + ")\n";
      message += "  " + threats[i].description + "\n";
      
      if (threats[i].type == "evil_twin") {
        message += "  SSID: `" + threats[i].targetSSID + "`\n";
        message += "  MAC: " + threats[i].targetBSSID + "\n";
      }
      
      // Время обнаружения
      if (timeSynced && threats[i].detectedTime > 0) {
        struct tm tm_info;
        localtime_r(&threats[i].detectedTime, &tm_info);
        char timeStr[9];
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &tm_info);
        message += "  Время: " + String(timeStr) + "\n";
      }
      
      message += "\n";
    }
    
    message += "*Статистика сканирования:*\n";
    
  } else {
    message = "✅ *ВСЕ ЧИСТО!*\n\n";
    message += "*Время:* " + currentTime + "\n";
    message += "*Цикл:* #" + String(totalCycles) + "\n\n";
  }
  
  // Общая статистика
  message += "📡 *Сетей обнаружено:* " + String(networkCount) + "\n";
  
  if (hiddenNetworksCount > 0) {
    message += "👻 *Скрытых сетей:* " + String(hiddenNetworksCount) + "\n";
  }
  
  int openNetworks = 0;
  int wpa2Networks = 0;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].encryption == "OPEN") openNetworks++;
    if (networks[i].encryption == "WPA2") wpa2Networks++;
  }
  
  if (openNetworks > 0) {
    message += "🔓 *Открытых сетей:* " + String(openNetworks) + "\n";
  }
  message += "🔐 *WPA2 сетей:* " + String(wpa2Networks) + "\n";
  
  message += "⚠️ *Всего угроз за время работы:* " + String(totalThreatsDetected) + "\n\n";
  
  // Топ сетей по сигналу
  if (networkCount > 0) {
    message += "*Топ-3 сети по сигналу:*\n";
    
    // Сортируем сети по RSSI (сильнейший сигнал первый)
    for (int i = 0; i < networkCount - 1; i++) {
      for (int j = i + 1; j < networkCount; j++) {
        if (networks[j].rssi > networks[i].rssi) {
          WiFiNetwork temp = networks[i];
          networks[i] = networks[j];
          networks[j] = temp;
        }
      }
    }
    
    int shown = 0;
    for (int i = 0; i < networkCount && shown < 3; i++) {
      if (!networks[i].isHidden) {
        String icon = networks[i].encryption == "OPEN" ? "🔓" : "🔐";
        String macShort = shortMAC(networks[i].bssid);
        
        message += icon + " `" + networks[i].ssid + "`\n";
        message += "  📶 " + String(networks[i].rssi) + "dBm | ";
        message += "📺 ch" + String(networks[i].channel) + " | ";
        message += "🔑 " + networks[i].encryption + "\n";
        message += "  🆔 " + macShort + "\n\n";
        
        shown++;
      }
    }
  }
  
  message += "*Устройство:* `" + DEVICE_ID + "`\n";
  message += "*IP:* " + WiFi.localIP().toString() + "\n";
  
  if (timeSynced) {
    message += "*Дата/время:* " + getCurrentDateTimeString() + "\n";
  }
  
  sendToTelegram(message);
}

/* ================= ОТПРАВКА НА СЕРВЕР ================= */
bool sendToServer() {
  Serial.println("[SERVER] Подготовка данных для сервера...");
  
  // Формируем JSON
  String jsonData = "{";
  
  // 1. Метаданные
  jsonData += "\"device_id\":\"" + escapeJsonString(DEVICE_ID) + "\",";
  jsonData += "\"timestamp\":" + String(getCurrentUnixTime()) + ",";
  jsonData += "\"local_time\":\"" + getCurrentDateTimeString() + "\",";
  jsonData += "\"scan_duration_ms\":" + String(SCAN_DURATION) + ",";
  jsonData += "\"network_count\":" + String(networkCount) + ",";
  jsonData += "\"threat_count\":" + String(threatCount) + ",";
  jsonData += "\"hidden_networks_count\":" + String(hiddenNetworksCount) + ",";
  jsonData += "\"ip_address\":\"" + WiFi.localIP().toString() + "\",";
  jsonData += "\"wifi_rssi\":" + String(WiFi.RSSI()) + ",";
  jsonData += "\"cycle_number\":" + String(totalCycles) + ",";
  jsonData += "\"time_synced\":" + String(timeSynced ? "true" : "false") + ",";
  
  // 2. Сети
  jsonData += "\"networks\":[";
  for (int i = 0; i < networkCount; i++) {
    if (i > 0) jsonData += ",";
    jsonData += "{";
    jsonData += "\"ssid\":\"" + escapeJsonString(networks[i].ssid) + "\",";
    jsonData += "\"bssid\":\"" + networks[i].bssid + "\",";
    jsonData += "\"channel\":" + String(networks[i].channel) + ",";
    jsonData += "\"rssi\":" + String(networks[i].rssi) + ",";
    jsonData += "\"encryption\":\"" + networks[i].encryption + "\",";
    jsonData += "\"is_hidden\":" + String(networks[i].isHidden ? "true" : "false") + ",";
    jsonData += "\"first_seen\":" + String(networks[i].firstSeen) + ",";
    jsonData += "\"last_seen\":" + String(networks[i].lastSeen);
    jsonData += "}";
  }
  jsonData += "],";
  
  // 3. Угрозы
  jsonData += "\"threats\":[";
  bool firstThreat = true;
  for (int i = 0; i < threatCount; i++) {
    // Только новые угрозы
    String threatSig = threats[i].type + "_" + threats[i].targetSSID;
    if (!isThreatAlreadyReported(threatSig, 0)) {
      if (!firstThreat) jsonData += ",";
      firstThreat = false;
      
      jsonData += "{";
      jsonData += "\"type\":\"" + threats[i].type + "\",";
      jsonData += "\"severity\":\"" + threats[i].severity + "\",";
      jsonData += "\"description\":\"" + escapeJsonString(threats[i].description) + "\",";
      jsonData += "\"target_ssid\":\"" + escapeJsonString(threats[i].targetSSID) + "\",";
      jsonData += "\"target_bssid\":\"" + threats[i].targetBSSID + "\",";
      jsonData += "\"detected_at\":" + String(threats[i].detectedTime);
      jsonData += "}";
    }
  }
  jsonData += "],";
  
  // 4. Статистика
  jsonData += "\"statistics\":{";
  jsonData += "\"total_cycles\":" + String(totalCycles) + ",";
  jsonData += "\"total_threats_detected\":" + String(totalThreatsDetected) + ",";
  jsonData += "\"total_networks_detected\":" + String(totalNetworks) + ",";
  jsonData += "\"avg_networks_per_scan\":" + String(totalCycles > 0 ? totalNetworks / totalCycles : 0);
  jsonData += "}";
  
  jsonData += "}";
  
  Serial.printf("[SERVER] JSON размер: %d байт\n", jsonData.length());
  
  // Отправка
  WiFiClient client;
  
  if (!client.connect(SERVER_HOST, SERVER_PORT)) {
    Serial.println("[SERVER] ❌ Ошибка подключения к серверу!");
    return false;
  }
  
  Serial.println("[SERVER] ✅ Подключено, отправляю данные...");
  
  String httpRequest = "POST " + String(SERVER_API) + " HTTP/1.1\r\n";
  httpRequest += "Host: " + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "\r\n";
  httpRequest += "User-Agent: ESP8266-WiFi-IDS\r\n";
  httpRequest += "Content-Type: application/json\r\n";
  httpRequest += "Content-Length: " + String(jsonData.length()) + "\r\n";
  httpRequest += "Connection: close\r\n\r\n";
  httpRequest += jsonData;
  
  client.print(httpRequest);
  Serial.println("[SERVER] 📤 Запрос отправлен");
  
  // Читаем ответ
  unsigned long timeout = millis();
  bool success = false;
  
  while (client.connected() && millis() - timeout < 5000) {
    if (client.available()) {
      String line = client.readStringUntil('\n');
      line.trim();
      
      if (line.length() > 0) {
        if (line.startsWith("HTTP/1.1 200") || line.startsWith("HTTP/1.1 201")) {
          success = true;
          Serial.println("[SERVER] ✅ Данные приняты сервером!");
        }
      }
      
      if (line.length() == 0) {
        break;
      }
    }
    delay(10);
  }
  
  client.stop();
  
  if (!success) {
    Serial.println("[SERVER] ⚠️ Проблема с ответом сервера");
  }
  
  return success;
}

/* ================= ОСНОВНЫЕ ФУНКЦИИ ================= */
void sendStartupMessage() {
  String message = "🛡️ *WiFi IDS System Activated!*\n\n";
  message += "*Устройство:* `" + DEVICE_ID + "`\n";
  message += "*IP адрес:* " + WiFi.localIP().toString() + "\n";
  message += "*Версия:* 3.0 (Time Sync + MAC)\n";
  
  if (timeSynced) {
    message += "*Время синхронизировано:* " + getCurrentDateTimeString() + "\n";
  } else {
    message += "*Время:* не синхронизировано\n";
  }
  
  message += "*Цикл мониторинга:* 60 секунд\n\n";
  message += "_Система готова к работе. Отчеты будут приходить каждую минуту._";
  
  sendToTelegram(message);
}

void processScanCycle() {
  totalCycles++;
  
  Serial.printf("\n=== ЦИКЛ СКАНИРОВАНИЯ #%lu ===\n", totalCycles);
  Serial.println("[TIME] Текущее время: " + getCurrentDateTimeString());
  
  // Проверяем синхронизацию времени
  if (!timeSynced || (millis() - lastTimeSync > TIME_SYNC_INTERVAL)) {
    syncTime();
  }
  
  // Шаг 1: Сканирование
  Serial.println("[1/4] Сканирование WiFi...");
  unsigned long scanStart = millis();
  performWiFiScan();
  Serial.printf("[SCAN] Длительность: %.1f сек\n", (millis() - scanStart) / 1000.0);
  
  // Шаг 2: Подключение к WiFi
  Serial.println("[2/4] Подключение к WiFi...");
  if (!connectToWiFi()) {
    Serial.println("[ERROR] ❌ Не удалось подключиться!");
    delay(30000);
    return;
  }
  
  // Шаг 3: Telegram отчет
  Serial.println("[3/4] Отчет в Telegram...");
  sendTelegramReport();
  
  // Шаг 4: Отправка на сервер
  Serial.println("[4/4] Отправка на сервер...");
  bool serverSuccess = sendToServer();
  
  if (serverSuccess) {
    Serial.println("[SUCCESS] ✅ Все данные отправлены!");
  } else {
    Serial.println("[WARNING] ⚠️ Проблемы с отправкой на сервер");
  }
  
  Serial.printf("[CYCLE] 🔄 Цикл #%lu завершен\n\n", totalCycles);
}

/* ================= SETUP И LOOP ================= */
void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n" + DEVICE_ID + " - WiFi IDS System v3.0");
  Serial.println("========================================");
  Serial.println("Функции:");
  Serial.println("  • Синхронизация времени по NTP");
  Serial.println("  • Форматирование MAC адресов");
  Serial.println("  • Умное обнаружение угроз");
  Serial.println("  • Telegram + Server отчеты");
  Serial.println("========================================\n");
  
  // Подключаемся к WiFi
  if (!connectToWiFi()) {
    Serial.println("[FATAL] ❌ Критическая ошибка WiFi!");
    ESP.restart();
  }
  
  // Синхронизация времени
  syncTime();
  
  // Стартовое сообщение
  sendStartupMessage();
  
  Serial.println("\n[SYSTEM] ✅ Система запущена! Начинаю мониторинг...\n");
}

void loop() {
  processScanCycle();
  
  Serial.printf("[WAIT] ⏳ Ожидание %d секунд...\n\n", CYCLE_DELAY / 1000);
  delay(CYCLE_DELAY);
}

