import re
import requests
import validators
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# === HARDCODED API KEYS ===
ABUSEIPDB_API_KEYS = [
    "eca572ae930dd61ded6eb59112d8bb15ea657fb34a069ec89543fa9a0d6e47ecd5bac8457566bdf3",
    "399456c14ee1b25c6cc9218a3257eeee373259c9aa813e0cddbe3ba296cbd651a975e70b11b8de33"
]
VIRUSTOTAL_API_KEY = "3302110c35e5e509eb7a27bbef49c6a5c5fed7051e7fd6f6fc36d6cdebca1673"
TELEGRAM_BOT_TOKEN = "7767832251:AAHSssrwQX6TuLLwkliJgV3EmpN3KGVb82I"  # Replace with your actual bot token

# Track current AbuseIPDB key in use (for rotation)
abuse_key_index = 0

# === HELPERS ===

def extract_ips_and_urls(text):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    urls = [token for token in text.split() if validators.url(token)]
    return ips, urls


def check_abuseipdb(ip):
    global abuse_key_index
    key = ABUSEIPDB_API_KEYS[abuse_key_index % len(ABUSEIPDB_API_KEYS)]
    abuse_key_index += 1

    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        if r.status_code == 200:
            data = r.json()["data"]
            return f"🔍 IP: {ip}\n⚠️ Score: {data['abuseConfidenceScore']}%\n🌍 Country: {data.get('countryCode', 'N/A')}\n"
        else:
            return f"❌ IP: {ip} - Error {r.status_code}: {r.text}"
    except Exception as e:
        return f"❌ IP: {ip} - Exception: {str(e)}"


def check_virustotal(url):
    # Encode URL before sending to VirusTotal
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # Step 1: Submit URL for scan
        r = requests.post(vt_url, headers=headers, data={"url": url})
        if r.status_code != 200:
            return f"❌ URL: {url} - Error {r.status_code}: {r.text}"

        url_id = r.json()["data"]["id"]

        # Step 2: Get scan result
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        a = requests.get(analysis_url, headers=headers).json()
        stats = a["data"]["attributes"]["stats"]

        return (f"🌐 URL: {url}\n"
                f"🛑 Malicious: {stats.get('malicious', 0)}\n"
                f"⚠️ Suspicious: {stats.get('suspicious', 0)}\n"
                f"✅ Harmless: {stats.get('harmless', 0)}\n")
    except Exception as e:
        return f"❌ URL: {url} - Exception: {str(e)}"

# === TELEGRAM BOT ===

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Send me a list of IPs and URLs and I’ll scan them for abuse & malware!")

async def scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    ips, urls = extract_ips_and_urls(text)
    response_lines = []

    if ips:
        for ip in ips:
            response_lines.append(check_abuseipdb(ip))
    if urls:
        for url in urls:
            response_lines.append(check_virustotal(url))

    if not response_lines:
        response_lines.append("❓ No valid IPs or URLs detected.")

    # Send results back in chunks to avoid Telegram limits
    chunk = ""
    for line in response_lines:
        if len(chunk) + len(line) > 4000:
            await update.message.reply_text(chunk)
            chunk = ""
        chunk += line + "\n"
    if chunk:
        await update.message.reply_text(chunk)

# === MAIN ===

def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_message))
    app.run_polling()

if __name__ == "__main__":
    main()
