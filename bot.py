import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import requests
import re

# Hardcoded API keys and token (not recommended for production; use GitHub Secrets or similar)
TELEGRAM_TOKEN = "8090856043:AAGGQrdyVWhHEWT8qfhQlT9nmSqHaQ6mrtc"
ABUSEIPDB_KEY = "eca572ae930dd61ded6eb59112d8bb15ea657fb34a069ec89543fa9a0d6e47ecd5bac8457566bdf3"
VIRUSTOTAL_KEY = "3302110c35e5e509eb7a27bbef49c6a5c5fed7051e7fd6f6fc36d6cdebca1673"

# Initialize the Telegram bot
application = Application.builder().token(TELEGRAM_TOKEN).build()

# AbuseIPDB API check for IP
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if data["data"]["isPublic"]:
            return (f"IP: {ip}\n"
                    f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}%\n"
                    f"Country: {data['data']['countryCode']}\n"
                    f"ISP: {data['data']['isp']}\n"
                    f"Total Reports: {data['data']['totalReports']}")
        else:
            return f"IP: {ip} - No public reports found."
    except requests.exceptions.RequestException as e:
        return f"Error checking IP {ip}: {str(e)}"

# VirusTotal API check for URL
def check_url(url):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_KEY
    }
    payload = {"url": url}
    try:
        response = requests.post(vt_url, headers=headers, data=payload)
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"]["stats"]
        return (f"URL: {url}\n"
                f"Malicious: {stats['malicious']}\n"
                f"Suspicious: {stats['suspicious']}\n"
                f"Harmless: {stats['harmless']}\n"
                f"Undetected: {stats['undetected']}")
    except requests.exceptions.RequestException as e:
        return f"Error checking URL {url}: {str(e)}"

# VirusTotal API check for file hash
def check_file_hash(file_hash):
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_KEY
    }
    try:
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return (f"File Hash: {file_hash}\n"
                f"Malicious: {stats['malicious']}\n"
                f"Suspicious: {stats['suspicious']}\n"
                f"Harmless: {stats['harmless']}\n"
                f"Undetected: {stats['undetected']}")
    except requests.exceptions.RequestException as e:
        return f"Error checking file hash {file_hash}: {str(e)}"

# Start command handler
async def start(update, context):
    await update.message.reply_text(
        "Welcome to the IP/URL/Hash Checker Bot!\n"
        "Commands:\n"
        "/check_ip <IP> - Check a single IP address\n"
        "/check_url <URL> - Check a single URL\n"
        "/check_hash <hash> - Check a file hash\n"
        "/bulk_check <type> <items> - Check multiple IPs, URLs, or hashes (type: ip, url, hash)\n"
        "Example: /bulk_check ip 1.1.1.1 8.8.8.8"
    )

# Handler for checking single IP
async def check_ip_command(update, context):
    if not context.args:
        await update.message.reply_text("Please provide an IP address. Example: /check_ip 1.1.1.1")
        return
    ip = context.args[0]
    result = check_ip(ip)
    await update.message.reply_text(result)

# Handler for checking single URL
async def check_url_command(update, context):
    if not context.args:
        await update.message.reply_text("Please provide a URL. Example: /check_url https://example.com")
        return
    url = context.args[0]
    result = check_url(url)
    await update.message.reply_text(result)

# Handler for checking single file hash
async def check_hash_command(update, context):
    if not context.args:
        await update.message.reply_text("Please provide a file hash. Example: /check_hash <hash>")
        return
    file_hash = context.args[0]
    result = check_file_hash(file_hash)
    await update.message.reply_text(result)

# Handler for bulk checks
async def bulk_check(update, context):
    if len(context.args) < 2:
        await update.message.reply_text("Please provide type (ip, url, hash) and items. Example: /bulk_check ip 1.1.1.1 8.8.8.8")
        return
    check_type = context.args[0].lower()
    items = context.args[1:]
    
    results = []
    if check_type == "ip":
        for ip in items:
            results.append(check_ip(ip))
    elif check_type == "url":
        for url in items:
            results.append(check_url(url))
    elif check_type == "hash":
        for file_hash in items:
            results.append(check_file_hash(file_hash))
    else:
        await update.message.reply_text("Invalid type. Use 'ip', 'url', or 'hash'.")
        return
    
    await update.message.reply_text("\n\n".join(results))

# Main function to run the bot
def main():
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("check_ip", check_ip_command))
    application.add_handler(CommandHandler("check_url", check_url_command))
    application.add_handler(CommandHandler("check_hash", check_hash_command))
    application.add_handler(CommandHandler("bulk_check", bulk_check))
    
    # Start the bot
    application.run_polling()

if __name__ == "__main__":
    main()
