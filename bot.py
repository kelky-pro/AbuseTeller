import os
import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import requests
import re

# Load environment variables
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")

# Validate environment variables
if not all([TELEGRAM_TOKEN, ABUSEIPDB_KEY, VIRUSTOTAL_KEY]):
    raise ValueError("Missing required environment variables: TELEGRAM_TOKEN, ABUSEIPDB_KEY, or VIRUSTOTAL_KEY")

# Initialize the Telegram bot
application = Application.builder().token(TELEGRAM_TOKEN).build()

# AbuseIPDB API check for IP
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if data["data"]["isPublic"]:
            return (f"IP: {ip}\n"
                    f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}%\n"
                    f"Country: {data['data']['countryCode'] or 'N/A'}\n"
                    f"ISP: {data['data']['isp'] or 'N/A'}\n"
                    f"Total Reports: {data['data']['totalReports']}")
        return f"IP: {ip} - No public reports found."
    except requests.exceptions.RequestException as e:
        return f"IP: {ip} - Error: {str(e)}"

# VirusTotal API check for URL
def check_url(url):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
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
        return f"URL: {url} - Error: {str(e)}"

# VirusTotal API check for file hash
def check_file_hash(file_hash):
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
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
        return f"File Hash: {file_hash} - Error: {str(e)}"

# Start command handler
async def start(update, context):
    await update.message.reply_text(
        "Welcome to the IP/URL/Hash Checker Bot!\n"
        "Commands:\n"
        "/check_ip <IP> - Check a single IP address\n"
        "/check_url <URL> - Check a single URL\n"
        "/check_hash <hash> - Check a file hash\n"
        "/bulk_check <type> <items> - Check multiple IPs, URLs, or hashes (type: ip, url, hash)\n"
        "Example: /bulk_check ip 1.1.1.1 8.8.8.8\n"
        "Or: /bulk_check url https://example.com https://test.com\n"
        "Items can be separated by spaces or newlines."
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
async def bulk_check_command(update, context):
    if len(context.args) < 2:
        await update.message.reply_text(
            "Please provide type (ip, url, hash) and items. Examples:\n"
            "/bulk_check ip 1.1.1.1 8.8.8.8\n"
            "/bulk_check url https://example.com https://test.com\n"
            "/bulk_check hash <hash1> <hash2>\n"
            "Items can be separated by spaces or newlines."
        )
        return

    check_type = context.args[0].lower()
    # Join all arguments after type and split by spaces or newlines
    raw_input = " ".join(context.args[1:])
    # Split by spaces or newlines, remove empty strings
    items = [item.strip() for item in re.split(r"\s+|\n+", raw_input) if item.strip()]

    if not items:
        await update.message.reply_text("No valid items provided.")
        return

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

    # Format results with clear separation
    formatted_results = "\n\n".join([f"Result {i+1}:\n{result}" for i, result in enumerate(results)])
    # Split response if it exceeds Telegram's 4096-character limit
    if len(formatted_results) <= 4096:
        await update.message.reply_text(formatted_results or "No results found.")
    else:
        parts = []
        current_part = ""
        for result in results:
            if len(current_part) + len(result) + 2 <= 4096:
                current_part += f"{result}\n\n"
            else:
                parts.append(current_part)
                current_part = f"{result}\n\n"
        if current_part:
            parts.append(current_part)
        for i, part in enumerate(parts):
            await update.message.reply_text(f"Part {i+1}:\n{part}")

# Main function to run the bot
def main():
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("check_ip", check_ip_command))
    application.add_handler(CommandHandler("check_url", check_url_command))
    application.add_handler(CommandHandler("check_hash", check_hash_command))
    application.add_handler(CommandHandler("bulk_check", bulk_check_command))
    
    # Start the bot with polling
    print("Starting bot with polling...")
    application.run_polling()

if __name__ == "__main__":
    main()
