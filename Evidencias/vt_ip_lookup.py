import requests
import csv
from datetime import datetime

API_KEY = "f4682ada933f08e88e386d9125ffda6a83f6e36fccc195cc4ca71bf0298e7f40"
IP_LIST = [
    "89.248.165.133", "89.248.163.83", "1.95.78.10",
    "89.248.163.57", "89.248.163.218", "143.110.142.48",
    "149.40.50.205", "146.70.212.85", "185.91.127.81",
    "134.122.78.78"
]

CSV_FILE = "vt_resultados_completos.csv"

headers = {
    "x-apikey": API_KEY
}

with open(CSV_FILE, mode="w", newline='', encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow([
        "IP", "Maliciosos", "Sospechosos", "Último_Análisis",
        "País", "ASN", "ISP", "Categorías", "Enlace"
    ])

    for ip in IP_LIST:
        print(f"🔎 Consultando: {ip}")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print(f"⚠️ Error {response.status_code} → {response.text}")
            writer.writerow([ip, "ERROR", "", "", "", "", "", "", ""])
            continue

        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        date_ts = data.get("last_analysis_date")
        date_str = datetime.utcfromtimestamp(date_ts).strftime("%d/%m/%Y %H:%M") if date_ts else "N/A"

        categories = data.get("categories", {})
        categories_text = ";".join(categories.values()) if categories else "N/A"

        writer.writerow([
            ip,
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            date_str,
            data.get("country", "N/A"),
            data.get("asn", "N/A"),
            data.get("as_owner", "N/A").replace(",", " "),
            categories_text,
            f"https://www.virustotal.com/gui/ip-address/{ip}"
        ])

print(f"\n✅ Informe guardado en {CSV_FILE}")
