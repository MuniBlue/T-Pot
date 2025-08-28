import requests
import csv

# Clave de API de AbuseIPDB (ya incluida)
API_KEY = "d70885dd53293218cf49b0857a3f51d2446ec4e4826d3042b902a6aa569bb181ec2e54705da7bc18"

# Lista de IPs a consultar
ips = [
    "89.248.165.133", "89.248.163.83", "1.95.78.10",
    "89.248.163.57", "89.248.163.218", "143.110.142.48",
    "149.40.50.205", "146.70.212.85", "185.91.127.81",
    "134.122.78.78"
]

# Encabezados de la petición
headers = {
    "Accept": "application/json",
    "Key": API_KEY
}

# Archivo de salida
output_file = "abuseipdb_resultados.csv"

# Abrimos el CSV en modo escritura
with open(output_file, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow([
        "IP", "Abuse Score", "Total Reportes", "Último Reporte",
        "País", "Dominio", "ISP", "Tipo de Uso", "Hostname"
    ])

    for ip in ips:
        print(f"🔍 Consultando: {ip}")
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params={"ipAddress": ip, "maxAgeInDays": "90"}
            )

            if resp.status_code == 200:
                data = resp.json()["data"]
                writer.writerow([
                    ip,
                    data.get("abuseConfidenceScore", 0),
                    data.get("totalReports", 0),
                    data.get("lastReportedAt", "N/A"),
                    data.get("countryCode", "N/A"),
                    data.get("domain", "N/A"),
                    data.get("isp", "N/A"),
                    data.get("usageType", "N/A"),
                    data.get("hostnames", ["N/A"])[0] if data.get("hostnames") else "N/A"
                ])
            else:
                print(f"❌ Error {resp.status_code} al consultar {ip}")
                writer.writerow([ip, "ERROR", "", "", "", "", "", "", ""])
        except Exception as e:
            print(f"❗ Excepción para {ip}: {e}")
            writer.writerow([ip, "ERROR", "", "", "", "", "", "", ""])

print(f"\n✅ Informe generado: {output_file}")
