import time
import json
import requests
import pandas as pd
from pathlib import Path


CACHE_FILE = Path("data/geoip_cache.json")
API_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100  # limite d ips por petición
RATE_LIMIT_DELAY = 1.5  # segundos entre batches 


def load_cache() -> dict:
    if CACHE_FILE.exists():
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def save_cache(cache: dict):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def geolocate_ips(ips: list[str]) -> dict:
    
    """ Geolocaliza una lista de IPs usando ip-api.com (batch).
    Usa caché local para no repetir peticiones ya hechas.
    Devuelve dict: {ip -> {country, country_code, city, lat, lon, org}} """
    
    cache = load_cache()
    to_fetch = [ip for ip in ips if ip not in cache]

    if not to_fetch:
        print(f"Todas las IPs en caché ({len(cache)} entradas)")
    else:
        print(f"Geolocalizando {len(to_fetch)} IPs nuevas (en caché: {len(cache)})...")
        batches = [to_fetch[i:i+BATCH_SIZE] for i in range(0, len(to_fetch), BATCH_SIZE)]

        for i, batch in enumerate(batches):
            payload = [{"query": ip, "fields": "status,message,country,countryCode,city,lat,lon,org,query"} for ip in batch]
            try:
                resp = requests.post(API_URL, json=payload, timeout=15)
                resp.raise_for_status()
                results = resp.json()

                for entry in results:
                    ip = entry.get("query")
                    if entry.get("status") == "success":
                        cache[ip] = {
                            "country":      entry.get("country", "Unknown"),
                            "country_code": entry.get("countryCode", ""),
                            "city":         entry.get("city", ""),
                            "lat":          entry.get("lat", 0),
                            "lon":          entry.get("lon", 0),
                            "org":          entry.get("org", ""),
                        }
                    else:
                        cache[ip] = {
                            "country": "Unknown", "country_code": "",
                            "city": "", "lat": 0, "lon": 0, "org": "",
                        }

                save_cache(cache)
                print(f"  Batch {i+1}/{len(batches)} completado ({len(batch)} IPs)")

                if i < len(batches) - 1:
                    time.sleep(RATE_LIMIT_DELAY)

            except requests.RequestException as e:
                print(f"  Error en batch {i+1}: {e}")
                for ip in batch:
                    if ip not in cache:
                        cache[ip] = {
                            "country": "Unknown", "country_code": "",
                            "city": "", "lat": 0, "lon": 0, "org": "",
                        }

    return cache


def enrich_dataframe(df: pd.DataFrame, ip_col: str = "src_ip") -> pd.DataFrame:

    #Añade columnas de geolocalización a un DataFrame que tenga una columna de IPs.
    
    unique_ips = df[ip_col].dropna().unique().tolist()
    geo = geolocate_ips(unique_ips)

    df = df.copy()
    df["country"]      = df[ip_col].map(lambda ip: geo.get(ip, {}).get("country", "Unknown"))
    df["country_code"] = df[ip_col].map(lambda ip: geo.get(ip, {}).get("country_code", ""))
    df["city"]         = df[ip_col].map(lambda ip: geo.get(ip, {}).get("city", ""))
    df["lat"]          = df[ip_col].map(lambda ip: geo.get(ip, {}).get("lat", 0))
    df["lon"]          = df[ip_col].map(lambda ip: geo.get(ip, {}).get("lon", 0))
    df["org"]          = df[ip_col].map(lambda ip: geo.get(ip, {}).get("org", ""))

    return df


if __name__ == "__main__":
    from parser import load_all_logs, get_connections

    df = load_all_logs()
    connections = get_connections(df)
    enriched = enrich_dataframe(connections)

    print("\n=== TOP 10 PAÍSES ATACANTES ===")
    print(enriched["country"].value_counts().head(10).to_string())

    print("\n=== TOP 10 ORGANIZACIONES / ASN ===")
    print(enriched["org"].value_counts().head(10).to_string())