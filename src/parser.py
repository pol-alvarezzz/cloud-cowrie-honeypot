import json
import pandas as pd
from pathlib import Path
from datetime import datetime


LOG_DIR = Path("logs")


def load_all_logs() -> pd.DataFrame:
    #Lee todos los cowrie.json* y devuelve un DataFrame con todos los eventos.
    records = []
    files = sorted(LOG_DIR.glob("cowrie.json*"))

    if not files:
        raise FileNotFoundError(f"No se encontraron logs en {LOG_DIR.resolve()}")

    print(f"Cargando {len(files)} ficheros de log...")
    for f in files:
        with open(f, "r") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    print(f"Total de eventos cargados: {len(df)}")
    return df


def get_connections(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df[df["eventid"] == "cowrie.session.connect"]
        .copy()
        [["session", "src_ip", "timestamp", "src_port"]]
        .drop_duplicates(subset="session")
        .reset_index(drop=True)
    )


def get_login_attempts(df: pd.DataFrame) -> pd.DataFrame:
    #Intentos de login con usuario y contraseña
    mask = df["eventid"].isin([
        "cowrie.login.failed",
        "cowrie.login.success"
    ])
    cols = ["session", "src_ip", "timestamp", "eventid"]
    optional = ["username", "password"]
    for col in optional:
        if col in df.columns:
            cols.append(col)

    return df[mask][cols].copy().reset_index(drop=True)


def get_commands(df: pd.DataFrame) -> pd.DataFrame:
    #comandos ejecutados dentro de las sesiones
    mask = df["eventid"].isin([
        "cowrie.command.input",
        "cowrie.command.failed"
    ])
    cols = ["session", "src_ip", "timestamp", "eventid"]
    if "input" in df.columns:
        cols.append("input")

    return df[mask][cols].copy().reset_index(drop=True)


def get_downloads(df: pd.DataFrame) -> pd.DataFrame:
    #ficheros que los atacantes intentaron descargar
    mask = df["eventid"] == "cowrie.session.file_download"
    cols = ["session", "src_ip", "timestamp"]
    for col in ["url", "outfile", "shasum"]:
        if col in df.columns:
            cols.append(col)

    return df[mask][cols].copy().reset_index(drop=True)


def get_summary(df: pd.DataFrame) -> dict:
    #resumen rapido de los datos para mostrar en el dashboard
    connections = get_connections(df)
    logins = get_login_attempts(df)
    commands = get_commands(df)
    downloads = get_downloads(df)

    return {
        "total_events": len(df),
        "total_sessions": connections["session"].nunique(),
        "unique_ips": connections["src_ip"].nunique(),
        "login_attempts": len(logins),
        "successful_logins": len(logins[logins["eventid"] == "cowrie.login.success"]),
        "commands_run": len(commands),
        "files_downloaded": len(downloads),
        "date_range": (
            df["timestamp"].min().strftime("%d %b %Y"),
            df["timestamp"].max().strftime("%d %b %Y"),
        ),
    }


if __name__ == "__main__":
    df = load_all_logs()
    summary = get_summary(df)

    print("\n=== RESUMEN DEL HONEYPOT ===")
    print(f"Periodo:              {summary['date_range'][0]} → {summary['date_range'][1]}")
    print(f"Total eventos:        {summary['total_events']:,}")
    print(f"Sesiones únicas:      {summary['total_sessions']:,}")
    print(f"IPs únicas:           {summary['unique_ips']:,}")
    print(f"Intentos de login:    {summary['login_attempts']:,}")
    print(f"Logins exitosos:      {summary['successful_logins']:,}")
    print(f"Comandos ejecutados:  {summary['commands_run']:,}")
    print(f"Ficheros descargados: {summary['files_downloaded']:,}")

    print("\n=== TIPOS DE EVENTOS ===")
    print(df["eventid"].value_counts().to_string())