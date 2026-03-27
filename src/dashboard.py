import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, html, dcc, dash_table
import dash_bootstrap_components as dbc

from parser import load_all_logs, get_connections, get_login_attempts, get_commands, get_summary
from geoip import enrich_dataframe

# Carga de datos 

print("Cargando datos...")
df_raw        = load_all_logs()
connections   = enrich_dataframe(get_connections(df_raw))
logins        = get_login_attempts(df_raw)
commands      = get_commands(df_raw)
summary       = get_summary(df_raw)

# Merge para tener país en logins
logins = logins.merge(
    connections[["session", "country", "country_code", "org", "lat", "lon"]],
    on="session", how="left"
)

BG        = "#0f1117"
CARD_BG   = "#1a1d27"
ACCENT    = "#00d4ff"
DANGER    = "#ff4757"
SUCCESS   = "#2ed573"
WARNING   = "#ffa502"
TEXT      = "#e0e0e0"
MUTED     = "#8892a4"

card_style = {
    "backgroundColor": CARD_BG,
    "borderRadius": "12px",
    "padding": "20px",
    "marginBottom": "20px",
    "border": f"1px solid #2a2d3a",
}

stat_card_style = {
    **card_style,
    "textAlign": "center",
    "padding": "24px 16px",
}

plot_cfg = {"displayModeBar": False}

PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color=TEXT, family="Inter, sans-serif"),
    margin=dict(l=10, r=10, t=30, b=10),
    legend=dict(bgcolor="rgba(0,0,0,0)"),
)

# Helpers 

def stat_card(label, value, color=ACCENT, icon=""):
    return html.Div([
        html.Div(f"{icon}  {value}", style={
            "fontSize": "2.2rem", "fontWeight": "700",
            "color": color, "marginBottom": "6px"
        }),
        html.Div(label, style={"color": MUTED, "fontSize": "0.85rem", "textTransform": "uppercase", "letterSpacing": "1px"})
    ], style=stat_card_style)


def section_title(text):
    return html.H3(text, style={
        "color": TEXT, "fontWeight": "600",
        "marginBottom": "16px", "fontSize": "1.1rem",
        "borderLeft": f"3px solid {ACCENT}",
        "paddingLeft": "12px",
    })


# Mapa de calor mundial por país
country_counts = connections.groupby(["country", "country_code"]).size().reset_index(name="sessions")
fig_map = px.choropleth(
    country_counts,
    locations="country_code",
    color="sessions",
    hover_name="country",
    color_continuous_scale=[[0, "#1a1d27"], [0.2, "#003d4d"], [0.5, "#006080"], [1, ACCENT]],
    title="Origen de ataques por país",
)
fig_map.update_layout(**PLOT_LAYOUT, title_font_color=TEXT, coloraxis_colorbar=dict(
    title="Sesiones", tickfont=dict(color=MUTED)
))
fig_map.update_geos(
    showframe=False, showcoastlines=True,
    coastlinecolor="#2a2d3a", landcolor="#1a1d27",
    oceancolor=BG, showocean=True,
    bgcolor="rgba(0,0,0,0)",
)

# Ataques por hora del día
df_raw["hour"] = df_raw["timestamp"].dt.hour
hourly = df_raw[df_raw["eventid"] == "cowrie.session.connect"].groupby("hour").size().reset_index(name="count")
all_hours = pd.DataFrame({"hour": range(24)})
hourly = all_hours.merge(hourly, on="hour", how="left").fillna(0)
fig_hourly = go.Figure(go.Bar(
    x=hourly["hour"], y=hourly["count"],
    marker_color=ACCENT, marker_opacity=0.8,
    hovertemplate="<b>%{x}:00h</b><br>Conexiones: %{y}<extra></extra>",
))
fig_hourly.update_layout(**PLOT_LAYOUT, title="Conexiones por hora del día (UTC)",
    xaxis=dict(tickmode="linear", tick0=0, dtick=2, gridcolor="#2a2d3a", title="Hora"),
    yaxis=dict(gridcolor="#2a2d3a", title="Conexiones"),
)

# Evolución diaria de ataques
df_raw["date"] = df_raw["timestamp"].dt.date
daily = df_raw[df_raw["eventid"] == "cowrie.session.connect"].groupby("date").size().reset_index(name="sessions")
fig_daily = go.Figure(go.Scatter(
    x=daily["date"], y=daily["sessions"],
    mode="lines+markers",
    line=dict(color=ACCENT, width=2),
    marker=dict(size=6, color=ACCENT),
    fill="tozeroy", fillcolor=f"rgba(0,212,255,0.08)",
    hovertemplate="<b>%{x}</b><br>Sesiones: %{y}<extra></extra>",
))
fig_daily.update_layout(**PLOT_LAYOUT, title="Sesiones diarias",
    xaxis=dict(gridcolor="#2a2d3a"),
    yaxis=dict(gridcolor="#2a2d3a", title="Sesiones"),
)

# Top contraseñas
if "password" in logins.columns:
    top_pass = (
        logins[logins["password"].notna()]
        ["password"].value_counts().head(15).reset_index()
    )
    top_pass.columns = ["password", "count"]
    fig_passwords = go.Figure(go.Bar(
        x=top_pass["count"], y=top_pass["password"],
        orientation="h",
        marker_color=DANGER, marker_opacity=0.85,
        hovertemplate="<b>%{y}</b><br>Intentos: %{x}<extra></extra>",
    ))
    fig_passwords.update_layout(**PLOT_LAYOUT, title="Top 15 contraseñas más usadas",
        xaxis=dict(gridcolor="#2a2d3a", title="Intentos"),
        yaxis=dict(autorange="reversed", tickfont=dict(size=11)),
        height=420,
    )
else:
    fig_passwords = go.Figure().update_layout(**PLOT_LAYOUT, title="Sin datos de contraseñas")

# Top usuarios
if "username" in logins.columns:
    top_users = (
        logins[logins["username"].notna()]
        ["username"].value_counts().head(15).reset_index()
    )
    top_users.columns = ["username", "count"]
    fig_users = go.Figure(go.Bar(
        x=top_users["count"], y=top_users["username"],
        orientation="h",
        marker_color=WARNING, marker_opacity=0.85,
        hovertemplate="<b>%{y}</b><br>Intentos: %{x}<extra></extra>",
    ))
    fig_users.update_layout(**PLOT_LAYOUT, title="Top 15 usuarios más probados",
        xaxis=dict(gridcolor="#2a2d3a", title="Intentos"),
        yaxis=dict(autorange="reversed", tickfont=dict(size=11)),
        height=420,
    )
else:
    fig_users = go.Figure().update_layout(**PLOT_LAYOUT, title="Sin datos de usuarios")

# Top organizaciones atacantes
top_orgs = (
    connections[connections["org"].str.strip() != ""]
    ["org"].value_counts().head(10).reset_index()
)
top_orgs.columns = ["org", "count"]
fig_orgs = go.Figure(go.Bar(
    x=top_orgs["count"], y=top_orgs["org"],
    orientation="h",
    marker_color="#a55eea", marker_opacity=0.85,
    hovertemplate="<b>%{y}</b><br>Sesiones: %{x}<extra></extra>",
))
fig_orgs.update_layout(**PLOT_LAYOUT, title="Top 10 organizaciones / ASN atacantes",
    xaxis=dict(gridcolor="#2a2d3a", title="Sesiones"),
    yaxis=dict(autorange="reversed", tickfont=dict(size=11)),
    height=360,
)

# Top comandos ejecutados
if "input" in commands.columns:
    top_cmds = (
        commands[commands["input"].notna()]
        ["input"].value_counts().head(15).reset_index()
    )
    top_cmds.columns = ["command", "count"]
    fig_commands = go.Figure(go.Bar(
        x=top_cmds["count"], y=top_cmds["command"],
        orientation="h",
        marker_color=SUCCESS, marker_opacity=0.85,
        hovertemplate="<b>%{y}</b><br>Veces: %{x}<extra></extra>",
    ))
    fig_commands.update_layout(**PLOT_LAYOUT, title="Top 15 comandos ejecutados por atacantes",
        xaxis=dict(gridcolor="#2a2d3a", title="Ejecuciones"),
        yaxis=dict(autorange="reversed", tickfont=dict(size=10)),
        height=420,
    )
else:
    fig_commands = go.Figure().update_layout(**PLOT_LAYOUT, title="Sin datos de comandos")

# Login failed vs success por país
login_country = logins.groupby(["country", "eventid"]).size().reset_index(name="count")
login_country["eventid"] = login_country["eventid"].map({
    "cowrie.login.failed": "Fallido",
    "cowrie.login.success": "Exitoso",
})
top_countries = connections["country"].value_counts().head(10).index
login_country_top = login_country[login_country["country"].isin(top_countries)]
fig_login_country = px.bar(
    login_country_top, x="country", y="count", color="eventid",
    color_discrete_map={"Fallido": DANGER, "Exitoso": SUCCESS},
    title="Intentos de login por país (top 10)",
    barmode="stack",
)
fig_login_country.update_layout(**PLOT_LAYOUT,
    xaxis=dict(gridcolor="#2a2d3a", title=""),
    yaxis=dict(gridcolor="#2a2d3a", title="Intentos"),
    legend_title="Resultado",
)

# Scatter map de IPs geolocalizadas
ip_map = connections.groupby(["lat", "lon", "country", "org"]).size().reset_index(name="sesiones")
ip_map = ip_map[ip_map["lat"] != 0]
fig_scatter_map = px.scatter_geo(
    ip_map,
    lat="lat", lon="lon",
    size="sesiones",
    hover_name="country",
    hover_data={"org": True, "sesiones": True, "lat": False, "lon": False},
    color="sesiones",
    color_continuous_scale=[[0, WARNING], [0.5, DANGER], [1, "#ff0000"]],
    title="Distribución geográfica de IPs atacantes",
    size_max=40,
)
fig_scatter_map.update_layout(**PLOT_LAYOUT, title_font_color=TEXT,
    coloraxis_colorbar=dict(title="Sesiones", tickfont=dict(color=MUTED))
)
fig_scatter_map.update_geos(
    showframe=False, showcoastlines=True,
    coastlinecolor="#2a2d3a", landcolor="#1a1d27",
    oceancolor=BG, showocean=True,
    bgcolor="rgba(0,0,0,0)",
)

# ── Top IPs tabla 

top_ips = connections.groupby(["src_ip", "country", "org"]).size().reset_index(name="Sesiones")
top_ips = top_ips.sort_values("Sesiones", ascending=False).head(20)
top_ips.columns = ["IP", "País", "Organización", "Sesiones"]

# ── Layout del dashboard 

app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.BOOTSTRAP,
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap",
    ],
    title="Cowrie Honeypot Dashboard",
)

app.layout = html.Div(style={"backgroundColor": BG, "minHeight": "100vh", "fontFamily": "Inter, sans-serif", "padding": "24px"}, children=[

    # Header
    html.Div([
        html.H1("🍯 Honeypot Dashboard", style={"color": ACCENT, "fontWeight": "700", "marginBottom": "4px"}),
        html.P(
            f"Cowrie SSH Honeypot · {summary['date_range'][0]} → {summary['date_range'][1]} · AWS EC2",
            style={"color": MUTED, "marginBottom": "0"}
        ),
    ], style={**card_style, "marginBottom": "24px"}),

    # Stat cards
    dbc.Row([
        dbc.Col(stat_card("Sesiones totales",   f"{summary['total_sessions']:,}",   ACCENT,   "🔌"), md=3),
        dbc.Col(stat_card("IPs únicas",          f"{summary['unique_ips']:,}",        WARNING,  "🌐"), md=3),
        dbc.Col(stat_card("Intentos de login",   f"{summary['login_attempts']:,}",   DANGER,   "🔑"), md=3),
        dbc.Col(stat_card("Logins exitosos",     f"{summary['successful_logins']:,}", SUCCESS,  "⚠️"), md=3),
    ], className="mb-3"),
    dbc.Row([
        dbc.Col(stat_card("Comandos ejecutados", f"{summary['commands_run']:,}",     "#a55eea", "💻"), md=3),
        dbc.Col(stat_card("Ficheros subidos",    "9",                                 DANGER,   "📤"), md=3),
        dbc.Col(stat_card("Días monitorizados",  "10",                                MUTED,    "📅"), md=3),
        dbc.Col(stat_card("Países atacantes",
            str(connections["country"].nunique()),                                   WARNING,  "🗺️"), md=3),
    ], className="mb-4"),

    # Mapas
    html.Div([
        section_title("Origen geográfico de los ataques"),
        dcc.Graph(figure=fig_map, config=plot_cfg, style={"height": "420px"}),
    ], style=card_style),

    html.Div([
        section_title("Distribución de IPs atacantes"),
        dcc.Graph(figure=fig_scatter_map, config=plot_cfg, style={"height": "420px"}),
    ], style=card_style),

    # Evolución temporal
    html.Div([
        section_title("Evolución temporal"),
        dcc.Graph(figure=fig_daily, config=plot_cfg, style={"height": "280px"}),
    ], style=card_style),

    html.Div([
        section_title("Distribución horaria de ataques (UTC)"),
        dcc.Graph(figure=fig_hourly, config=plot_cfg, style={"height": "280px"}),
    ], style=card_style),

    # Credenciales
    dbc.Row([
        dbc.Col(html.Div([
            section_title("Contraseñas más usadas"),
            dcc.Graph(figure=fig_passwords, config=plot_cfg),
        ], style=card_style), md=6),
        dbc.Col(html.Div([
            section_title("Usuarios más probados"),
            dcc.Graph(figure=fig_users, config=plot_cfg),
        ], style=card_style), md=6),
    ]),

    # Comandos y orgs
    dbc.Row([
        dbc.Col(html.Div([
            section_title("Comandos ejecutados por atacantes"),
            dcc.Graph(figure=fig_commands, config=plot_cfg),
        ], style=card_style), md=6),
        dbc.Col(html.Div([
            section_title("Organizaciones / ASN atacantes"),
            dcc.Graph(figure=fig_orgs, config=plot_cfg),
        ], style=card_style), md=6),
    ]),

    # Login por país
    html.Div([
        section_title("Intentos de login por país"),
        dcc.Graph(figure=fig_login_country, config=plot_cfg, style={"height": "360px"}),
    ], style=card_style),

    # Top IPs tabla
    html.Div([
        section_title("Top 20 IPs más activas"),
        dash_table.DataTable(
            data=top_ips.to_dict("records"),
            columns=[{"name": c, "id": c} for c in top_ips.columns],
            style_table={"overflowX": "auto"},
            style_header={"backgroundColor": "#2a2d3a", "color": TEXT, "fontWeight": "600", "border": "none"},
            style_cell={"backgroundColor": CARD_BG, "color": TEXT, "border": "1px solid #2a2d3a",
                        "padding": "10px 14px", "fontSize": "0.88rem"},
            style_data_conditional=[
                {"if": {"row_index": "odd"}, "backgroundColor": "#1e2130"},
            ],
            page_size=20,
            sort_action="native",
        ),
    ], style=card_style),

    # Footer
    html.Div([
        html.P("Honeypot desplegado en AWS EC2 · Cowrie SSH Honeypot · Datos reales de ataques",
               style={"color": MUTED, "textAlign": "center", "marginBottom": "0", "fontSize": "0.85rem"}),
    ], style={**card_style, "marginTop": "8px"}),
])

if __name__ == "__main__":
    print("\nDashboard disponible en → http://127.0.0.1:8050\n")
    app.run(debug=False)