"""
Streamlit dashboard for exposed-ai-radar.

Public-safe view: aggregate trends only (counts over time, by country/org).
Raw per-host data (private tab) is for your own responsible-disclosure
use — never publish specific IPs.

Run: uv run streamlit run dashboard.py
"""

import sqlite3

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from globe_view import build_globe_html
from premium_ui import TAB_CSS, build_kpi_header_html
from report_generator import build_report_pdf
from splash import build_splash_html

DB_PATH = "radar.db"

st.set_page_config(page_title="GHOSTGRID", layout="wide")


@st.cache_data(ttl=300)
def load_hosts() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM hosts", conn)
    conn.close()
    return df


@st.cache_data(ttl=300)
def load_runs() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM snapshot_runs", conn)
    conn.close()
    df["run_at"] = pd.to_datetime(df["run_at"])
    return df


hosts = load_hosts()
runs = load_runs()

if hosts.empty:
    st.warning("No data yet — run `uv run collector.py` first.")
    st.stop()

if "entered" not in st.session_state:
    st.session_state.entered = False

if not st.session_state.entered:
    st.markdown(
        """
        <style>
        #MainMenu, header, footer {visibility: hidden;}
        .block-container {padding-top: 1rem;}
        div[data-testid="stButton"] > button {
            background: linear-gradient(160deg, rgba(0,217,192,0.25), rgba(0,217,192,0.08));
            border: 1px solid #00D9C0;
            color: #F2F4F8;
            font-weight: 700;
            letter-spacing: 0.05em;
            padding: 10px 0;
            box-shadow: 0 0 20px rgba(0,217,192,0.3);
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        div[data-testid="stButton"] > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 28px rgba(0,217,192,0.5);
            border-color: #00D9C0;
            color: #F2F4F8;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    components.html(build_splash_html(hosts), height=640, scrolling=False)
    spacer1, enter_col, spacer2 = st.columns([2, 1, 2])
    with enter_col:
        if st.button("ENTER GHOSTGRID →", width='stretch', key="enter_btn"):
            st.session_state.entered = True
            st.rerun()
    st.stop()

st.title("GHOSTGRID")
st.caption(
    "Passive Shodan-based tracking of internet-exposed self-hosted AI "
    "inference tools. No host is ever contacted directly — all data is "
    "the source engines' own pre-collected banner data."
)

kpi_stats = [
    {"label": "Hosts Tracked", "value": len(hosts), "accent": "#00D9C0", "icon": "🌐"},
    {"label": "Critical Risk", "value": int((hosts["risk_tier"] == "Critical").sum()),
     "accent": "#FF3B3B", "icon": "🔴"},
    {"label": "High Risk", "value": int((hosts["risk_tier"] == "High").sum()),
     "accent": "#E07B39", "icon": "🟠"},
    {"label": "Countries", "value": int(hosts["country"].nunique()), "accent": "#5B8DEF", "icon": "🗺️"},
    {"label": "KEV-Confirmed Exploits", "value": int(hosts["cve_kev"].sum()),
     "accent": "#C400FF", "icon": "🎯"},
    {"label": "GreyNoise: Malicious IP", "value": int((hosts["greynoise_classification"] == "malicious").sum()),
     "accent": "#FF3B3B", "icon": "☠️"},
]
components.html(build_kpi_header_html(kpi_stats), height=150)

report_col1, report_col2 = st.columns([5, 1])
with report_col2:
    if st.button("📄 Generate Report", width='stretch'):
        st.session_state["report_pdf"] = build_report_pdf(hosts, runs)
if "report_pdf" in st.session_state:
    with report_col2:
        st.download_button(
            "⬇️ Download PDF",
            st.session_state["report_pdf"],
            file_name="exposed_ai_radar_snapshot.pdf",
            mime="application/pdf",
            width='stretch',
        )

search_query = st.text_input(
    "🔍 Search all tracked hosts — IP, org, or country",
    key="global_search",
    placeholder="e.g. 96.82.119.99, Comcast, Germany...",
)
if search_query.strip():
    q = search_query.strip().lower()
    search_results = hosts[
        hosts["ip"].str.lower().str.contains(q, na=False)
        | hosts["org"].str.lower().str.contains(q, na=False)
        | hosts["country"].str.lower().str.contains(q, na=False)
    ]
    st.markdown(f"**{len(search_results)} match(es)**")
    if not search_results.empty:
        st.dataframe(
            search_results[["product", "ip", "port", "country", "org", "risk_tier",
                             "hosting_category", "cve_flags", "abuse_contact"]],
            width='stretch',
            hide_index=True,
        )
    st.divider()

st.markdown(TAB_CSS, unsafe_allow_html=True)
tab_globe, tab_trends, tab_countries, tab_risk, tab_raw = st.tabs(
    ["Globe", "Trends", "By Country / Org (aggregate)", "Risk", "Raw hosts (private use only)"]
)

with tab_globe:
    st.subheader("Every tracked host, live on a globe")
    st.caption(
        "Real coordinates from Shodan's geolocation data — every point here "
        "is an actual exposed instance from the current snapshot, not a "
        "demo. Color = risk tier. Pulsing rings = High/Critical."
    )
    globe_product = st.selectbox(
        "Product", ["All"] + sorted(hosts["product"].unique()), key="globe_product"
    )
    globe_subset = hosts if globe_product == "All" else hosts[hosts["product"] == globe_product]
    components.html(build_globe_html(globe_subset), height=670, scrolling=False)

with tab_trends:
    st.subheader("Reported exposure over time (Shodan's total count per query)")
    chart = (
        alt.Chart(runs)
        .mark_line(point=True)
        .encode(
            x="run_at:T",
            y=alt.Y("total_reported:Q", title="Total reported by Shodan"),
            color="product:N",
            tooltip=["run_at:T", "product:N", "total_reported:Q"],
        )
        .properties(height=400)
    )
    st.altair_chart(chart, width='stretch')

    st.subheader("Latest snapshot counts")
    latest = runs.sort_values("run_at").groupby("product").tail(1)
    st.dataframe(
        latest[["product", "total_reported", "fetched", "run_at"]].sort_values(
            "total_reported", ascending=False
        ),
        width='stretch',
        hide_index=True,
    )

with tab_countries:
    st.subheader("Geographic distribution (this page's sample, aggregate only)")
    st.caption(
        "Sampled from up to 100 results per product per run — not the full "
        "population. Useful for rough distribution, not precise counts."
    )
    product_filter = st.selectbox("Product", sorted(hosts["product"].unique()))
    subset = hosts[hosts["product"] == product_filter]

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**By country**")
        by_country = (
            subset.groupby("country").size().reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        chart = (
            alt.Chart(by_country.head(20))
            .mark_bar()
            .encode(x=alt.X("count:Q"), y=alt.Y("country:N", sort="-x"))
            .properties(height=450)
        )
        st.altair_chart(chart, width='stretch')
        st.download_button(
            "Download country breakdown (CSV)",
            by_country.to_csv(index=False),
            file_name=f"{product_filter.lower().replace(' ', '_')}_by_country.csv",
        )

    with col2:
        st.markdown("**By hosting category**")
        st.caption(
            "Rough keyword-based classification (see classify.py) — "
            "residential ISP exposure is generally more concerning than a "
            "cloud/rental GPU box someone will tear down soon."
        )
        by_category = (
            subset.groupby("hosting_category").size().reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        chart = (
            alt.Chart(by_category)
            .mark_bar()
            .encode(x=alt.X("count:Q"), y=alt.Y("hosting_category:N", sort="-x"))
            .properties(height=450)
        )
        st.altair_chart(chart, width='stretch')

    st.subheader("Top organizations / ASNs")
    by_org = (
        subset.groupby("org").size().reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    st.dataframe(by_org.head(15), width='stretch', hide_index=True)
    st.download_button(
        "Download org breakdown (CSV)",
        by_org.to_csv(index=False),
        file_name=f"{product_filter.lower().replace(' ', '_')}_by_org.csv",
    )

    if subset["source"].nunique() > 1:
        st.subheader("By data source")
        st.caption(
            "This product was found by more than one engine — comparing "
            "risk-tier composition between sources can reveal whether one "
            "engine's fingerprinting skews toward different kinds of hosts."
        )
        source_counts = subset["source"].value_counts()
        cols = st.columns(len(source_counts))
        for col, (src, count) in zip(cols, source_counts.items()):
            col.metric(src.capitalize(), count)

        by_source_tier = (
            subset.groupby(["source", "risk_tier"]).size().reset_index(name="count")
        )
        tier_order_local = ["Low", "Medium", "High", "Critical"]
        chart = (
            alt.Chart(by_source_tier)
            .mark_bar()
            .encode(
                x=alt.X("risk_tier:N", sort=tier_order_local, title="Risk tier"),
                y=alt.Y("count:Q"),
                color=alt.Color("source:N", title="Source"),
                xOffset="source:N",
                tooltip=["source:N", "risk_tier:N", "count:Q"],
            )
            .properties(height=350)
        )
        st.altair_chart(chart, width='stretch')

    if product_filter == "Ollama":
        st.subheader("Known-CVE exposure (version-based, best-effort — see cve_check.py)")
        flagged = subset[subset["cve_flags"].notna() & (subset["cve_flags"] != "")]
        st.metric("Hosts flagged with a known CVE (this sample)", len(flagged))
        if not flagged.empty:
            st.dataframe(
                flagged[["ip", "port", "version", "cve_flags", "country", "org"]],
                width='stretch',
                hide_index=True,
            )

with tab_risk:
    st.subheader("Risk tier distribution (this page's sample)")
    st.caption(
        "Heuristic triage score, not an objective severity measure — see "
        "risk_score.py for the weighting logic and reasoning. Combines auth "
        "status, hosting category, and known CVEs (Ollama only)."
    )
    product_options = ["All"] + sorted(hosts["product"].unique())
    risk_product = st.selectbox("Product", product_options, key="risk_product")
    risk_subset = hosts if risk_product == "All" else hosts[hosts["product"] == risk_product]

    tier_order = ["Low", "Medium", "High", "Critical"]
    tier_colors = {"Low": "#4C9F70", "Medium": "#E8B339", "High": "#E07B39", "Critical": "#C0392B"}

    st.caption("Click a bar to see the actual hosts behind it.")

    if risk_product == "All":
        # Grouped by tier and product, so composition across products stays visible
        by_tier = (
            risk_subset.groupby(["risk_tier", "product"]).size()
            .reset_index(name="count")
        )
        tier_click = alt.selection_point(name="tier_click", fields=["risk_tier", "product"])
        chart = (
            alt.Chart(by_tier)
            .mark_bar()
            .encode(
                x=alt.X("risk_tier:N", sort=tier_order, title="Risk tier"),
                y=alt.Y("count:Q"),
                color=alt.Color("product:N", title="Product"),
                xOffset="product:N",
                opacity=alt.condition(tier_click, alt.value(1), alt.value(0.45)),
                tooltip=["product:N", "risk_tier:N", "count:Q"],
            )
            .properties(height=350)
            .add_params(tier_click)
        )
        event = st.altair_chart(chart, width='stretch', on_select="rerun", key="risk_chart_all")
        selections = event.selection.get("tier_click", []) if event and event.selection else []
        detail = pd.concat([
            risk_subset[(risk_subset["risk_tier"] == s["risk_tier"]) & (risk_subset["product"] == s["product"])]
            for s in selections
        ]) if selections else pd.DataFrame()
        detail_desc = ", ".join(f"{s['product']} / {s['risk_tier']}" for s in selections)
    else:
        by_tier = (
            risk_subset.groupby("risk_tier").size().reindex(tier_order).fillna(0)
            .reset_index(name="count").rename(columns={"index": "risk_tier"})
        )
        tier_click = alt.selection_point(name="tier_click", fields=["risk_tier"])
        chart = (
            alt.Chart(by_tier)
            .mark_bar()
            .encode(
                x=alt.X("risk_tier:N", sort=tier_order, title="Risk tier"),
                y=alt.Y("count:Q"),
                color=alt.Color(
                    "risk_tier:N",
                    scale=alt.Scale(domain=tier_order, range=[tier_colors[t] for t in tier_order]),
                    legend=None,
                ),
                opacity=alt.condition(tier_click, alt.value(1), alt.value(0.45)),
            )
            .properties(height=350)
            .add_params(tier_click)
        )
        event = st.altair_chart(chart, width='stretch', on_select="rerun", key="risk_chart_single")
        selections = event.selection.get("tier_click", []) if event and event.selection else []
        detail = pd.concat([
            risk_subset[risk_subset["risk_tier"] == s["risk_tier"]] for s in selections
        ]) if selections else pd.DataFrame()
        detail_desc = ", ".join(s["risk_tier"] for s in selections)

    if not detail.empty:
        st.markdown(f"**{len(detail)} host(s) — {detail_desc}**")
        cols = ["ip", "port", "version", "country", "org", "hosting_category",
                "looks_unauthenticated", "cve_flags", "abuse_contact",
                "censys_open_ports", "censys_os", "censys_services_summary",
                "greynoise_classification", "greynoise_noise"]
        if detail["censys_open_ports"].notna().any():
            st.caption(
                "⚠️ `censys_services_summary` shows ALL open services Censys found on that "
                "IP — not necessarily the same device for **Residential ISP** hosts. "
                "Confirmed empirically: every high open-port-count host in this dataset is "
                "Residential ISP, consistent with carrier-grade NAT sharing one public IP "
                "across multiple unrelated devices/customers, not one box running everything. "
                "Trust this data at face value for Cloud/Hosting hosts (one IP = one VM)."
            )
        if (detail["greynoise_classification"] == "malicious").any():
            st.error(
                "🚨 One or more hosts below have an IP independently classified "
                "**malicious** by GreyNoise — that's a signal on top of exposure "
                "alone: the box may be compromised or repurposed, not just "
                "misconfigured."
            )
        st.dataframe(detail[cols], width='stretch', hide_index=True)
    else:
        st.caption("No bar selected yet.")

    if risk_product == "Ollama":
        st.subheader("Ollama version distribution (this page's sample)")
        st.caption(
            "How outdated the exposed fleet actually is — Ollama's version "
            "field is trustworthy (unlike Open WebUI/vLLM, see products.py)."
        )
        by_version = (
            risk_subset[risk_subset["version"].notna()]
            .groupby("version").size().reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        vchart = (
            alt.Chart(by_version.head(20))
            .mark_bar()
            .encode(x=alt.X("count:Q"), y=alt.Y("version:N", sort="-x"))
            .properties(height=400)
        )
        st.altair_chart(vchart, width='stretch')

with tab_raw:
    st.warning(
        "Contains specific IP addresses. For your own responsible-disclosure "
        "use only — do not publish this tab's contents."
    )
    st.caption(
        "`abuse_contact` is populated separately via `uv run enrich_abuse.py` "
        "(High/Critical risk tier only, RDAP-based — see abuse_lookup.py). "
        "`censys_*` columns via `uv run enrich_censys.py` (Critical/High only, "
        "1 Censys credit/host — see censys_lookup.py). ⚠️ `censys_services_summary` "
        "may reflect multiple unrelated devices sharing one IP via CGNAT for "
        "Residential ISP hosts — trust it at face value only for Cloud/Hosting. "
        "`greynoise_*` columns via `uv run enrich_greynoise.py` (Critical tier by "
        "default — Community API budget is only 50/week, see greynoise_lookup.py): "
        "`greynoise_noise` means this IP has itself been observed mass-scanning "
        "the internet; `greynoise_classification` of 'malicious' is a stronger "
        "signal than exposure alone. None of these three enrichments run "
        "automatically as part of collector.py."
    )
    col_prod, col_src = st.columns(2)
    with col_prod:
        product_filter2 = st.selectbox(
            "Product", sorted(hosts["product"].unique()), key="raw_product"
        )
    with col_src:
        available_sources = ["All"] + sorted(
            hosts[hosts["product"] == product_filter2]["source"].unique()
        )
        source_filter = st.selectbox("Source", available_sources, key="raw_source")

    raw_subset = hosts[hosts["product"] == product_filter2]
    if source_filter != "All":
        raw_subset = raw_subset[raw_subset["source"] == source_filter]
    raw_subset = raw_subset.sort_values("last_seen", ascending=False)

    checked = raw_subset["abuse_checked_at"].notna().sum()
    found = raw_subset["abuse_contact"].notna().sum()
    st.caption(f"{len(raw_subset)} host(s) — abuse-contact lookup: {checked} checked, "
               f"{found} resolved to a contact.")
    st.dataframe(raw_subset, width='stretch', hide_index=True)
