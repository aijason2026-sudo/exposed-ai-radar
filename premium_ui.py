"""
Glassmorphic animated KPI header — the first thing anyone sees, so it
carries a lot of the "does this feel like a real product" weight. Pure
CSS/JS (count-up animation on load), no external dependencies beyond
what's already loaded for the globe tab.
"""

import json

TAB_CSS = """
<style>
  .stTabs [data-baseweb="tab-list"] {
    gap: 10px;
    border-bottom: none;
    margin-bottom: 8px;
  }
  .stTabs [data-baseweb="tab"] {
    height: auto;
    background: linear-gradient(160deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px;
    padding: 10px 18px;
    color: #9AA4B2;
    font-weight: 600;
    letter-spacing: 0.02em;
    transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease, color 0.15s ease;
  }
  .stTabs [data-baseweb="tab"]:hover {
    transform: translateY(-2px);
    border-color: rgba(0,217,192,0.4);
    color: #E5E7EB;
  }
  .stTabs [aria-selected="true"] {
    background: linear-gradient(160deg, rgba(0,217,192,0.18), rgba(0,217,192,0.05)) !important;
    border: 1px solid #00D9C0 !important;
    color: #F2F4F8 !important;
    box-shadow: 0 0 16px rgba(0,217,192,0.35);
  }
  .stTabs [data-baseweb="tab-highlight"] {
    display: none;
  }
  .stTabs [data-baseweb="tab-border"] {
    display: none;
  }
</style>
"""


def build_kpi_header_html(stats: list[dict], height: int = 160) -> str:
    """
    stats: list of {"label": str, "value": int|float, "suffix": str,
                     "accent": "#hexcolor", "icon": "emoji"}
    """
    cards_html = ""
    for i, s in enumerate(stats):
        cards_html += f"""
        <div class="kpi-card" style="--accent: {s['accent']};">
          <div class="kpi-icon">{s['icon']}</div>
          <div class="kpi-value" id="kpi-{i}" data-target="{s['value']}" data-suffix="{s.get('suffix', '')}">0</div>
          <div class="kpi-label">{s['label']}</div>
        </div>
        """

    stats_json = json.dumps(stats)

    return f"""
    <style>
      .kpi-row {{
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        margin-bottom: 8px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }}
      .kpi-card {{
        flex: 1;
        min-width: 160px;
        background: linear-gradient(160deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 14px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
        box-shadow: 0 4px 24px rgba(0,0,0,0.25);
        backdrop-filter: blur(6px);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
      }}
      .kpi-card::before {{
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: var(--accent);
        box-shadow: 0 0 12px var(--accent);
      }}
      .kpi-card:hover {{
        transform: translateY(-3px);
        box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px var(--accent);
      }}
      .kpi-icon {{
        font-size: 22px;
        margin-bottom: 6px;
        opacity: 0.9;
      }}
      .kpi-value {{
        font-size: 34px;
        font-weight: 700;
        color: #F2F4F8;
        line-height: 1.1;
        text-shadow: 0 0 20px var(--accent);
      }}
      .kpi-label {{
        margin-top: 4px;
        font-size: 13px;
        color: #9AA4B2;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }}
    </style>
    <div class="kpi-row">
      {cards_html}
    </div>
    <script>
      const stats = {stats_json};
      stats.forEach((s, i) => {{
        const el = document.getElementById('kpi-' + i);
        const target = s.value;
        const isFloat = target % 1 !== 0;
        const duration = 1400;
        const start = performance.now();
        function tick(now) {{
          const progress = Math.min((now - start) / duration, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          const current = target * eased;
          el.textContent = (isFloat ? current.toFixed(1) : Math.round(current).toLocaleString()) + (s.suffix || '');
          if (progress < 1) requestAnimationFrame(tick);
        }}
        requestAnimationFrame(tick);
      }});
    </script>
    """
