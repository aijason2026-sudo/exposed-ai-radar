"""
GHOSTGRID entrance splash — a more dramatic variant of globe_view.py's
globe (faster rotation, scan arcs between a few flagged hosts) with the
tool's title/tagline baked into the same HTML document so it overlays
the canvas cleanly, since components.html renders in an isolated iframe
and can't share DOM positioning with Streamlit's native elements.

The "Enter" action itself is a native st.button rendered just below this
in dashboard.py, not inside this HTML — a click inside an iframe can't
directly flip Streamlit session_state without a fragile postMessage
bridge, and a plain st.button is one line and always works.
"""

import json
import random

from globe_view import TIER_COLORS


def build_splash_html(hosts_df, height: int = 640) -> str:
    points = []
    for _, row in hosts_df.iterrows():
        if row.get("latitude") is None or row.get("longitude") is None:
            continue
        tier = row.get("risk_tier") or "Low"
        points.append({
            "lat": row["latitude"],
            "lng": row["longitude"],
            "color": TIER_COLORS.get(tier, "#999999"),
            "size": 0.32 if tier in ("High", "Critical") else 0.18,
        })

    # A handful of "scan pulse" arcs between random flagged hosts, purely
    # decorative — not implying any real relationship between the hosts.
    high_risk = hosts_df[hosts_df["risk_tier"].isin(["High", "Critical"])]
    arcs = []
    if len(high_risk) >= 2:
        sample = high_risk.sample(min(10, len(high_risk)))
        coords = list(zip(sample["latitude"], sample["longitude"]))
        for i in range(0, len(coords) - 1, 2):
            arcs.append({
                "startLat": coords[i][0], "startLng": coords[i][1],
                "endLat": coords[i + 1][0], "endLng": coords[i + 1][1],
            })

    total = len(hosts_df)
    countries = int(hosts_df["country"].nunique())
    critical = int((hosts_df["risk_tier"] == "Critical").sum())
    high = int((hosts_df["risk_tier"] == "High").sum())

    points_json = json.dumps(points)
    arcs_json = json.dumps(arcs)

    return f"""
    <div id="splashGlobe" style="width:100%; height:{height}px; position:relative;">
      <div style="position:absolute; top:8%; left:0; right:0; text-align:center; z-index:10; pointer-events:none;">
        <div style="font-family:-apple-system,'Segoe UI',sans-serif; font-size:56px; font-weight:800;
                    letter-spacing:0.08em; color:#F2F4F8; text-shadow:0 0 30px #00D9C0, 0 0 60px #00D9C0aa;">
          GHOSTGRID
        </div>
        <div style="font-family:-apple-system,'Segoe UI',sans-serif; font-size:15px; color:#9AA4B2;
                    letter-spacing:0.04em; margin-top:6px;">
          Passive reconnaissance for exposed AI infrastructure
        </div>
        <div style="font-family:-apple-system,'Segoe UI',sans-serif; font-size:13px; color:#6B7684;
                    margin-top:14px;">
          {total:,} hosts tracked &nbsp;·&nbsp; {countries} countries &nbsp;·&nbsp;
          <span style="color:#FF3B3B;">{critical} critical</span> &nbsp;·&nbsp;
          <span style="color:#E07B39;">{high} high</span>
        </div>
      </div>
    </div>
    <script src="https://unpkg.com/globe.gl"></script>
    <script>
      const pointsData = {points_json};
      const arcsData = {arcs_json};

      const world = Globe()
        (document.getElementById('splashGlobe'))
        .backgroundColor('rgba(0,0,0,0)')
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
        .pointsData(pointsData)
        .pointLat('lat')
        .pointLng('lng')
        .pointColor('color')
        .pointAltitude(0.01)
        .pointRadius('size')
        .arcsData(arcsData)
        .arcStartLat('startLat').arcStartLng('startLng')
        .arcEndLat('endLat').arcEndLng('endLng')
        .arcColor(() => 'rgba(0,217,192,0.6)')
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashAnimateTime(2000)
        .arcStroke(0.5)
        .width(document.getElementById('splashGlobe').clientWidth)
        .height({height});

      world.controls().autoRotate = true;
      world.controls().autoRotateSpeed = 1.4;
      world.controls().enableZoom = false;
      world.pointOfView({{ lat: 15, lng: 20, altitude: 2.0 }});
    </script>
    """
