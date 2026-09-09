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

    # Pulsing radar-ping rings on flagged hosts, same effect as globe_view.py.
    rings = [
        {"lat": p["lat"], "lng": p["lng"], "color": p["color"]}
        for p in points
        if p["size"] >= 0.32
    ]

    total = len(hosts_df)
    countries = int(hosts_df["country"].nunique())
    critical = int((hosts_df["risk_tier"] == "Critical").sum())
    high = int((hosts_df["risk_tier"] == "High").sum())

    points_json = json.dumps(points)
    arcs_json = json.dumps(arcs)
    rings_json = json.dumps(rings)

    return f"""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap');

      @keyframes titleFlicker {{
        0%   {{ opacity: 0; }}
        6%   {{ opacity: 1; }}
        11%  {{ opacity: 0.15; }}
        16%  {{ opacity: 1; }}
        22%  {{ opacity: 0.25; }}
        28%  {{ opacity: 1; }}
        100% {{ opacity: 1; }}
      }}
      @keyframes glowPulse {{
        0%, 100% {{ text-shadow: 0 0 30px #00D9C0, 0 0 60px #00D9C0aa; }}
        50%      {{ text-shadow: 0 0 44px #00D9C0, 0 0 90px #00D9C0dd; }}
      }}
      @keyframes gradientShift {{
        to {{ background-position: 200% center; }}
      }}
      @keyframes glitchSliceA {{
        0%, 92%, 100% {{ transform: translate(0, 0); opacity: 0; }}
        93% {{ transform: translate(-3px, -1px); opacity: 0.85; }}
        95% {{ transform: translate(3px, 1px); opacity: 0.85; }}
        97% {{ transform: translate(-2px, 0); opacity: 0.6; }}
        98% {{ opacity: 0; }}
      }}
      @keyframes glitchSliceB {{
        0%, 92%, 100% {{ transform: translate(0, 0); opacity: 0; }}
        93% {{ transform: translate(3px, 1px); opacity: 0.85; }}
        95% {{ transform: translate(-3px, -1px); opacity: 0.85; }}
        97% {{ transform: translate(2px, 0); opacity: 0.6; }}
        98% {{ opacity: 0; }}
      }}
      @keyframes fadeUp {{
        from {{ opacity: 0; transform: translateY(14px); }}
        to   {{ opacity: 1; transform: translateY(0); }}
      }}
      @keyframes sweepSpin {{
        from {{ transform: rotate(0deg); }}
        to   {{ transform: rotate(360deg); }}
      }}
      #splashGlobe .ghostgrid-title {{
        position: relative;
        display: inline-block;
        font-family: 'Orbitron', -apple-system, sans-serif;
        font-size: 54px; font-weight: 900;
        letter-spacing: 0.14em;
        background: linear-gradient(90deg, #00D9C0, #7CF2FF 45%, #00D9C0 90%);
        background-size: 200% auto;
        -webkit-background-clip: text; background-clip: text;
        -webkit-text-fill-color: transparent; color: transparent;
        animation: titleFlicker 1.3s ease-out forwards,
                   gradientShift 5s linear infinite,
                   glowPulse 3s ease-in-out 1.3s infinite;
      }}
      #splashGlobe .ghostgrid-title::before,
      #splashGlobe .ghostgrid-title::after {{
        content: attr(data-text);
        position: absolute; top: 0; left: 0; width: 100%;
        background: none; -webkit-text-fill-color: initial;
      }}
      #splashGlobe .ghostgrid-title::before {{
        color: #FF2ED0;
        clip-path: inset(0 0 55% 0);
        animation: glitchSliceA 4.5s ease-in-out infinite;
      }}
      #splashGlobe .ghostgrid-title::after {{
        color: #00E5FF;
        clip-path: inset(55% 0 0 0);
        animation: glitchSliceB 4.5s ease-in-out infinite;
      }}
      #splashGlobe .ghostgrid-subtitle {{
        font-family: -apple-system,'Segoe UI',sans-serif; font-size: 15px; color: #9AA4B2;
        letter-spacing: 0.04em; margin-top: 6px; opacity: 0;
        animation: fadeUp 0.8s ease-out 1.4s forwards;
      }}
      #splashGlobe .ghostgrid-stats {{
        font-family: -apple-system,'Segoe UI',sans-serif; font-size: 13px; color: #6B7684;
        margin-top: 14px; opacity: 0;
        animation: fadeUp 0.8s ease-out 1.7s forwards;
      }}
      #splashGlobe .radarSweep {{
        position: absolute; inset: 0; z-index: 5; pointer-events: none;
        background: conic-gradient(from 0deg, rgba(0,217,192,0) 0deg,
                    rgba(0,217,192,0.20) 6deg, rgba(0,217,192,0) 34deg);
        mix-blend-mode: screen;
        animation: sweepSpin 4.5s linear infinite;
      }}
    </style>
    <div id="splashGlobe" style="width:100%; height:{height}px; position:relative; overflow:hidden;">
      <div id="splashGlobeCanvas" style="position:absolute; inset:0; z-index:1;"></div>
      <div class="radarSweep"></div>
      <div style="position:absolute; top:8%; left:0; right:0; text-align:center; z-index:10; pointer-events:none;">
        <div class="ghostgrid-title" data-text="GHOSTGRID">GHOSTGRID</div>
        <div class="ghostgrid-subtitle">Passive reconnaissance for exposed AI infrastructure</div>
        <div class="ghostgrid-stats">
          <span id="statTotal">0</span> hosts tracked &nbsp;·&nbsp;
          <span id="statCountries">0</span> countries &nbsp;·&nbsp;
          <span style="color:#FF3B3B;"><span id="statCritical">0</span> critical</span> &nbsp;·&nbsp;
          <span style="color:#E07B39;"><span id="statHigh">0</span> high</span>
        </div>
      </div>
    </div>
    <script src="https://unpkg.com/globe.gl"></script>
    <script>
      const pointsData = {points_json};
      const arcsData = {arcs_json};
      const ringsData = {rings_json};

      const world = Globe()
        (document.getElementById('splashGlobeCanvas'))
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
        .ringsData(ringsData)
        .ringLat('lat')
        .ringLng('lng')
        .ringColor(() => t => `rgba(255,59,59,${{1 - t}})`)
        .ringMaxRadius(3.5)
        .ringPropagationSpeed(2.5)
        .ringRepeatPeriod(900)
        .width(document.getElementById('splashGlobeCanvas').clientWidth)
        .height({height});

      world.controls().enableZoom = false;
      world.controls().autoRotate = true;

      // Dramatic fast spin-up on entrance, decelerating to a steady drift.
      let spinSpeed = 7;
      world.controls().autoRotateSpeed = spinSpeed;
      const rampDown = setInterval(() => {{
        spinSpeed *= 0.90;
        if (spinSpeed <= 1.4) {{
          spinSpeed = 1.4;
          clearInterval(rampDown);
        }}
        world.controls().autoRotateSpeed = spinSpeed;
      }}, 100);

      world.pointOfView({{ lat: 15, lng: 20, altitude: 2.6 }});
      // Ease the initial camera pull-in to altitude 2.0 over the first ~1.5s.
      setTimeout(() => world.pointOfView({{ lat: 15, lng: 20, altitude: 2.0 }}, 1500), 50);

      // Count the header stats up from zero once the fade-in has started.
      function animateCount(id, target, duration) {{
        const el = document.getElementById(id);
        const start = performance.now();
        function tick(now) {{
          const progress = Math.min((now - start) / duration, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          el.textContent = Math.round(eased * target).toLocaleString();
          if (progress < 1) requestAnimationFrame(tick);
        }}
        requestAnimationFrame(tick);
      }}
      setTimeout(() => {{
        animateCount('statTotal', {total}, 1400);
        animateCount('statCountries', {countries}, 1000);
        animateCount('statCritical', {critical}, 1200);
        animateCount('statHigh', {high}, 1200);
      }}, 1700);
    </script>
    """
