"""
3D WebGL globe visualization (globe.gl, loaded via CDN — this is a local
Streamlit app on localhost, not a sandboxed artifact, so a CDN script is
fine here). Every point is a real host from our own verified dataset —
no synthetic/demo data.

Renders points colored by risk tier, with pulsing expanding rings on
High/Critical hosts for a radar-ping effect.
"""

import json

TIER_COLORS = {
    "Low": "#4C9F70",
    "Medium": "#E8B339",
    "High": "#E07B39",
    "Critical": "#FF3B3B",
}


def build_globe_html(hosts_df, height: int = 650) -> str:
    points = []
    rings = []
    for _, row in hosts_df.iterrows():
        if row.get("latitude") is None or row.get("longitude") is None:
            continue
        tier = row.get("risk_tier") or "Low"
        color = TIER_COLORS.get(tier, "#999999")
        label = (
            f"{row.get('product')} — {tier} risk<br>"
            f"{row.get('city') or '?'}, {row.get('country') or '?'}<br>"
            f"{row.get('org') or 'unknown org'}"
        )
        points.append({
            "lat": row["latitude"],
            "lng": row["longitude"],
            "color": color,
            "label": label,
            "size": 0.35 if tier in ("High", "Critical") else 0.22,
        })
        if tier in ("High", "Critical"):
            rings.append({
                "lat": row["latitude"],
                "lng": row["longitude"],
                "color": color,
            })

    points_json = json.dumps(points)
    rings_json = json.dumps(rings)

    return f"""
    <div id="globeViz" style="width:100%; height:{height}px;"></div>
    <script src="https://unpkg.com/globe.gl"></script>
    <script>
      const pointsData = {points_json};
      const ringsData = {rings_json};

      const world = Globe()
        (document.getElementById('globeViz'))
        .backgroundColor('rgba(0,0,0,0)')
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
        .pointsData(pointsData)
        .pointLat('lat')
        .pointLng('lng')
        .pointColor('color')
        .pointAltitude(0.01)
        .pointRadius('size')
        .pointLabel('label')
        .onPointHover(point => {{
          world.controls().autoRotate = !point;
        }})
        .ringsData(ringsData)
        .ringLat('lat')
        .ringLng('lng')
        .ringColor(() => t => `rgba(255,59,59,${{1 - t}})`)
        .ringMaxRadius(4)
        .ringPropagationSpeed(2)
        .ringRepeatPeriod(1200)
        .width(document.getElementById('globeViz').clientWidth)
        .height({height});

      world.controls().autoRotate = true;
      world.controls().autoRotateSpeed = 0.6;
      world.pointOfView({{ lat: 20, lng: 0, altitude: 2.2 }});
    </script>
    """
