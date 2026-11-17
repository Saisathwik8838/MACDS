import os
import json
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

dynamodb = None
table = None
try:
    import boto3
    dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
    table = dynamodb.Table("macds-attack-history")
except Exception:
    pass

def fetch_events():
    # Try DynamoDB first if configured and reachable
    if table is not None:
        try:
            return table.scan().get("Items", [])
        except Exception:
            pass
    # Fallback to local Control Plane API
    control_url = os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000")
    try:
        with urllib.request.urlopen(f"{control_url}/api/verdicts?limit=500", timeout=2) as resp:
            data = json.loads(resp.read().decode())
            return data.get("verdicts", [])
    except Exception:
        return []

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def do_GET(self):
        items = fetch_events()
        counts = {}
        actions = {"block_ip": 0, "raise_alert": 0, "do_nothing": 0}
        for item in items:
            at = item.get("attack_type", "unknown")
            counts[at] = counts.get(at, 0) + 1
            ad = item.get("action_decided") or item.get("action", "do_nothing")
            if ad in actions:
                actions[ad] += 1

        rows = "".join(f'''<tr>
<td>{i.get("attack_type","")}</td>
<td>{i.get("source_ip","")}</td>
<td style="color:{"#f85149" if (i.get("action_decided") or i.get("action"))=="block_ip" else "#d29922" if (i.get("action_decided") or i.get("action"))=="raise_alert" else "#8b949e"}">{i.get("action_decided") or i.get("action","")}</td>
<td>{i.get("confidence", "MEDIUM")}</td>
<td style="font-size:11px;color:#8b949e">{i.get("detail", i.get("packet_rate", "-"))}</td>
</tr>''' for i in sorted(items, key=lambda x: float(x.get("timestamp", 0) or 0), reverse=True))

        breakdown = "".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k,v in counts.items())

        html = f"""<!DOCTYPE html>
<html>
<head>
<title>MACDS Live Dashboard</title>
<meta http-equiv="refresh" content="5">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:monospace;background:#0d1117;color:#e6edf3;padding:30px}}
h1{{color:#58a6ff;margin-bottom:5px}}
.sub{{color:#8b949e;margin-bottom:30px;font-size:13px}}
.cards{{display:flex;gap:20px;margin-bottom:30px}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;flex:1;text-align:center}}
.card h2{{font-size:36px;margin-bottom:5px}}
.card p{{color:#8b949e;font-size:12px}}
.total{{color:#58a6ff}}.blocked{{color:#f85149}}.alerted{{color:#d29922}}
h3{{color:#3fb950;margin-bottom:15px}}
table{{border-collapse:collapse;width:100%;margin-bottom:30px;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;padding:12px 16px;text-align:left;color:#58a6ff;font-size:13px}}
td{{padding:12px 16px;border-bottom:1px solid #21262d;font-size:13px}}
</style>
</head>
<body>
<h1>MACDS Attack Monitor</h1>
<p class="sub">Live dashboard — auto-refreshes every 5 seconds</p>
<div class="cards">
  <div class="card"><h2 class="total">{len(items)}</h2><p>Total Attacks</p></div>
  <div class="card"><h2 class="blocked">{actions["block_ip"]}</h2><p>IPs Blocked</p></div>
  <div class="card"><h2 class="alerted">{actions["raise_alert"]}</h2><p>Alerts Raised</p></div>
  <div class="card"><h2 style="color:#3fb950">{len(counts)}</h2><p>Attack Types Seen</p></div>
</div>
<h3>Attack Type Breakdown</h3>
<table><tr><th>Attack Type</th><th>Count</th></tr>{breakdown}</table>
<h3>Full Attack History</h3>
<table>
<tr><th>Attack Type</th><th>Source IP</th><th>Action Taken</th><th>Confidence</th><th>Detail / Rate</th></tr>
{rows}
</table>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

print("Dashboard running on http://0.0.0.0:9000")
HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
