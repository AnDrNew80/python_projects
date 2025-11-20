import csv
import requests
import json
from tqdm import tqdm

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

def load_purls_from_csv(filename):
    purls = []
    with open(filename, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            p = (row.get("PURL") or "").strip()
            if p:
                purls.append(p)
    print(f"[LOG] Wczytano {len(purls)} PURL-i z pliku {filename}")
    return purls

def query_osv(purls):
    payload = {"queries": [{"package": {"purl": p}} for p in purls]}
    headers = {"Content-Type": "application/json"}
    print(f"[LOG] Wysyłam {len(purls)} PURL-i do OSV.dev...")
    response = requests.post(OSV_BATCH_URL, headers=headers, data=json.dumps(payload), timeout=30)
    response.raise_for_status()
    return response.json()

def extract_from_severity_list(sev_list):
    # Prefer numeric score; fall back to label
    for s in sev_list or []:
        score = s.get("score")
        if score is not None:
            try:
                return float(score), None
            except Exception:
                pass
        value = s.get("value")
        if value:
            v = value.strip().upper()
            if v == "CRITICAL": return None, "Critical"
            if v == "HIGH":     return None, "High"
            if v in ("MEDIUM", "MODERATE"): return None, "Medium"
            if v == "LOW":      return None, "Low"
    return None, None

def extract_from_cvss_list(cvss_list):
    if cvss_list:
        score = cvss_list[0].get("score")
        try:
            return float(score)
        except Exception:
            return None
    return None

def extract_from_database_specific(db_spec):
    # GHSA records often carry database_specific.severity
    if isinstance(db_spec, dict):
        val = (db_spec.get("severity") or "").strip().upper()
        if val == "CRITICAL": return "Critical"
        if val == "HIGH":     return "High"
        if val in ("MEDIUM", "MODERATE"): return "Medium"
        if val == "LOW":      return "Low"
    return None

def fetch_vuln_details(vuln_id, cache):
    if vuln_id in cache:
        return cache[vuln_id]
    try:
        r = requests.get(OSV_VULN_URL.format(vuln_id), timeout=20)
        r.raise_for_status()
        v = r.json()
    except Exception:
        cache[vuln_id] = (None, None)
        return cache[vuln_id]

    score, label = extract_from_severity_list(v.get("severity"))
    if score is not None or label is not None:
        cache[vuln_id] = (score, label)
        return cache[vuln_id]

    score = extract_from_cvss_list(v.get("cvss", []))
    if score is not None:
        cache[vuln_id] = (score, None)
        return cache[vuln_id]

    label = extract_from_database_specific(v.get("database_specific"))
    cache[vuln_id] = (None, label)
    return cache[vuln_id]

def extract_cvss_score_and_label_from_batch(vuln):
    score, label = extract_from_severity_list(vuln.get("severity"))
    if score is not None or label is not None:
        return score, label
    score = extract_from_cvss_list(vuln.get("cvss", []))
    if score is not None:
        return score, None
    label = extract_from_database_specific(vuln.get("database_specific"))
    return None, label

def bucket_from_score_or_label(score, label):
    if label:
        return label
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def save_html_report(results, purls, filename="report.html"):
    rows = []
    cache = {}

    for i, res in enumerate(tqdm(results.get("results", []), desc="Skanowanie", unit="purl")):
        purl = purls[i]
        for v in res.get("vulns", []):
            vid = v.get("id", "")
            score, label = extract_cvss_score_and_label_from_batch(v)
            if score is None and label is None and vid:
                score, label = fetch_vuln_details(vid, cache)
            severity = bucket_from_score_or_label(score, label)
            rows.append({
                "purl": purl,
                "id": vid,
                "summary": v.get("summary", ""),
                "score": f"{score:.1f}" if isinstance(score, float) else ("N/A" if score is None else score),
                "severity": severity
            })

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OSV Scan Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
h1 { color: #333; margin-bottom: 10px; }
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.toolbar .group { display: flex; gap: 8px; align-items: center; }
input[type=text] { padding: 6px 8px; width: 320px; }
button { padding: 6px 10px; cursor: pointer; }
.badge { background:#eee; border:1px solid #ccc; padding:4px 8px; border-radius:10px; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }
th { background: #f5f5f5; }
tr.critical { background-color: #ffd6d6; }
tr.high { background-color: #ffefef; }
tr.medium { background-color: #fff7da; }
tr.low { background-color: #eaf6ea; }
tr.unknown { background-color: #eeeeee; }
tfoot td { font-weight: bold; }
.small { color:#666; font-size: 12px; }
</style>
</head>
<body>
<h1>OSV Vulnerability Report</h1>

<div class="toolbar">
  <div class="group">
    <input type="text" id="filterInput" placeholder="Filtruj po PURL, CVE/GHSA, Summary">
    <span class="badge" id="visibleCount">Widoczne: 0</span>
  </div>
  <div class="group">
    <label><input type="checkbox" id="sevCritical" checked> Critical</label>
    <label><input type="checkbox" id="sevHigh" checked> High</label>
    <label><input type="checkbox" id="sevMedium" checked> Medium</label>
    <label><input type="checkbox" id="sevLow" checked> Low</label>
    <label><input type="checkbox" id="sevUnknown" checked> Unknown</label>
  </div>
  <div class="group">
    <button id="exportBtn">Eksportuj widoczne do CSV</button>
  </div>
</div>

<table id="vulnTable">
  <thead>
    <tr><th>PURL</th><th>CVE/GHSA</th><th>Summary</th><th>CVSS</th><th>Severity</th></tr>
  </thead>
  <tbody>
"""
    if not rows:
        html += "<tr><td colspan='5'>Brak podatności w wynikach dla dostarczonych PURL-i.</td></tr>\n"
    else:
        for r in rows:
            css_class = r["severity"].lower()
            html += f"<tr class='{css_class}'><td>{r['purl']}</td><td>{r['id']}</td><td>{r['summary']}</td><td>{r['score']}</td><td>{r['severity']}</td></tr>\n"

    html += """  </tbody>
</table>

<script>
function updateVisibleCount() {
  const rows = document.querySelectorAll("#vulnTable tbody tr");
  let visible = 0;
  rows.forEach(row => { if (row.style.display !== "none") visible++; });
  document.getElementById("visibleCount").innerText = "Widoczne: " + visible;
}

function applyFilters() {
  const text = document.getElementById("filterInput").value.toLowerCase();
  const showCritical = document.getElementById("sevCritical").checked;
  const showHigh = document.getElementById("sevHigh").checked;
  const showMedium = document.getElementById("sevMedium").checked;
  const showLow  = document.getElementById("sevLow").checked;
  const showUnknown  = document.getElementById("sevUnknown").checked;

  const rows = document.querySelectorAll("#vulnTable tbody tr");
  rows.forEach(row => {
    let sev = "unknown";
    if (row.classList.contains("critical")) sev = "critical";
    else if (row.classList.contains("high")) sev = "high";
    else if (row.classList.contains("medium")) sev = "medium";
    else if (row.classList.contains("low")) sev = "low";

    let sevOk = (sev === "critical" && showCritical) ||
                (sev === "high" && showHigh) ||
                (sev === "medium" && showMedium) ||
                (sev === "low" && showLow) ||
                (sev === "unknown" && showUnknown);

    const cells = row.querySelectorAll("td");
    const hay = (cells[0].innerText + " " + cells[1].innerText + " " + cells[2].innerText).toLowerCase();
    const textOk = text === "" || hay.includes(text);

    row.style.display = (sevOk && textOk) ? "" : "none";
  });

  updateVisibleCount();
}

function exportVisibleToCSV(filename) {
  const allRows = document.querySelectorAll("#vulnTable tr");
  let csv = [];
  allRows.forEach((row, idx) => {
    const isHeader = idx === 0;
    const isHidden = row.style.display === "none";
    if (!isHeader && isHidden) return;
    const cols = row.querySelectorAll("td, th");
    let rowData = [];
    cols.forEach(col => {
      let text = col.innerText.replace(/\\n/g, " ").replace(/\\r/g, " ").trim();
      text = '"' + text.replace(/"/g, '""') + '"';
      rowData.push(text);
    });
    csv.push(rowData.join(","));
  });

  const csvFile = new Blob([csv.join("\\n")], { type: "text/csv" });
  const link = document.createElement("a");
  link.download = filename;
  link.href = window.URL.createObjectURL(csvFile);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

document.getElementById("filterInput").addEventListener("input", applyFilters);
document.getElementById("sevCritical").addEventListener("change", applyFilters);
document.getElementById("sevHigh").addEventListener("change", applyFilters);
document.getElementById("sevMedium").addEventListener("change", applyFilters);
document.getElementById("sevLow").addEventListener("change", applyFilters);
document.getElementById("sevUnknown").addEventListener("change", applyFilters);
document.getElementById("exportBtn").addEventListener("click", function(){ exportVisibleToCSV("osv_report.csv"); });

// initial count
applyFilters();
</script>

</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[LOG] Raport zapisany do %s" % filename)

def main():
    filename = "purls.csv"
    purls = load_purls_from_csv(filename)
    results = query_osv(purls)
    save_html_report(results, purls)

if __name__ == "__main__":
    main()
