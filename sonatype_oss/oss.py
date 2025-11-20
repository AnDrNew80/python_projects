import csv
import requests
import json

OSV_URL = "https://api.osv.dev/v1/querybatch"

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
    response = requests.post(OSV_URL, headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    return response.json()

def categorize_vuln(vuln):
    score = vuln.get("cvss", [{}])[0].get("score", None)
    try:
        s = float(score) if score is not None else 0.0
    except Exception:
        s = 0.0
    if s >= 7.0:
        return "High", s
    elif s >= 4.0:
        return "Warning", s
    else:
        return "Low", s

def save_html_report(results, purls, filename="report.html"):
    rows = []
    for i, res in enumerate(results.get("results", [])):
        purl = purls[i]
        vulns = res.get("vulns", [])
        for v in vulns:
            severity, score = categorize_vuln(v)
            rows.append({
                "purl": purl,
                "id": v.get("id", ""),
                "summary": v.get("summary", ""),
                "score": score if score != 0.0 else "N/A",
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
tr.high { background-color: #ffefef; }
tr.warning { background-color: #fff7da; }
tr.low { background-color: #eaf6ea; }
tfoot td { font-weight: bold; }
.small { color:#666; font-size: 12px; }
</style>
</head>
<body>
<h1>OSV Vulnerability Report</h1>

<div class="toolbar">
  <div class="group">
    <input type="text" id="filterInput" placeholder="Filtruj po PURL, CVE, Summary">
    <span class="badge" id="visibleCount">Widoczne: 0</span>
  </div>
  <div class="group">
    <label><input type="checkbox" id="sevHigh" checked> High</label>
    <label><input type="checkbox" id="sevWarn" checked> Warning</label>
    <label><input type="checkbox" id="sevLow" checked> Low</label>
  </div>
  <div class="group">
    <button id="exportBtn">Eksportuj widoczne do CSV</button>
  </div>
</div>

<table id="vulnTable">
  <thead>
    <tr><th>PURL</th><th>CVE ID</th><th>Summary</th><th>CVSS</th><th>Severity</th></tr>
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
  const showHigh = document.getElementById("sevHigh").checked;
  const showWarn = document.getElementById("sevWarn").checked;
  const showLow  = document.getElementById("sevLow").checked;

  const rows = document.querySelectorAll("#vulnTable tbody tr");
  rows.forEach(row => {
    const sev = row.classList.contains("high") ? "high" :
                row.classList.contains("warning") ? "warning" : "low";

    // severity filter
    let sevOk = (sev === "high" && showHigh) ||
                (sev === "warning" && showWarn) ||
                (sev === "low" && showLow);

    // text filter across first 3 columns (PURL, CVE, Summary)
    const cells = row.querySelectorAll("td");
    const hay = (cells[0].innerText + " " + cells[1].innerText + " " + cells[2].innerText).toLowerCase();

    const textOk = text === "" || hay.includes(text);

    row.style.display = (sevOk && textOk) ? "" : "none";
  });

  updateVisibleCount();
}

function exportVisibleToCSV(filename) {
  const rows = document.querySelectorAll("#vulnTable tr");
  let csv = [];
  rows.forEach((row, idx) => {
    const isDataRow = idx > 0; // skip header on index 0
    const isHidden = row.style.display === "none";
    if (isDataRow && isHidden) return;
    const cols = row.querySelectorAll("td, th");
    let rowData = [];
    cols.forEach(col => {
      let text = col.innerText.replace(/\\n/g, " ").replace(/\\r/g, " ").trim();
      // escape double quotes
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
document.getElementById("sevHigh").addEventListener("change", applyFilters);
document.getElementById("sevWarn").addEventListener("change", applyFilters);
document.getElementById("sevLow").addEventListener("change", applyFilters);
document.getElementById("exportBtn").addEventListener("click", function(){ exportVisibleToCSV("osv_report.csv"); });

// initial count
applyFilters();
</script>

</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[LOG] Raport zapisany do {filename}")

def main():
    filename = "purls.csv"
    purls = load_purls_from_csv(filename)
    results = query_osv(purls)
    save_html_report(results, purls)

if __name__ == "__main__":
    main()
