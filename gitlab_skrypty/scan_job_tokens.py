#!/usr/bin/env python3
"""
Skrypt skanuje wszystkie projekty GitLab pod kątem użycia CI_JOB_TOKEN w plikach .gitlab-ci.yml
Użycie: python3 scan_job_tokens.py
"""

import urllib.request
import urllib.error
import json
import sys
from datetime import datetime

# ============================================================
#  KONFIGURACJA — uzupełnij przed uruchomieniem
# ============================================================
GITLAB_URL = "https://twoj-gitlab.example.com"   # bez trailing slash
PRIVATE_TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"      # twój admin Personal Access Token
OUTPUT_FILE = "wyniki_scan.txt"                   # plik z wynikami
# ============================================================

HEADERS = {
    "PRIVATE-TOKEN": PRIVATE_TOKEN,
    "Content-Type": "application/json",
}

PROBLEMATIC_PATTERNS = [
    "JOB-TOKEN: $CI_JOB_TOKEN",   # curl do innego projektu
    "trigger:",                    # cross-project trigger
    "artifacts:\n.*project:",      # artefakty z innego projektu
]

# Użycia które NIE wymagają allowlisty (własne registry projektu)
SAFE_PATTERNS = [
    "CI_REGISTRY",
    "docker login",
    "docker build",
    "docker push",
]


def api_get(path: str) -> dict | list | None:
    """Wykonuje GET request do GitLab API."""
    url = f"{GITLAB_URL}/api/v4{path}"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        print(f"  [błąd HTTP {e.code}] {url}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [błąd] {url}: {e}", file=sys.stderr)
        return None


def get_all_projects() -> list[dict]:
    """Pobiera wszystkie projekty z paginacją."""
    projects = []
    page = 1
    print("Pobieranie listy projektów...")
    while True:
        batch = api_get(f"/projects?per_page=50&page={page}&membership=false&simple=false")
        if not batch:
            break
        projects.extend(batch)
        print(f"  strona {page}: pobrano {len(batch)} projektów (łącznie: {len(projects)})")
        if len(batch) < 50:
            break
        page += 1
    return projects


def get_ci_file(project_id: int, default_branch: str) -> str | None:
    """Pobiera zawartość .gitlab-ci.yml dla projektu."""
    branch = default_branch or "main"
    url = f"/projects/{project_id}/repository/files/.gitlab-ci.yml/raw?ref={branch}"
    req = urllib.request.Request(f"{GITLAB_URL}/api/v4{url}", headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # projekt nie ma pliku CI — normalne
        return None
    except Exception:
        return None


def analyze_ci_content(content: str) -> dict:
    """
    Analizuje zawartość .gitlab-ci.yml.
    Zwraca słownik z liniami zawierającymi CI_JOB_TOKEN i oceną ryzyka.
    """
    lines_with_token = []
    risky_lines = []

    for i, line in enumerate(content.splitlines(), start=1):
        if "CI_JOB_TOKEN" in line:
            lines_with_token.append((i, line.strip()))

            # Oceń czy linia jest ryzykowna (cross-project)
            is_safe = any(safe in line for safe in SAFE_PATTERNS)
            if not is_safe:
                risky_lines.append((i, line.strip()))

    return {
        "all_lines": lines_with_token,
        "risky_lines": risky_lines,
    }


def format_risk(risky_count: int, total_count: int) -> str:
    if risky_count == 0:
        return "NISKIE  (prawdopodobnie tylko własne registry)"
    elif risky_count <= 2:
        return "ŚREDNIE (wymaga sprawdzenia)"
    else:
        return "WYSOKIE (wiele cross-project użyć)"


def main():
    print("=" * 60)
    print("GitLab CI_JOB_TOKEN Scanner")
    print(f"Instancja: {GITLAB_URL}")
    print(f"Rozpoczęto: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    projects = get_all_projects()
    print(f"\nŁącznie projektów do sprawdzenia: {len(projects)}\n")
    print("-" * 60)

    results = []
    no_ci = 0
    scanned = 0

    for project in projects:
        project_id = project["id"]
        name = project["name_with_namespace"]
        default_branch = project.get("default_branch") or "main"
        owner = project.get("namespace", {}).get("name", "?")

        ci_content = get_ci_file(project_id, default_branch)

        if ci_content is None:
            no_ci += 1
            continue

        scanned += 1

        if "CI_JOB_TOKEN" not in ci_content:
            continue

        analysis = analyze_ci_content(ci_content)

        if not analysis["all_lines"]:
            continue

        result = {
            "id": project_id,
            "name": name,
            "owner": owner,
            "branch": default_branch,
            "analysis": analysis,
        }
        results.append(result)

        risk = format_risk(len(analysis["risky_lines"]), len(analysis["all_lines"]))
        print(f"\n{'='*60}")
        print(f"PROJEKT : {name}")
        print(f"ID      : {project_id}  |  Właściciel: {owner}  |  Branch: {default_branch}")
        print(f"Ryzyko  : {risk}")
        print(f"Wszystkie linie z CI_JOB_TOKEN ({len(analysis['all_lines'])}):")
        for lineno, line in analysis["all_lines"]:
            print(f"  linia {lineno:4d}: {line[:120]}")

        if analysis["risky_lines"]:
            print(f"Potencjalnie cross-project ({len(analysis['risky_lines'])}):")
            for lineno, line in analysis["risky_lines"]:
                print(f"  >>> linia {lineno:4d}: {line[:120]}")

    # --- Podsumowanie ---
    print()
    print("=" * 60)
    print("PODSUMOWANIE")
    print("=" * 60)
    print(f"Wszystkich projektów       : {len(projects)}")
    print(f"Bez pliku .gitlab-ci.yml   : {no_ci}")
    print(f"Przeskanowanych            : {scanned}")
    print(f"Używa CI_JOB_TOKEN         : {len(results)}")
    high_risk = [r for r in results if r["analysis"]["risky_lines"]]
    print(f"Wymaga sprawdzenia         : {len(high_risk)}")
    print()

    if high_risk:
        print("Projekty wymagające uwagi (cross-project job token):")
        for r in high_risk:
            print(f"  - [{r['id']:5d}] {r['name']}")
    else:
        print("Brak projektów z ryzykownym użyciem CI_JOB_TOKEN.")

    print(f"\nZakończono: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # --- Zapis do pliku ---
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"Skan GitLab CI_JOB_TOKEN — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Instancja: {GITLAB_URL}\n\n")
        for r in results:
            f.write(f"PROJEKT: {r['name']} (ID: {r['id']})\n")
            f.write(f"Branch: {r['branch']}\n")
            for lineno, line in r["analysis"]["all_lines"]:
                f.write(f"  linia {lineno}: {line}\n")
            f.write("\n")
        f.write(f"\nŁącznie znaleziono: {len(results)} projektów\n")
        f.write(f"Wymaga sprawdzenia: {len(high_risk)} projektów\n")

    print(f"Wyniki zapisano do: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()