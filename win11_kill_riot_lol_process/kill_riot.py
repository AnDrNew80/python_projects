import psutil
import subprocess

TARGET_PROCESSES = [
    "RiotClientServices.exe",
    "RiotClientUx.exe",
    "RiotClientUxRender.exe",
    "LeagueClient.exe",
    "LeagueClientUx.exe",
    "LeagueClientUxRender.exe",
    "LoR.exe"
]

def kill_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in TARGET_PROCESSES:
                print(f"Killing {proc.info['name']} (PID {proc.info['pid']})")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def stop_riot_service():
    try:
        subprocess.run(["sc", "stop", "RiotClientServices"], check=False)
        print("RiotClientServices service stopped (if it exists).")
    except Exception as e:
        print("Could not stop RiotClientServices:", e)

if __name__ == "__main__":
    print("🔍 Searching for Riot/LoL processes...")
    kill_processes()
    stop_riot_service()
    print("Done.")

    # 🔹 Close console after input from user - press "enter"
    input("\nPress ENTER to close this window...")
