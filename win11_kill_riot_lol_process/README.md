# Kill Riot / League of Legends Processes

Ten projekt zawiera skrypt w **Pythonie** , który wymusza zamknięcie wszystkich procesów związanych z Riot Client i League of Legends na Windows 11.  
Standardowe `taskkill` nie wystarcza, ponieważ procesy uruchamiają się ponownie w pętli — tutaj rozwiązałem problem poprzez zatrzymanie usługi `RiotClientServices` oraz zabicie wszystkich powiązanych procesów.

This project contains a Python script that forces the termination of all processes related to Riot Client and League of Legends on Windows 11. The standard taskkill command is not sufficient, because the processes restart in a loop — here I solve the problem by stopping the RiotClientServices service and killing all associated processes.

Este proyecto contiene un script en Python que obliga al cierre de todos los procesos relacionados con Riot Client y League of Legends en Windows 11. El comando estándar taskkill no es suficiente, ya que los procesos se reinician en bucle — aqui yo resolví el problema deteniendo el servicio RiotClientServices y finalizando todos los procesos asociados.

---

## 📂 Struktura projektu

win11_kill_riot_lol_process\ 
│ kill_riot.py # Skrypt Python 
│ kill_riot.exe # Gotowy plik wykonywalny (portable) 
│ myicon.ico # Ikona aplikacji
└── build\ # Folder roboczy PyInstaller (pliki tymczasowe kompilacji)


---

## Wymagania

- **System:** Windows 11
- **Uprawnienia:** Uruchamianie jako Administrator (CMD/PowerShell)
- **Dla uruchomienia Python:**
  - **Python:** 3.10+ zainstalowany w systemie
  - **Biblioteka:** `psutil`
    ```powershell /CMD
    pip install psutil
    ```
- **Dla uruchomienia .exe:** Brak dodatkowych wymagań (nie wymaga Pythona)

## Uruchamianie skryptu Python

1. **Otwórz konsolę jako Administrator.**
2. **Przejdź do folderu projektu:**
   ```powershell / CMD
   cd "Twoja ścieżka do skryptu"\win11_kill_riot_lol_process
 ```
 
3. **Uruchom skrypt:**
   python kill_riot.py

## Uruchamianie gotowego pliku .exe

Plik: kill_riot.exe znajduje się w folderze projektu.

Start: Uruchom dwuklikiem.

Działanie: Konsola wyświetli logi i na końcu poczeka na naciśnięcie Enter.