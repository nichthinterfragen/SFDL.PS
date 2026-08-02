# SFDL.PS

SFDL.NET Implementierung in PowerShell

## Voraussetzungen

- Windows PowerShell **5.1** oder neuer

## Schnellstart

```powershell
.\SFDL.ps1 mein-container.sfdl
```

Standard Downloadverzeichnis: `%USERPROFILE%\Downloads\`.

## Was das Skript automatisch macht

Nach einem **erfolgreichen** Download:

| Aktion | Verhalten |
|--------|-----------|
| Speedreport | Erstellt einen Speedreport als Textdatei `speedreport.txt` in den Download-Ordner. |
| Archive | Entpackt RAR-/ZIP-Dateien und **löscht** die Archive danach. |
| SFDL-Datei | Löscht die `.sfdl` Datei, wenn alle Dateien erfolgreich heruntergeladen wurden. |

Bei **Abbruch** (STRG+C) oder Fehlern bleiben SFDL und unfertige Dateien erhalten (Resume möglich).

## Verwendungsbeispiele

### Einfacher Download

```powershell
.\SFDL.ps1 container.sfdl
```

### Verschlüsselter Container

```powershell
.\SFDL.ps1 container.sfdl -Password "geheim"
```

Ohne `-Password` werden Einträge aus `passwords.txt` neben dem Skript der Reihe nach versucht.

### Anderes Zielverzeichnis

```powershell
.\SFDL.ps1 container.sfdl -DownloadDirectory "D:\Downloads"
```

### Mehr parallele Verbindungen

```powershell
.\SFDL.ps1 container.sfdl -MaxThreads 6
```

Standard = Wert aus dem Container.

### Nur Dateiliste anzeigen (kein Download)

```powershell
.\SFDL.ps1 container.sfdl -ListOnly
```

### Vorhandene Dateien überschreiben (kein Resume)

```powershell
.\SFDL.ps1 container.sfdl -Overwrite
```

### Pro Package einen Unterordner

```powershell
.\SFDL.ps1 container.sfdl -PackageSubfolder
```

### Entpacken überspringen

```powershell
.\SFDL.ps1 container.sfdl -SkipUnrar
```

### Passwortgeschützte Archive

```powershell
.\SFDL.ps1 container.sfdl -UnrarPassword "archiv-pw"
```

Oder mehrere Kandidaten:

```powershell
.\SFDL.ps1 container.sfdl -UnrarPasswordList "pw1","pw2","pw3"
```

### Eigenen unrar-Pfad setzen

```powershell
.\SFDL.ps1 container.sfdl -UnrarPath "C:\Tools\UnRAR\UnRAR.exe"
```

### Eigene Blacklist / Malware-Filter

Standardmäßig werden potenziell schädliche Muster (z. B. `.scr`, `.lnk`) übersprungen.

```powershell
# zusätzliche Muster (Regex)
.\SFDL.ps1 container.sfdl -Blacklist '^temp_.*\.exe$'

# Blacklist für „malicious“-Muster deaktivieren
.\SFDL.ps1 container.sfdl -IncludeMalicious
```

### Retry-Verhalten

```powershell
.\SFDL.ps1 container.sfdl -MaxRetry 5 -RetryWaitSeconds 10
```

## Parameterübersicht

| Parameter | Beschreibung |
|-----------|--------------|
| `SfdlFile` | Pfad zur `.sfdl`-Datei (Pflicht, Positionsargument). |
| `Password` | Passwort für verschlüsselte Container. |
| `DownloadDirectory` | Zielwurzel (Standard: Benutzer-Downloads). |
| `MaxThreads` | Parallele Downloads (Standard = aus Container). |
| `Overwrite` | Neu laden statt fortsetzen. |
| `PackageSubfolder` | Unterordner pro Package. |
| `SkipUnrar` | Kein automatisches Entpacken. |
| `UnrarPath` | Pfad zu `unrar.exe`. |
| `UnrarPassword` / `UnrarPasswordList` | Archiv-Passwörter. |
| `ListOnly` | Nur auflisten. |
| `IncludeMalicious` | Auch blacklisted „malicious“-Dateien laden. |
| `Blacklist` | Zusätzliche Regex-Ausschlüsse. |
| `MaxRetry` / `RetryWaitSeconds` | Wiederholungen bei Fehlern. |

## Abbruch

Während des Downloads mit **STRG+C** abbrechen. Laufende Übertragungen werden gestoppt; bereits geladene Bytes bleiben für ein späteres Resume erhalten. Die PowerShell-Session bleibt geöffnet.

## Hinweise

- Ausführen ggf. mit: `Set-ExecutionPolicy -Scope Process Bypass`
