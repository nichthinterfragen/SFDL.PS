#Requires -Version 5.1
<#
.SYNOPSIS
    SFDL.PS - Simple FTP Download Manager (PowerShell-Port)

.DESCRIPTION
    Ein-Datei-Port von SFDL.PS 3: SFDL v2/v3 laden, AES-entschlüsseln,
    per FTP (Resume, Multi-Thread) herunterladen, Blacklist, optional UnRAR, Speedreport.

.PARAMETER SfdlFile
    Pfad zur .sfdl-Datei (auch als Positionsargument möglich).

.PARAMETER Password
    Passwort für verschlüsselte Container.
    Ohne Angabe werden Passwörter aus passwords.txt neben dem Skript versucht.

.PARAMETER DownloadDirectory
    Zielverzeichnis (Standard: %USERPROFILE%\Downloads).

.PARAMETER MaxThreads
    Maximale parallele Downloads (Standard: aus Container oder 3).

.PARAMETER Overwrite
    Vorhandene Dateien überschreiben statt fortsetzen.

.PARAMETER PackageSubfolder
    Pro Package einen Unterordner anlegen.

.PARAMETER SkipUnrar
    Kein automatisches Entpacken von RAR-/ZIP-Archiven.

.PARAMETER DeleteAfterUnRar
    Veraltet: Nach erfolgreichem Entpacken werden Archivdateien
    (RAR-Kette / ZIP) automatisch gelöscht.

.PARAMETER UnrarPath
    Pfad zu unrar.exe (Standard: Suche im PATH / neben dem Skript).

.PARAMETER UnrarPassword
    RAR-Passwort (sonst Passwortliste / interaktiv).

.PARAMETER IncludeMalicious
    Auch potenziell schädliche Dateien (Blacklist) herunterladen.

.PARAMETER ListOnly
    Nur Dateiliste anzeigen, nicht herunterladen.

.PARAMETER Speedreport
    Veraltet: Der Speedreport wird nach jedem Download automatisch
    als speedreport.txt im Download-Ordner erzeugt.

.EXAMPLE
    .\SFDL.ps1 container.sfdl
    .\SFDL.ps1 container.sfdl -Password geheim -DownloadDirectory D:\Downloads
    .\SFDL.ps1 container.sfdl -ListOnly
#>

[CmdletBinding(DefaultParameterSetName = 'Download')]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$SfdlFile,

    [Parameter()]
    [string]$Password,

    [Parameter()]
    [string]$DownloadDirectory = (Join-Path $env:USERPROFILE 'Downloads'),

    [Parameter()]
    [ValidateRange(0, 32)]
    [int]$MaxThreads = 0,

    [Parameter()]
    [switch]$Overwrite,

    [Parameter()]
    [switch]$PackageSubfolder,

    [Parameter()]
    [switch]$SkipUnrar,

    [Parameter()]
    [switch]$DeleteAfterUnRar,

    [Parameter()]
    [string]$UnrarPath,

    [Parameter()]
    [string]$UnrarPassword,

    [Parameter()]
    [string[]]$UnrarPasswordList = @(),

    [Parameter()]
    [switch]$ListOnly,

    [Parameter()]
    [switch]$Speedreport,

    [Parameter()]
    [switch]$IncludeMalicious,

    [Parameter()]
    [string[]]$Blacklist = @(),

    [Parameter()]
    [int]$MaxRetry = 3,

    [Parameter()]
    [int]$RetryWaitSeconds = 3,

    [Parameter()]
    [switch]$DeleteSfdlAfterOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

# ---------------------------------------------------------------------------
# Defaults / embedded malicious blacklist (from SFDL.PS Blacklist.lst)
# ---------------------------------------------------------------------------
$script:DefaultMaliciousBlacklist = @(
    '^.*\.(SCR|scr)$'
    '^.*\.(lnk|LNK)$'
    '^IMG001\.exe$'
    '^(?i)Info\.zip$'
)

$script:SpeedreportTemplate = @"
SFDL: %%SFDL_FILENAME%%
Upper: %%SFDL_UPPER%%

%%SFDL_SIZE%% in %%DLTIME%% heruntergeladen @ %%SPEED%% (Im Durchschnitt)

Kommentar: %%COMMENT%%
"@

$script:PasswordListFile = Join-Path $PSScriptRoot 'passwords.txt'

# ---------------------------------------------------------------------------
# Abbruch-Steuerung (STRG+C / Skriptende) - shared mit Runspaces
# ---------------------------------------------------------------------------
$script:SfdlCancelEvent = New-Object System.Threading.ManualResetEventSlim $false
$script:SfdlActiveRequests = [hashtable]::Synchronized(@{})
$script:SfdlWorkerPipes = [hashtable]::Synchronized(@{})
$script:SfdlRunspacePool = $null
$script:SfdlCancelHandler = $null
$script:SfdlAborting = $false

# Globaler Session-State für PowerShell.Exiting (Action läuft isoliert, sieht $script: nicht)
$global:SfdlSessionState = [hashtable]::Synchronized(@{
    CancelEvent    = $script:SfdlCancelEvent
    ActiveRequests = $script:SfdlActiveRequests
    WorkerPipes    = $script:SfdlWorkerPipes
    RunspacePool   = $null
})

function New-SfdlSafeQueue {
    return [hashtable]::Synchronized(@{
        Items = New-Object System.Collections.ArrayList
        Sync  = (New-Object object)
    })
}

function Add-SfdlSafeQueueItem {
    param($Queue, $Item)
    $lockTaken = $false
    try {
        [System.Threading.Monitor]::Enter($Queue.Sync, [ref]$lockTaken)
        [void]$Queue.Items.Add($Item)
    }
    finally {
        if ($lockTaken) { [System.Threading.Monitor]::Exit($Queue.Sync) }
    }
}

function Get-SfdlSafeQueueItem {
    param($Queue)
    $lockTaken = $false
    try {
        [System.Threading.Monitor]::Enter($Queue.Sync, [ref]$lockTaken)
        if ($Queue.Items.Count -eq 0) { return $null }
        $item = $Queue.Items[0]
        $Queue.Items.RemoveAt(0)
        return $item
    }
    finally {
        if ($lockTaken) { [System.Threading.Monitor]::Exit($Queue.Sync) }
    }
}


# Native CancelKeyPress-Bridge: kein PowerShell-Code auf dem Cancel-Thread.
if (-not ('SfdlNativeCancel' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Threading;
public static class SfdlNativeCancel {
    static ManualResetEventSlim _gate;
    static readonly ConsoleCancelEventHandler Handler = OnCancel;
    static int _registered;

    public static void Register(ManualResetEventSlim gate) {
        _gate = gate;
        if (Interlocked.Exchange(ref _registered, 1) == 0) {
            Console.CancelKeyPress += Handler;
        }
    }

    public static void Unregister() {
        if (Interlocked.Exchange(ref _registered, 0) == 1) {
            try { Console.CancelKeyPress -= Handler; } catch { }
        }
        _gate = null;
    }

    public static void SetGate(ManualResetEventSlim gate) {
        _gate = gate;
    }

    static void OnCancel(object sender, ConsoleCancelEventArgs e) {
        // Prozess nicht beenden; Hauptthread räumt über das Event auf.
        e.Cancel = true;
        var g = _gate;
        if (g != null) {
            try { g.Set(); } catch { }
        }
    }
}
'@
}

function Request-SfdlCancel {
    param([string]$Reason = 'Abbruch')
    if ($script:SfdlAborting) { return }
    $script:SfdlAborting = $true
    try { $script:SfdlCancelEvent.Set() } catch { }
    try { [SfdlNativeCancel]::SetGate($script:SfdlCancelEvent) } catch { }

    # Nur FTP-Requests abbrechen, damit blockierende Reads sofort zurückkehren.
    # RunspacePool/Pipes schließt ausschließlich der Hauptthread im finally.
    foreach ($key in @($script:SfdlActiveRequests.Keys)) {
        $req = $script:SfdlActiveRequests[$key]
        if ($null -ne $req) {
            try { $req.Abort() } catch { }
        }
    }
}

function Register-SfdlCancelHandler {
    try {
        [SfdlNativeCancel]::SetGate($script:SfdlCancelEvent)
        [SfdlNativeCancel]::Register($script:SfdlCancelEvent)
        $script:SfdlCancelHandler = $true
    }
    catch {
        # ISE / Hosts ohne Konsole: Abbruch über CancelEvent / PipelineStopped
        $script:SfdlCancelHandler = $null
    }
}

function Complete-SfdlScript {
    param([int]$ExitCode = 0)
    try { $global:LASTEXITCODE = $ExitCode } catch { }

    # 130 = Benutzerabbruch: niemals exit - das schließt interaktive Sessions.
    if ($ExitCode -eq 130) { return }

    # Andere Fehlercodes nur bei Non-Interactive an den Prozess durchreichen.
    if (-not [Environment]::UserInteractive) {
        exit $ExitCode
    }
}

function Unregister-SfdlCancelHandler {
    try { [SfdlNativeCancel]::Unregister() } catch { }
    $script:SfdlCancelHandler = $null
}

function Clear-SfdlDownloadSession {
    $prevEa = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        Unregister-SfdlCancelHandler
        foreach ($key in @($script:SfdlWorkerPipes.Keys)) {
            $pipe = $script:SfdlWorkerPipes[$key]
            if ($null -ne $pipe) {
                try { $pipe.Stop() } catch { }
                try { $pipe.Dispose() } catch { }
            }
        }
        try { $script:SfdlWorkerPipes.Clear() } catch { }

        foreach ($key in @($script:SfdlActiveRequests.Keys)) {
            $req = $script:SfdlActiveRequests[$key]
            if ($null -ne $req) {
                try { $req.Abort() } catch { }
            }
        }
        try { $script:SfdlActiveRequests.Clear() } catch { }

        if ($null -ne $script:SfdlRunspacePool) {
            try { $script:SfdlRunspacePool.Close() } catch { }
            try { $script:SfdlRunspacePool.Dispose() } catch { }
            $script:SfdlRunspacePool = $null
        }
        if ($null -ne $global:SfdlSessionState) {
            $global:SfdlSessionState['RunspacePool'] = $null
        }
    }
    finally {
        $ErrorActionPreference = $prevEa
    }
}

# Bei Host-/Skriptende ebenfalls alles stoppen (über $global:SfdlSessionState)
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    try {
        $state = $global:SfdlSessionState
        if ($null -eq $state) { return }
        $cancelEvent = $state['CancelEvent']
        if ($null -ne $cancelEvent) { $cancelEvent.Set() }
        $active = $state['ActiveRequests']
        if ($null -ne $active) {
            foreach ($key in @($active.Keys)) {
                $req = $active[$key]
                if ($null -ne $req) {
                    try { $req.Abort() } catch { }
                }
            }
        }
        $pipes = $state['WorkerPipes']
        if ($null -ne $pipes) {
            foreach ($key in @($pipes.Keys)) {
                $pipe = $pipes[$key]
                if ($null -ne $pipe) {
                    try { $pipe.Stop() } catch { }
                    try { $pipe.Dispose() } catch { }
                }
            }
        }
        $pool = $state['RunspacePool']
        if ($null -ne $pool) {
            try { $pool.Close() } catch { }
            try { $pool.Dispose() } catch { }
        }
    }
    catch { }
} | Out-Null

# ---------------------------------------------------------------------------
# Logging / Konsolen-Kodierung
# ---------------------------------------------------------------------------
function Initialize-SfdlNativeConsole {
    if ('SfdlNative.ConsoleIo' -as [type]) { return }
    try {
        Add-Type -Namespace SfdlNative -Name ConsoleIo -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern System.IntPtr GetStdHandle(int nStdHandle);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(System.IntPtr hConsoleHandle, out uint lpMode);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(System.IntPtr hConsoleHandle, uint dwMode);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleOutputCP(uint wCodePageID);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleCP(uint wCodePageID);
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern bool WriteConsoleW(System.IntPtr hConsoleOutput, string lpBuffer, uint nNumberOfCharsToWrite, out uint lpNumberOfCharsWritten, System.IntPtr lpReserved);
'@ -ErrorAction Stop
    }
    catch { }
}

function Test-SfdlScriptEncoding {
    # PowerShell 5.1 liest .ps1 ohne UTF-8-BOM als System-ANSI (CP1252).
    # Dann wird UTF-8 "oe" zu zwei Zeichen (Mojibake). Canary muss U+00F6 sein.
    $canary = "ö"
    if ($canary.Length -ne 1 -or [int][char]$canary[0] -ne 0x00F6) {
        $cps = [string]::Join(',', ($canary.ToCharArray() | ForEach-Object { 'U+{0:X4}' -f [int]$_ }))
        throw ("SFDL.ps1 wurde nicht als UTF-8 geladen. Unter Windows PowerShell 5.1 muss die Datei als UTF-8 MIT BOM gespeichert sein. Aktuell: Length={0}, Codepoint(s)={1}" -f $canary.Length, $cps)
    }
}

function Initialize-SfdlConsoleEncoding {
    # Einheitlich UTF-8: Windows Terminal / ConPTY / VS Code erwarten UTF-8-Bytes
    # auf dem umgeleiteten stdout. Klassische Konsolen bekommen WriteConsoleW
    # (Unicode) in Write-SfdlHostLine.
    Initialize-SfdlNativeConsole

    $utf8 = New-Object System.Text.UTF8Encoding $false
    $script:SfdlUtf8NoBom = $utf8

    if ('SfdlNative.ConsoleIo' -as [type]) {
        try { [void][SfdlNative.ConsoleIo]::SetConsoleOutputCP(65001) } catch { }
        try { [void][SfdlNative.ConsoleIo]::SetConsoleCP(65001) } catch { }

        try {
            $script:SfdlStdOutHandle = [SfdlNative.ConsoleIo]::GetStdHandle(-11)
            $mode = [uint32]0
            $script:SfdlHasRealConsole = [SfdlNative.ConsoleIo]::GetConsoleMode($script:SfdlStdOutHandle, [ref]$mode)
            if ($script:SfdlHasRealConsole) {
                # VT-Sequenzen fuer Farben, falls stdout doch ueber Byte-Stream geht
                $ENABLE_VIRTUAL_TERMINAL_PROCESSING = [uint32]0x0004
                try { [void][SfdlNative.ConsoleIo]::SetConsoleMode($script:SfdlStdOutHandle, ($mode -bor $ENABLE_VIRTUAL_TERMINAL_PROCESSING)) } catch { }
            }
        }
        catch {
            $script:SfdlHasRealConsole = $false
            $script:SfdlStdOutHandle = [IntPtr]::Zero
        }
    }
    else {
        $script:SfdlHasRealConsole = $false
        $script:SfdlStdOutHandle = [IntPtr]::Zero
    }

    try { [Console]::OutputEncoding = $utf8 } catch { }
    try { [Console]::InputEncoding = $utf8 } catch { }
    try { $script:OutputEncoding = $utf8 } catch { }
    try { $global:OutputEncoding = $utf8 } catch { }
    try { $OutputEncoding = $utf8 } catch { }

    try {
        $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
        $PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8'
        $PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
        $PSDefaultParameterValues['Export-Csv:Encoding'] = 'utf8'
    }
    catch { }
}

function Get-SfdlAnsiForegroundCode {
    param([ConsoleColor]$ForegroundColor)
    switch ($ForegroundColor) {
        ([ConsoleColor]::Black)       { return 30 }
        ([ConsoleColor]::DarkBlue)    { return 34 }
        ([ConsoleColor]::DarkGreen)   { return 32 }
        ([ConsoleColor]::DarkCyan)    { return 36 }
        ([ConsoleColor]::DarkRed)     { return 31 }
        ([ConsoleColor]::DarkMagenta) { return 35 }
        ([ConsoleColor]::DarkYellow)  { return 33 }
        ([ConsoleColor]::Gray)        { return 37 }
        ([ConsoleColor]::DarkGray)    { return 90 }
        ([ConsoleColor]::Blue)        { return 94 }
        ([ConsoleColor]::Green)       { return 92 }
        ([ConsoleColor]::Cyan)        { return 96 }
        ([ConsoleColor]::Red)         { return 91 }
        ([ConsoleColor]::Magenta)     { return 95 }
        ([ConsoleColor]::Yellow)      { return 93 }
        ([ConsoleColor]::White)       { return 97 }
        default                       { return 37 }
    }
}

function Write-SfdlHostLine {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text = '',
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::Gray
    )

    if ($null -eq $Text) { $Text = '' }
    $line = $Text + [Environment]::NewLine

    # 1) Echte Konsole: WriteConsoleW (UTF-16) - unabhängig von OEM/ANSI-Codepage
    if ($script:SfdlHasRealConsole -and $script:SfdlStdOutHandle -ne [IntPtr]::Zero -and ('SfdlNative.ConsoleIo' -as [type])) {
        $prev = $null
        try {
            try { $prev = [Console]::ForegroundColor } catch { }
            try { [Console]::ForegroundColor = $ForegroundColor } catch { }
            $written = [uint32]0
            $ok = [SfdlNative.ConsoleIo]::WriteConsoleW($script:SfdlStdOutHandle, $line, [uint32]$line.Length, [ref]$written, [IntPtr]::Zero)
            if ($ok) { return }
        }
        finally {
            if ($null -ne $prev) {
                try { [Console]::ForegroundColor = $prev } catch { }
            }
        }
    }

    # 2) Umgeleitet (Windows Terminal / ConPTY / Pipe): UTF-8-Bytes + VT-Farbe
    try {
        $utf8 = if ($script:SfdlUtf8NoBom) { $script:SfdlUtf8NoBom } else { New-Object System.Text.UTF8Encoding $false }
        $esc = [char]27
        $code = Get-SfdlAnsiForegroundCode -ForegroundColor $ForegroundColor
        $payload = '{0}[{1}m{2}{0}[0m{3}' -f $esc, $code, $Text, [Environment]::NewLine
        $bytes = $utf8.GetBytes($payload)
        $stdout = [Console]::OpenStandardOutput()
        $stdout.Write($bytes, 0, $bytes.Length)
        return
    }
    catch { }

    # 3) Fallback
    try {
        Write-Host $Text -ForegroundColor $ForegroundColor
    }
    catch {
        try { [Console]::WriteLine($Text) } catch { Write-Output $Text }
    }
}

function Write-SfdlLog {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'OK')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory, ValueFromRemainingArguments)]
        [object[]]$Message
    )
    $text = ($Message | ForEach-Object { "$_" }) -join ' '
    $ts = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'INFO'  { [ConsoleColor]::Cyan }
        'WARN'  { [ConsoleColor]::Yellow }
        'ERROR' { [ConsoleColor]::Red }
        'DEBUG' { [ConsoleColor]::DarkGray }
        'OK'    { [ConsoleColor]::Green }
        default { [ConsoleColor]::White }
    }
    Write-SfdlHostLine -Text "[$ts][$Level] $text" -ForegroundColor $color
}

function Format-ByteSize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N2} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:N2} KB' -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Format-Speed {
    param([double]$BytesPerSecond)
    if ($BytesPerSecond -ge 1GB) { return '{0:N2} GB/s' -f ($BytesPerSecond / 1GB) }
    if ($BytesPerSecond -ge 1MB) { return '{0:N2} MB/s' -f ($BytesPerSecond / 1MB) }
    if ($BytesPerSecond -ge 1KB) { return '{0:N2} KB/s' -f ($BytesPerSecond / 1KB) }
    return ('{0:N0} B/s' -f [Math]::Max(0, $BytesPerSecond))
}

function ConvertTo-Hms {
    param([double]$Seconds)
    $ts = [TimeSpan]::FromSeconds([Math]::Max(0, $Seconds))
    '{0:00}:{1:00}:{2:00}' -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds
}

function Format-ProgressBar {
    param(
        [double]$Percent,
        [int]$Width = 30
    )
    $pct = [Math]::Max(0, [Math]::Min(100, $Percent))
    $filled = [int][Math]::Round(($pct / 100.0) * $Width)
    $empty = $Width - $filled
    return ('[{0}{1}]' -f ('#' * $filled), ('-' * $empty))
}

function Get-ConsoleLineWidth {
    try {
        $w = $Host.UI.RawUI.WindowSize.Width
        if ($w -gt 20) { return $w }
    }
    catch { }
    return 100
}

function Write-ConsoleLinePadded {
    param([string]$Text, [ConsoleColor]$ForegroundColor = [ConsoleColor]::Gray)
    $width = Get-ConsoleLineWidth
    $line = if ($null -eq $Text) { ''.PadRight([Math]::Max(0, $width - 1)) }
            elseif ($Text.Length -ge $width) { $Text.Substring(0, [Math]::Max(1, $width - 1)) }
            else { $Text.PadRight($width - 1) }
    Write-SfdlHostLine -Text $line -ForegroundColor $ForegroundColor
}

# ---------------------------------------------------------------------------
# Crypto - AES-128-CBC, Key = MD5(UTF8(password)), IV prepended, Base64
# (identisch zu SFDL.Container / markhaehnel/sfdl)
# ---------------------------------------------------------------------------
function Get-SfdlAesKey {
    param([string]$Password)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        return $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
    }
    finally {
        $md5.Dispose()
    }
}

function Decrypt-SfdlString {
    param(
        [AllowEmptyString()]
        [string]$Value,
        [string]$Password
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

    $blob = [Convert]::FromBase64String($Value)
    if ($blob.Length -lt 16) {
        throw "Ciphertext zu kurz ($($blob.Length) Bytes)."
    }

    $iv = New-Object byte[] 16
    [Array]::Copy($blob, 0, $iv, 0, 16)
    $cipherLen = $blob.Length - 16
    $cipher = New-Object byte[] $cipherLen
    [Array]::Copy($blob, 16, $cipher, 0, $cipherLen)

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 128
        $aes.Key = Get-SfdlAesKey -Password $Password
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        try {
            $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
            return [System.Text.Encoding]::UTF8.GetString($plain)
        }
        finally {
            $decryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }
}

function Test-SfdlPassword {
    param(
        [string]$EncryptedHost,
        [string]$Password
    )
    # Leerer Ciphertext darf kein Passwort "erfolgreich" machen
    if ([string]::IsNullOrWhiteSpace($EncryptedHost)) { return $false }
    if ($null -eq $Password) { return $false }
    try {
        $null = Decrypt-SfdlString -Value $EncryptedHost -Password $Password
        return $true
    }
    catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
function Sanitize-FileName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return '_' }
    # Path-Traversal-Segmente nie als Ordner-/Dateiname durchlassen
    if ($Name -eq '.' -or $Name -eq '..') { return '_' }

    $invalid = [Regex]::Escape([string][IO.Path]::GetInvalidFileNameChars())
    $clean = [Regex]::Replace($Name, "[$invalid]+", '_')
    $clean = $clean.TrimEnd(' ', '.')
    $reserved = @('CON','PRN','AUX','CLOCK$','NUL',
        'COM0','COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9',
        'LPT0','LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9')
    $base = [IO.Path]::GetFileNameWithoutExtension($clean)
    $ext = [IO.Path]::GetExtension($clean)
    foreach ($word in $reserved) {
        if ($base.Equals($word, [StringComparison]::OrdinalIgnoreCase)) {
            $clean = "_$base$ext"
            break
        }
        # CLOCK$ u. a.: Metazeichen in reserved Names escapen
        $escapedWord = [Regex]::Escape($word)
        $clean = [Regex]::Replace($clean, "^$escapedWord\.", "_$word.", 'IgnoreCase')
    }
    if ([string]::IsNullOrWhiteSpace($clean) -or $clean -eq '.' -or $clean -eq '..') { return '_' }
    return $clean
}

function Test-SfdlLocalPathUnderRoot {
    param(
        [string]$LocalRoot,
        [string]$CandidatePath
    )
    if ([string]::IsNullOrWhiteSpace($LocalRoot) -or [string]::IsNullOrWhiteSpace($CandidatePath)) {
        return $false
    }
    $rootFull = [IO.Path]::GetFullPath($LocalRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $targetFull = [IO.Path]::GetFullPath($CandidatePath)
    return $targetFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
           $targetFull.TrimEnd('\', '/').Equals($rootFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)
}

function Get-XmlChildText {
    param(
        [System.Xml.XmlNode]$Node,
        [string]$Name,
        [string]$Default = ''
    )
    if ($null -eq $Node) { return $Default }
    $child = $Node.SelectSingleNode($Name)
    if ($null -eq $child -or [string]::IsNullOrWhiteSpace($child.InnerText)) {
        return $Default
    }
    return $child.InnerText.Trim()
}

function Get-XmlChildBool {
    param([System.Xml.XmlNode]$Node, [string]$Name, [bool]$Default = $false)
    $t = Get-XmlChildText -Node $Node -Name $Name
    if ([string]::IsNullOrWhiteSpace($t)) { return $Default }
    switch -Regex ($t.Trim()) {
        '^(?i)(true|yes|y|1)$'  { return $true }
        '^(?i)(false|no|n|0)$' { return $false }
        default {
            try { return [System.Convert]::ToBoolean($t) }
            catch { return $Default }
        }
    }
}

function Get-XmlChildInt {
    param([System.Xml.XmlNode]$Node, [string]$Name, [int]$Default = 0)
    $t = Get-XmlChildText -Node $Node -Name $Name
    if ([string]::IsNullOrWhiteSpace($t)) { return $Default }
    $n = 0
    if ([int]::TryParse($t, [ref]$n)) { return $n }
    return $Default
}

function Get-XmlChildLong {
    param([System.Xml.XmlNode]$Node, [string]$Name, [long]$Default = 0)
    $t = Get-XmlChildText -Node $Node -Name $Name
    if ([string]::IsNullOrWhiteSpace($t)) { return $Default }
    $n = [long]0
    if ([long]::TryParse($t, [ref]$n)) { return $n }
    return $Default
}

# ---------------------------------------------------------------------------
# SFDL parse / convert
# ---------------------------------------------------------------------------
function Get-SfdlContainerVersion {
    param([string]$Path)
    $raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $xml = New-Object System.Xml.XmlDocument
    $xml.XmlResolver = $null
    $xml.LoadXml($raw)

    foreach ($el in $xml.GetElementsByTagName('ContainerVersion')) {
        $v = 0
        if ([int]::TryParse($el.InnerText.Trim(), [ref]$v)) { return $v }
    }
    foreach ($el in $xml.GetElementsByTagName('SFDLFileVersion')) {
        $v = 0
        if ([int]::TryParse($el.InnerText.Trim(), [ref]$v)) { return $v }
    }
    return 0
}

function ConvertFrom-SfdlDataConnectionType {
    param([string]$Value, [bool]$IsV2 = $false)
    if ($IsV2) {
        switch -Regex ($Value) {
            'AutoActive|Active|PORT' { return 'Active' }
            'EPSV|ExtendedPassive'   { return 'ExtendedPassive' }
            default                  { return 'Passive' }
        }
    }
    switch -Regex ($Value) {
        'Active'           { return 'Active' }
        'ExtendedPassive'  { return 'ExtendedPassive' }
        default            { return 'Passive' }
    }
}

function ConvertFrom-SfdlSslProtocol {
    param([string]$Value, [bool]$IsV2EncryptionMode = $false)
    if ($IsV2EncryptionMode) {
        # v2 EncryptionMode -> v3 SSLProtocol mapping (Converter.vb)
        switch ($Value) {
            'Implicit' { return 'Tls' }   # FtpES
            'Explicit' { return 'Tls' }   # früher Ssl3 - auf modernen Windows-Systemen tot
            default    { return 'None' }
        }
    }
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'None' }
    return $Value
}

function New-SfdlFileItem {
    param([System.Xml.XmlNode]$Node, [bool]$IsV2 = $false)
    $fullPathName = if ($IsV2) { 'FileFullPath' } else { 'FullPath' }
    $hashTypeName = if ($IsV2) { 'FileHashType' } else { 'HashType' }

    [pscustomobject]@{
        FileName      = Get-XmlChildText -Node $Node -Name 'FileName'
        DirectoryRoot = Get-XmlChildText -Node $Node -Name 'DirectoryRoot'
        DirectoryPath = Get-XmlChildText -Node $Node -Name 'DirectoryPath'
        FullPath      = Get-XmlChildText -Node $Node -Name $fullPathName
        FileSize      = Get-XmlChildLong -Node $Node -Name 'FileSize'
        HashType      = Get-XmlChildText -Node $Node -Name $hashTypeName -Default 'None'
        FileHash      = Get-XmlChildText -Node $Node -Name 'FileHash'
        PackageName   = Get-XmlChildText -Node $Node -Name 'PackageName'
    }
}

function New-SfdlBulkFolder {
    param([System.Xml.XmlNode]$Node)
    [pscustomobject]@{
        BulkFolderPath = Get-XmlChildText -Node $Node -Name 'BulkFolderPath'
        PackageName    = Get-XmlChildText -Node $Node -Name 'PackageName'
    }
}

function New-SfdlPackageFromXml {
    param([System.Xml.XmlNode]$Node, [bool]$IsV2 = $false)
    $nameTag = if ($IsV2) { 'Packagename' } else { 'Name' }
    $fileTag = if ($IsV2) { 'FileInfo' } else { 'FileItem' }

    $files = New-Object System.Collections.Generic.List[object]
    $fileListNode = $Node.SelectSingleNode('FileList')
    if ($fileListNode) {
        foreach ($f in $fileListNode.SelectNodes($fileTag)) {
            $files.Add((New-SfdlFileItem -Node $f -IsV2:$IsV2))
        }
    }

    $bulk = New-Object System.Collections.Generic.List[object]
    $bulkListNode = $Node.SelectSingleNode('BulkFolderList')
    if ($bulkListNode) {
        foreach ($b in $bulkListNode.SelectNodes('BulkFolder')) {
            $bulk.Add((New-SfdlBulkFolder -Node $b))
        }
    }

    [pscustomobject]@{
        Name           = Get-XmlChildText -Node $Node -Name $nameTag
        BulkFolderMode = Get-XmlChildBool -Node $Node -Name 'BulkFolderMode'
        FileList       = $files
        BulkFolderList = $bulk
    }
}

function Read-SfdlContainer {
    param([string]$Path)

    $version = Get-SfdlContainerVersion -Path $Path
    Write-SfdlLog INFO "SFDL-Version: $version"

    if ($version -eq 0 -or $version -gt 10) {
        throw "Ungültige oder nicht unterstützte SFDL-Version: $version"
    }
    if ($version -ge 1 -and $version -le 5) {
        throw "SFDL v1 (Version $version) wird nicht unterstützt."
    }

    $isV2 = ($version -ge 6 -and $version -le 9)
    $raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $xml = New-Object System.Xml.XmlDocument
    $xml.XmlResolver = $null
    $xml.LoadXml($raw)

    if ($isV2) {
        $root = $xml.SelectSingleNode('//SFDLFile')
        if (-not $root) { throw 'SFDL v2 Root <SFDLFile> nicht gefunden.' }
        $connNode = $root.SelectSingleNode('ConnectionInfo')
        $pkgTag = 'SFDLPackage'
        $encMode = Get-XmlChildText -Node $connNode -Name 'EncryptionMode' -Default 'None'
        $ssl = ConvertFrom-SfdlSslProtocol -Value $encMode -IsV2EncryptionMode:$true
        $dataConn = ConvertFrom-SfdlDataConnectionType -Value (Get-XmlChildText -Node $connNode -Name 'DataConnectionType') -IsV2:$true
    }
    else {
        $root = $xml.SelectSingleNode('//Container')
        if (-not $root) { throw 'SFDL v3 Root <Container> nicht gefunden.' }
        $connNode = $root.SelectSingleNode('Connection')
        $pkgTag = 'Package'
        $ssl = ConvertFrom-SfdlSslProtocol -Value (Get-XmlChildText -Node $connNode -Name 'SSLProtocol' -Default 'None')
        $dataConn = ConvertFrom-SfdlDataConnectionType -Value (Get-XmlChildText -Node $connNode -Name 'DataConnectionType' -Default 'Passive')
    }

    $packages = New-Object System.Collections.Generic.List[object]
    $pkgRoot = $root.SelectSingleNode('Packages')
    if ($pkgRoot) {
        foreach ($p in $pkgRoot.SelectNodes($pkgTag)) {
            $packages.Add((New-SfdlPackageFromXml -Node $p -IsV2:$isV2))
        }
    }

    $container = [pscustomobject]@{
        Description         = Get-XmlChildText -Node $root -Name 'Description'
        Uploader            = Get-XmlChildText -Node $root -Name 'Uploader'
        ContainerVersion    = 10
        Encrypted           = Get-XmlChildBool -Node $root -Name 'Encrypted'
        MaxDownloadThreads  = Get-XmlChildInt -Node $root -Name 'MaxDownloadThreads' -Default 3
        SourceVersion       = $version
        Connection          = [pscustomobject]@{
            Host               = Get-XmlChildText -Node $connNode -Name 'Host'
            Port               = Get-XmlChildInt -Node $connNode -Name 'Port' -Default 21
            Username           = Get-XmlChildText -Node $connNode -Name 'Username'
            Password           = Get-XmlChildText -Node $connNode -Name 'Password'
            AuthRequired       = Get-XmlChildBool -Node $connNode -Name 'AuthRequired'
            DataConnectionType = $dataConn
            DataType           = Get-XmlChildText -Node $connNode -Name 'DataType' -Default 'Binary'
            CharacterEncoding  = Get-XmlChildText -Node $connNode -Name 'CharacterEncoding' -Default 'UTF8'
            SSLProtocol        = $ssl
            ConnectTimeout     = Get-XmlChildInt -Node $connNode -Name 'ConnectTimeout' -Default 30
            CommandTimeout     = Get-XmlChildInt -Node $connNode -Name 'CommandTimeout' -Default 30
        }
        Packages            = $packages
    }

    return $container
}

function Decrypt-SfdlContainer {
    param(
        [Parameter(Mandatory)]
        $Container,
        [Parameter(Mandatory)]
        [string]$Password
    )

    $Container.Description = Decrypt-SfdlString -Value $Container.Description -Password $Password
    $Container.Uploader    = Decrypt-SfdlString -Value $Container.Uploader -Password $Password
    $Container.Connection.Host     = Decrypt-SfdlString -Value $Container.Connection.Host -Password $Password
    $Container.Connection.Username = Decrypt-SfdlString -Value $Container.Connection.Username -Password $Password
    $Container.Connection.Password = Decrypt-SfdlString -Value $Container.Connection.Password -Password $Password

    foreach ($pkg in $Container.Packages) {
        $pkg.Name = Decrypt-SfdlString -Value $pkg.Name -Password $Password
        foreach ($f in $pkg.FileList) {
            $f.DirectoryPath = Decrypt-SfdlString -Value $f.DirectoryPath -Password $Password
            $f.DirectoryRoot = Decrypt-SfdlString -Value $f.DirectoryRoot -Password $Password
            $f.FileName      = Decrypt-SfdlString -Value $f.FileName -Password $Password
            $f.FullPath      = Decrypt-SfdlString -Value $f.FullPath -Password $Password
            $f.PackageName   = Decrypt-SfdlString -Value $f.PackageName -Password $Password
        }
        foreach ($b in $pkg.BulkFolderList) {
            $b.BulkFolderPath = Decrypt-SfdlString -Value $b.BulkFolderPath -Password $Password
            $b.PackageName    = Decrypt-SfdlString -Value $b.PackageName -Password $Password
        }
    }
    $Container.Encrypted = $false
}

function Get-ScriptPasswords {
    $list = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $script:PasswordListFile) {
        Get-Content -LiteralPath $script:PasswordListFile -Encoding UTF8 -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^\s*#' } |
            ForEach-Object { $list.Add($_.Trim()) }
    }
    return $list
}

function Save-ScriptPassword {
    param([string]$Password)
    if ([string]::IsNullOrWhiteSpace($Password)) { return }
    $existing = Get-ScriptPasswords
    if ($existing -notcontains $Password) {
        Add-Content -LiteralPath $script:PasswordListFile -Value $Password -Encoding UTF8
        Write-SfdlLog INFO 'Passwort in passwords.txt gespeichert.'
    }
}

function Resolve-SfdlPassword {
    param(
        [Parameter(Mandatory)]$Container,
        [string]$ProvidedPassword
    )

    if (-not $Container.Encrypted) { return $null }

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($ProvidedPassword)) {
        $candidates.Add($ProvidedPassword)
    }
    else {
        $fromFile = @(Get-ScriptPasswords)
        if ($fromFile.Count -gt 0) {
            Write-SfdlLog INFO ("Versuche {0} Passwort(e) aus passwords.txt ..." -f $fromFile.Count)
            foreach ($p in $fromFile) {
                if ($candidates -notcontains $p) { $candidates.Add($p) }
            }
        }
        else {
            Write-SfdlLog INFO ("Keine passwords.txt neben dem Skript gefunden ({0})." -f $script:PasswordListFile)
        }
    }

    foreach ($pw in $candidates) {
        if (Test-SfdlPassword -EncryptedHost $Container.Connection.Host -Password $pw) {
            Write-SfdlLog OK 'Container-Passwort akzeptiert.'
            if ([string]::IsNullOrWhiteSpace($ProvidedPassword)) {
                Save-ScriptPassword -Password $pw
            }
            return $pw
        }
    }

    while ($true) {
        $secure = Read-Host -Prompt 'Container-Passwort' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if ([string]::IsNullOrWhiteSpace($pw)) {
            throw 'Abbruch: kein Passwort angegeben.'
        }
        if (Test-SfdlPassword -EncryptedHost $Container.Connection.Host -Password $pw) {
            Save-ScriptPassword -Password $pw
            return $pw
        }
        Write-SfdlLog WARN 'Falsches Passwort - bitte erneut eingeben.'
    }
}

# ---------------------------------------------------------------------------
# FTP helpers (System.Net.FtpWebRequest)
# ---------------------------------------------------------------------------
function Get-FtpUri {
    param($Connection, [string]$RemotePath = '/')
    $hostPart = [string]$Connection.Host
    # IPv6: in URI-Klammern setzen
    if ($hostPart -match ':' -and -not $hostPart.StartsWith('[')) {
        $hostPart = "[$hostPart]"
    }
    $port = $Connection.Port
    $path = ($RemotePath -replace '\\', '/')
    if ([string]::IsNullOrWhiteSpace($path)) { $path = '/' }
    if (-not $path.StartsWith('/')) { $path = '/' + $path }

    # Segmente einzeln encoden, Slash-Struktur erhalten
    $encodedSegments = foreach ($seg in ($path -split '/')) {
        if ($seg -eq '') { '' }
        else { [Uri]::EscapeDataString($seg) }
    }
    $encodedPath = ($encodedSegments -join '/')
    if (-not $encodedPath.StartsWith('/')) { $encodedPath = '/' + $encodedPath }

    return [Uri]("ftp://${hostPart}:${port}${encodedPath}")
}

function Get-FtpTextEncoding {
    param($Connection)
    $name = if ($Connection -and $Connection.CharacterEncoding) { $Connection.CharacterEncoding } else { 'UTF8' }
    switch -Regex ($name) {
        '^(?i)UTF-?8$'     { return [Text.Encoding]::UTF8 }
        '^(?i)ASCII$'      { return [Text.Encoding]::ASCII }
        '^(?i)Unicode$'    { return [Text.Encoding]::Unicode }
        '^(?i)Default|ANSI$' { return [Text.Encoding]::Default }
        default {
            try { return [Text.Encoding]::GetEncoding($name) }
            catch { return [Text.Encoding]::UTF8 }
        }
    }
}

function Set-FtpRequestCredentials {
    param($Request, $Connection)
    $hasUser = -not [string]::IsNullOrWhiteSpace($Connection.Username)
    if ($Connection.AuthRequired -or $hasUser) {
        $user = if ($hasUser) { $Connection.Username } else { 'anonymous' }
        $pass = if ([string]::IsNullOrWhiteSpace($Connection.Password)) { 'sfdl@anon.net' } else { $Connection.Password }
        $Request.Credentials = New-Object System.Net.NetworkCredential($user, $pass)
    }
    else {
        $Request.Credentials = New-Object System.Net.NetworkCredential('anonymous', 'sfdl@anon.net')
    }
}

function New-FtpRequest {
    param(
        $Connection,
        [string]$RemotePath,
        [string]$Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile,
        [long]$RestartOffset = 0
    )

    $uri = Get-FtpUri -Connection $Connection -RemotePath $RemotePath
    $req = [System.Net.FtpWebRequest]::Create($uri)
    $req.Method = $Method
    $req.UseBinary = ($Connection.DataType -ne 'ASCII')
    $req.UsePassive = ($Connection.DataConnectionType -ne 'Active')
    $req.KeepAlive = $false
    $req.Timeout = [Math]::Max(10000, $Connection.ConnectTimeout * 1000)
    $req.ReadWriteTimeout = [Math]::Max(30000, $Connection.CommandTimeout * 1000)

    if ($Connection.SSLProtocol -and $Connection.SSLProtocol -ne 'None') {
        $req.EnableSsl = $true
    }

    Set-FtpRequestCredentials -Request $req -Connection $Connection

    if ($RestartOffset -gt 0) {
        $req.ContentOffset = $RestartOffset
    }

    return $req
}

function Test-FtpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 5000)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) {
            $client.Close()
            return $false
        }
        $client.EndConnect($iar)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Parse-FtpListLine {
    <#
    .SYNOPSIS
        Parst Unix/Windows LIST-Zeilen und liefert Name, Typ, Größe.
    #>
    param(
        [string]$Line,
        [string]$ParentPath
    )
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    $parent = ($ParentPath -replace '\\', '/').TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($parent)) { $parent = '' }

    # MLSD: type=file;size=123; name
    if ($Line -match '(?i)(?:^|;)\s*type=([^;]+);') {
        $typeRaw = $Matches[1].Trim()
        $size = 0L
        if ($Line -match '(?i)size=(\d+);') { $size = [long]$Matches[1] }
        $name = ($Line -split ' ', 2)[-1].Trim()
        if ($name -match ';') { $name = ($Line.Substring($Line.LastIndexOf(';') + 1)).Trim() }
        if ($name -eq '.' -or $name -eq '..') { return $null }
        $isDir = $typeRaw -match '^(dir|cdir|pdir)$'
        $full = if ($parent) { "$parent/$name" } else { "/$name" }
        return [pscustomobject]@{ Name = $name; FullPath = $full; IsDirectory = [bool]$isDir; Size = $size }
    }

    # Windows IIS: 01-01-20  01:00AM  <DIR>  name  OR  size name
    if ($Line -match '^\d{2}-\d{2}-\d{2}\s+\d{1,2}:\d{2}(?:AM|PM)\s+(<DIR>|\d+)\s+(.+)$') {
        $isDir = ($Matches[1] -eq '<DIR>')
        $size = if ($isDir) { 0L } else { [long]$Matches[1] }
        $name = $Matches[2].Trim()
        if ($name -eq '.' -or $name -eq '..') { return $null }
        $full = if ($parent) { "$parent/$name" } else { "/$name" }
        return [pscustomobject]@{ Name = $name; FullPath = $full; IsDirectory = $isDir; Size = $size }
    }

    # Unix: drwxr-xr-x ... name
    if ($Line -match '^([d\-l])[rwxsStT\-]{9}\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\d+\s+[\d:]+\s+(.+)$') {
        $isDir = ($Matches[1] -eq 'd')
        $size = [long]$Matches[2]
        $name = $Matches[3].Trim()
        if ($name -eq '.' -or $name -eq '..') { return $null }
        # optional " -> link"
        if ($name -match '^(.*) -> ') { $name = $Matches[1] }
        $full = if ($parent) { "$parent/$name" } else { "/$name" }
        return [pscustomobject]@{ Name = $name; FullPath = $full; IsDirectory = $isDir; Size = $size }
    }

    return $null
}

function Test-FtpPathIsDirectory {
    param($Connection, [string]$RemotePath)
    # SIZE erfolgreich -> Datei; sonst LIST versuchen -> Verzeichnis
    try {
        $req = New-FtpRequest -Connection $Connection -RemotePath $RemotePath `
            -Method ([System.Net.WebRequestMethods+Ftp]::GetFileSize)
        $resp = $req.GetResponse()
        try { $resp.Close() } catch { }
        return $false
    }
    catch { }

    try {
        $req = New-FtpRequest -Connection $Connection -RemotePath $RemotePath `
            -Method ([System.Net.WebRequestMethods+Ftp]::ListDirectory)
        $resp = $req.GetResponse()
        try { $resp.Close() } catch { }
        return $true
    }
    catch {
        return $false
    }
}

function Get-FtpDirectoryListing {
    param(
        $Connection,
        [string]$RemotePath
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $encoding = Get-FtpTextEncoding -Connection $Connection
    $methods = @(
        [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        [System.Net.WebRequestMethods+Ftp]::ListDirectory
    )

    foreach ($method in $methods) {
        try {
            $req = New-FtpRequest -Connection $Connection -RemotePath $RemotePath -Method $method
            $resp = $req.GetResponse()
            try {
                $stream = $resp.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream, $encoding)
                $text = $reader.ReadToEnd()
                $reader.Close()
                foreach ($line in ($text -split "`r?`n")) {
                    $parsed = Parse-FtpListLine -Line $line -ParentPath $RemotePath
                    if ($parsed) { $entries.Add($parsed) }
                    elseif ($method -eq [System.Net.WebRequestMethods+Ftp]::ListDirectory -and -not [string]::IsNullOrWhiteSpace($line)) {
                        $name = $line.Trim()
                        if ($name -eq '.' -or $name -eq '..') { continue }
                        $parent = ($RemotePath -replace '\\', '/').TrimEnd('/')
                        $full = if ($parent) { "$parent/$name" } else { "/$name" }
                        $isDir = Test-FtpPathIsDirectory -Connection $Connection -RemotePath $full
                        $entries.Add([pscustomobject]@{
                            Name = $name; FullPath = $full; IsDirectory = $isDir; Size = 0L
                        })
                    }
                }
            }
            finally {
                $resp.Close()
            }
            if ($entries.Count -gt 0) { break }
        }
        catch {
            Write-SfdlLog DEBUG "LIST $RemotePath ($method) fehlgeschlagen: $($_.Exception.Message)"
            $entries.Clear()
        }
    }
    return $entries
}

function Get-FtpBulkFileList {
    param(
        $Connection,
        [string]$BulkFolderPath,
        [string]$PackageName,
        [string]$DirectoryRoot = $null,
        [int]$Depth = 0
    )

    if ($Depth -gt 64) {
        Write-SfdlLog WARN "Max. Rekursionstiefe erreicht bei $BulkFolderPath"
        return @()
    }

    $root = if ($null -eq $DirectoryRoot) { $BulkFolderPath } else { $DirectoryRoot }
    $files = New-Object System.Collections.Generic.List[object]
    $entries = Get-FtpDirectoryListing -Connection $Connection -RemotePath $BulkFolderPath

    foreach ($entry in ($entries | Sort-Object Name)) {
        if ($entry.IsDirectory) {
            $child = Get-FtpBulkFileList -Connection $Connection -BulkFolderPath $entry.FullPath `
                -PackageName $PackageName -DirectoryRoot $root -Depth ($Depth + 1)
            foreach ($c in $child) { $files.Add($c) }
        }
        else {
            $files.Add([pscustomobject]@{
                FileName      = $entry.Name
                DirectoryRoot = $root
                DirectoryPath = $BulkFolderPath
                FullPath      = $entry.FullPath
                FileSize      = [long]$entry.Size
                HashType      = 'None'
                FileHash      = ''
                PackageName   = $PackageName
            })
        }
    }
    return $files
}

function Expand-SfdlBulkFolders {
    param($Container)

    $bulkPackages = @($Container.Packages | Where-Object { $_.BulkFolderMode })
    if ($bulkPackages.Count -eq 0) { return }

    Write-SfdlLog INFO "Bulk-Folder-Modus: rekursives Listing für $($bulkPackages.Count) Package(s)..."
    if (-not (Test-FtpPort -HostName $Container.Connection.Host -Port $Container.Connection.Port)) {
        throw "FTP-Port $($Container.Connection.Host):$($Container.Connection.Port) nicht erreichbar."
    }

    foreach ($pkg in $bulkPackages) {
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($bulk in $pkg.BulkFolderList) {
            Write-SfdlLog INFO "  Listing: $($bulk.BulkFolderPath)"
            $listed = Get-FtpBulkFileList -Connection $Container.Connection `
                -BulkFolderPath $bulk.BulkFolderPath -PackageName $pkg.Name
            foreach ($f in $listed) { $all.Add($f) }
        }
        $pkg.FileList = $all
        Write-SfdlLog OK "  $($all.Count) Datei(en) gefunden in Package '$($pkg.Name)'."
    }
}

# ---------------------------------------------------------------------------
# Download items / blacklist / paths
# ---------------------------------------------------------------------------
function ConvertTo-SfdlBlacklistRegex {
    param([string]$Pattern)
    # Explizite Regex (Anker): unverändert; sonst Literal (Punkte etc. escapen)
    if ($Pattern.StartsWith('^') -or $Pattern.EndsWith('$')) {
        return $Pattern
    }
    return ('^{0}$' -f [Regex]::Escape($Pattern))
}

function Test-BlacklistMatch {
    param(
        [string]$FileName,
        [string[]]$Patterns
    )
    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        if ($FileName.Equals($pat, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        $regex = ConvertTo-SfdlBlacklistRegex -Pattern $pat
        try {
            if ([Regex]::IsMatch($FileName, $regex, 'IgnoreCase')) { return $true }
        }
        catch {
            if ($FileName.Equals($pat, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    return $false
}

function Get-DownloadLocalPath {
    param(
        [string]$LocalRoot,
        $Item,
        [bool]$CreatePackageSubfolder
    )

    $dir = $LocalRoot
    if ($CreatePackageSubfolder -and -not [string]::IsNullOrWhiteSpace($Item.PackageName)) {
        $dir = Join-Path $dir (Sanitize-FileName $Item.PackageName)
    }

    $rel = ''
    if ($Item.DirectoryPath -and $Item.DirectoryRoot) {
        $pathNorm = $Item.DirectoryPath -replace '\\', '/'
        $rootNorm = ($Item.DirectoryRoot -replace '\\', '/').TrimEnd('/')
        if ($pathNorm.StartsWith($rootNorm, [StringComparison]::OrdinalIgnoreCase)) {
            $rel = $pathNorm.Substring($rootNorm.Length)
        }
        else {
            # Fallback: case-insensitive Replace nur des Prefixes
            $idx = $pathNorm.IndexOf($rootNorm, [StringComparison]::OrdinalIgnoreCase)
            if ($idx -eq 0) {
                $rel = $pathNorm.Substring($rootNorm.Length)
            }
        }
    }
    $rel = $rel.TrimStart('\', '/').TrimEnd('\', '/')
    if ($rel) {
        foreach ($part in ($rel -split '[\\/]+')) {
            if (-not $part -or $part -eq '.' -or $part -eq '..') { continue }
            if ([IO.Path]::IsPathRooted($part)) {
                throw "Unsicherer DirectoryPath abgelehnt: $($Item.DirectoryPath)"
            }
            $dir = Join-Path $dir (Sanitize-FileName $part)
        }
    }

    $localPath = Join-Path $dir (Sanitize-FileName $Item.FileName)
    if (-not (Test-SfdlLocalPathUnderRoot -LocalRoot $LocalRoot -CandidatePath $localPath)) {
        throw "Lokaler Pfad außerhalb des Download-Roots abgelehnt: $localPath"
    }
    return $localPath
}

function New-DownloadItemList {
    param(
        $Container,
        [string]$LocalRoot,
        [bool]$CreatePackageSubfolder,
        [string[]]$UserBlacklist,
        [string[]]$MaliciousBlacklist,
        [bool]$ExcludeMalicious
    )

    $items = New-Object System.Collections.Generic.List[object]
    $pkgIndex = 1

    foreach ($pkg in $Container.Packages) {
        if ([string]::IsNullOrWhiteSpace($pkg.Name)) {
            $pkg.Name = "Package$pkgIndex"
        }
        $pkgIndex++

        foreach ($file in $pkg.FileList) {
            $excluded = $false
            $excludeReason = ''

            if ($ExcludeMalicious -and (Test-BlacklistMatch -FileName $file.FileName -Patterns $MaliciousBlacklist)) {
                $excluded = $true
                $excludeReason = 'Malicious'
            }
            elseif (Test-BlacklistMatch -FileName $file.FileName -Patterns $UserBlacklist) {
                $excluded = $true
                $excludeReason = 'User'
            }

            $local = Get-DownloadLocalPath -LocalRoot $LocalRoot -Item ([pscustomobject]@{
                PackageName   = $pkg.Name
                DirectoryPath = $file.DirectoryPath
                DirectoryRoot = $file.DirectoryRoot
                FileName      = $file.FileName
            }) -CreatePackageSubfolder:$CreatePackageSubfolder

            $status = 'Pending'
            $selected = -not $excluded

            if (-not $excluded -and $file.FileSize -gt 0 -and (Test-Path -LiteralPath $local)) {
                $len = (Get-Item -LiteralPath $local).Length
                if ($len -eq $file.FileSize) {
                    if (Test-SfdlFileHash -FilePath $local -HashType $file.HashType -ExpectedHash $file.FileHash) {
                        $status = 'AlreadyDownloaded'
                        $selected = $false
                    }
                }
            }

            $items.Add([pscustomobject]@{
                FileName      = $file.FileName
                DirectoryRoot = $file.DirectoryRoot
                DirectoryPath = $file.DirectoryPath
                FullPath      = $file.FullPath
                FileSize      = [long]$file.FileSize
                HashType      = $file.HashType
                FileHash      = $file.FileHash
                PackageName   = $pkg.Name
                LocalFile     = $local
                Selected      = $selected
                Excluded      = $excluded
                ExcludeReason = $excludeReason
                Status        = $status
                SizeDownloaded = [long]0
                Progress      = 0.0
                Speed         = ''
                BytesPerSecond = [double]0
                FirstUnRarFile = $false
                RetryCount    = 0
            })
        }
    }

    return $items
}

# ---------------------------------------------------------------------------
# Single-file FTP download with resume
# ---------------------------------------------------------------------------
function Test-SfdlFileHash {
    param(
        [string]$FilePath,
        [string]$HashType,
        [string]$ExpectedHash
    )
    if ([string]::IsNullOrWhiteSpace($HashType) -or $HashType -eq 'None') { return $true }
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) { return $true }
    if (-not (Test-Path -LiteralPath $FilePath)) { return $false }

    $algoName = switch -Regex ($HashType) {
        '^(?i)MD5$'    { 'MD5' }
        '^(?i)SHA1$'   { 'SHA1' }
        '^(?i)SHA256$' { 'SHA256' }
        '^(?i)SHA384$' { 'SHA384' }
        '^(?i)SHA512$' { 'SHA512' }
        default        { $null }
    }
    if (-not $algoName) {
        Write-SfdlLog WARN "Unbekannter HashType '$HashType' - Prüfung übersprungen."
        return $true
    }

    $algo = [System.Security.Cryptography.HashAlgorithm]::Create($algoName)
    if (-not $algo) { return $true }
    try {
        $fs = [IO.File]::OpenRead($FilePath)
        try {
            $hashBytes = $algo.ComputeHash($fs)
        }
        finally {
            $fs.Dispose()
        }
        $actual = ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
        $expected = ($ExpectedHash -replace '[\s-]', '').ToLowerInvariant()
        return ($actual -eq $expected)
    }
    finally {
        $algo.Dispose()
    }
}

function Invoke-FtpFileDownload {
    param(
        $Connection,
        $Item,
        [bool]$Resume = $true,
        [int]$BufferSize = 8192,
        $CancelEvent = $null,
        $ActiveRequests = $null
    )

    if ($CancelEvent -and $CancelEvent.IsSet) {
        $Item.Status = 'Stopped'
        $Item.BytesPerSecond = 0
        $Item.Speed = ''
        throw 'DownloadCancelled'
    }

    $remotePath = $Item.FullPath
    if ([string]::IsNullOrWhiteSpace($remotePath)) {
        throw "Kein FullPath für $($Item.FileName)"
    }

    $localDir = Split-Path -Parent $Item.LocalFile
    if (-not (Test-Path -LiteralPath $localDir)) {
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    }

    $restart = 0L
    $fileMode = [IO.FileMode]::Create

    if ($Resume -and (Test-Path -LiteralPath $Item.LocalFile)) {
        $existing = (Get-Item -LiteralPath $Item.LocalFile).Length
        if ($Item.FileSize -gt 0 -and $existing -eq $Item.FileSize) {
            if (-not (Test-SfdlFileHash -FilePath $Item.LocalFile -HashType $Item.HashType -ExpectedHash $Item.FileHash)) {
                Remove-Item -LiteralPath $Item.LocalFile -Force -ErrorAction SilentlyContinue
                $restart = 0L
                $fileMode = [IO.FileMode]::Create
                $Item.SizeDownloaded = 0
            }
            else {
                $Item.Status = 'Completed'
                $Item.SizeDownloaded = $Item.FileSize
                $Item.Progress = 100
                $Item.BytesPerSecond = 0
                $Item.Speed = ''
                return $Item
            }
        }
        elseif ($Item.FileSize -gt 0 -and $existing -gt $Item.FileSize) {
            # Lokale Datei größer als erwartet -> neu beginnen
            $restart = 0L
            $fileMode = [IO.FileMode]::Create
            $Item.SizeDownloaded = 0
        }
        elseif ($Item.FileSize -gt 0 -and $existing -gt 0 -and $existing -lt $Item.FileSize) {
            $restart = $existing
            $fileMode = [IO.FileMode]::Append
            $Item.SizeDownloaded = $existing
        }
        elseif ($Item.FileSize -eq 0 -and $existing -gt 0) {
            # Unbekannte Remote-Größe: kein Resume (REST unsicher -> Duplikat-Risiko)
            $restart = 0L
            $fileMode = [IO.FileMode]::Create
            $Item.SizeDownloaded = 0
        }
    }

    $Item.Status = 'Running'
    $start = Get-Date
    $requestId = [guid]::NewGuid().ToString()

    $req = New-FtpRequest -Connection $Connection -RemotePath $remotePath `
        -Method ([System.Net.WebRequestMethods+Ftp]::DownloadFile) -RestartOffset $restart

    if ($ActiveRequests) {
        $ActiveRequests[$requestId] = $req
    }

    $response = $null
    $remoteStream = $null
    $localStream = $null

    try {
        $response = $req.GetResponse()
        $remoteStream = $response.GetResponseStream()
        $localStream = New-Object IO.FileStream($Item.LocalFile, $fileMode, [IO.FileAccess]::Write, [IO.FileShare]::None, $BufferSize, $false)

        $buffer = New-Object byte[] $BufferSize

        while ($true) {
            if ($CancelEvent -and $CancelEvent.IsSet) {
                try { $req.Abort() } catch { }
                $Item.Status = 'Stopped'
                $Item.BytesPerSecond = 0
                $Item.Speed = ''
                throw 'DownloadCancelled'
            }

            $read = $remoteStream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $localStream.Write($buffer, 0, $read)
            $Item.SizeDownloaded += $read

            $elapsed = ((Get-Date) - $start).TotalSeconds
            $sessionBytes = [Math]::Max([long]0, $Item.SizeDownloaded - $restart)
            $bps = if ($elapsed -gt 0) { $sessionBytes / $elapsed } else { 0 }
            $Item.BytesPerSecond = $bps
            $Item.Speed = Format-Speed $bps
            if ($Item.FileSize -gt 0) {
                $Item.Progress = [Math]::Round(100.0 * $Item.SizeDownloaded / $Item.FileSize, 1)
            }
        }

        if ($CancelEvent -and $CancelEvent.IsSet) {
            $Item.Status = 'Stopped'
            $Item.BytesPerSecond = 0
            $Item.Speed = ''
            throw 'DownloadCancelled'
        }

        if ($localStream) {
            $localStream.Flush()
            $localStream.Dispose()
            $localStream = $null
        }

        if ($Item.FileSize -gt 0 -and $Item.SizeDownloaded -ne $Item.FileSize) {
            $Item.Status = 'Failed'
            $Item.BytesPerSecond = 0
            $Item.Speed = ''
            throw ("Größenmismatch: erwartet {0}, erhalten {1}" -f $Item.FileSize, $Item.SizeDownloaded)
        }

        if (-not (Test-SfdlFileHash -FilePath $Item.LocalFile -HashType $Item.HashType -ExpectedHash $Item.FileHash)) {
            $Item.Status = 'Failed'
            $Item.BytesPerSecond = 0
            $Item.Speed = ''
            throw ("Hash-Prüfung fehlgeschlagen ({0})" -f $Item.HashType)
        }

        $Item.Status = 'Completed'
        $Item.Progress = 100
        $Item.BytesPerSecond = 0
        $Item.Speed = ''
    }
    catch {
        if (($CancelEvent -and $CancelEvent.IsSet) -or $_.Exception.Message -eq 'DownloadCancelled') {
            $Item.Status = 'Stopped'
            $Item.BytesPerSecond = 0
            $Item.Speed = ''
            throw 'DownloadCancelled'
        }
        $Item.Status = 'Failed'
        $Item.BytesPerSecond = 0
        $Item.Speed = ''
        throw
    }
    finally {
        if ($ActiveRequests -and $ActiveRequests.ContainsKey($requestId)) {
            $ActiveRequests.Remove($requestId)
        }
        if ($localStream) { $localStream.Dispose() }
        if ($remoteStream) { $remoteStream.Dispose() }
        if ($response) { $response.Close() }
    }

    return $Item
}

function Write-SfdlDownloadProgress {
    param(
        [System.Collections.IList]$TrackedItems,
        [datetime]$StartedAt,
        [int]$TotalFiles,
        [int]$CompletedFiles,
        [int]$FailedFiles,
        [long]$BaselineDownloaded,
        [int]$DashboardLines,
        [bool]$Final = $false
    )

    $now = Get-Date
    $elapsedSec = [Math]::Max(0.001, ($now - $StartedAt).TotalSeconds)
    $elapsedText = ConvertTo-Hms $elapsedSec

    $totalBytes = 0L
    $downloadedBytes = 0L
    $activeSpeed = [double]0
    $active = New-Object System.Collections.Generic.List[object]

    foreach ($item in $TrackedItems) {
        $totalBytes += [long]$item.FileSize
        $downloadedBytes += [long]$item.SizeDownloaded
        if ($item.Status -eq 'Running') {
            $activeSpeed += [double]$item.BytesPerSecond
            $active.Add($item)
        }
    }

    $sessionBytes = [Math]::Max([long]0, $downloadedBytes - $BaselineDownloaded)
    $overallSpeed = if ($activeSpeed -gt 0) { $activeSpeed } else { $sessionBytes / $elapsedSec }
    $percent = if ($totalBytes -gt 0) { [Math]::Round(100.0 * $downloadedBytes / $totalBytes, 1) } else { 0 }

    $etaText = '--:--:--'
    $remaining = $totalBytes - $downloadedBytes
    if ($overallSpeed -gt 0 -and $remaining -gt 0) {
        $etaText = ConvertTo-Hms ($remaining / $overallSpeed)
    }
    elseif ($remaining -le 0 -and $totalBytes -gt 0) {
        $etaText = '00:00:00'
    }

    $width = Get-ConsoleLineWidth
    $barWidth = [Math]::Max(10, [Math]::Min(40, $width - 20))

    # Cursor zurücksetzen, damit die Anzeige live überschrieben wird
    if ($DashboardLines -gt 0) {
        try {
            $pos = $Host.UI.RawUI.CursorPosition
            $newTop = [Math]::Max(0, $pos.Y - $DashboardLines)
            $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 0, $newTop
        }
        catch { }
    }

    $linesWritten = 0
    $sep = ('=' * [Math]::Min($width - 1, 78))
    $thin = ('-' * [Math]::Min($width - 1, 78))

    Write-ConsoleLinePadded $sep ([ConsoleColor]::DarkCyan)
    $linesWritten++
    Write-ConsoleLinePadded (" Download-Fortschritt                  Verstrichen: {0}   ETA: {1}" -f $elapsedText, $etaText) ([ConsoleColor]::Cyan)
    $linesWritten++
    Write-ConsoleLinePadded $thin ([ConsoleColor]::DarkCyan)
    $linesWritten++

    Write-ConsoleLinePadded (" Gesamt:  {0} / {1}  ({2}%)   |   Geschwindigkeit: {3}" -f `
        (Format-ByteSize $downloadedBytes),
        (Format-ByteSize $totalBytes),
        $percent,
        (Format-Speed $overallSpeed)) ([ConsoleColor]::White)
    $linesWritten++

    Write-ConsoleLinePadded (" {0} {1,5:N1}%" -f (Format-ProgressBar -Percent $percent -Width $barWidth), $percent) ([ConsoleColor]::Green)
    $linesWritten++

    Write-ConsoleLinePadded (" Dateien: {0}/{1} fertig   |   Aktiv: {2}   |   Fehler: {3}" -f `
        $CompletedFiles, $TotalFiles, $active.Count, $FailedFiles) ([ConsoleColor]::Gray)
    $linesWritten++

    Write-ConsoleLinePadded $thin ([ConsoleColor]::DarkCyan)
    $linesWritten++

    $maxActiveLines = 8
    if ($active.Count -eq 0) {
        $msg = if ($Final) { ' Keine aktiven Downloads.' } else { ' Warte auf nächste Datei...' }
        Write-ConsoleLinePadded $msg ([ConsoleColor]::DarkGray)
        $linesWritten++
    }
    else {
        $shown = 0
        foreach ($a in ($active | Sort-Object FileName)) {
            if ($shown -ge $maxActiveLines) { break }
            $filePct = if ($a.FileSize -gt 0) {
                [Math]::Round(100.0 * $a.SizeDownloaded / $a.FileSize, 1)
            } else { 0 }
            $name = $a.FileName
            if ($name.Length -gt 36) { $name = $name.Substring(0, 33) + '...' }
            Write-ConsoleLinePadded (" > {0,-36} {1,10} / {2,-10} ({3,5:N1}%)  {4}" -f `
                $name,
                (Format-ByteSize $a.SizeDownloaded),
                (Format-ByteSize $a.FileSize),
                $filePct,
                (Format-Speed $a.BytesPerSecond)) ([ConsoleColor]::Yellow)
            $linesWritten++
            $shown++
        }
        if ($active.Count -gt $maxActiveLines) {
            Write-ConsoleLinePadded ("   ... und {0} weitere aktive Datei(en)" -f ($active.Count - $maxActiveLines)) ([ConsoleColor]::DarkGray)
            $linesWritten++
        }
    }

    Write-ConsoleLinePadded $sep ([ConsoleColor]::DarkCyan)
    $linesWritten++

    # Überzählige Zeilen der vorherigen Darstellung löschen
    if ($DashboardLines -gt $linesWritten) {
        for ($i = 0; $i -lt ($DashboardLines - $linesWritten); $i++) {
            Write-ConsoleLinePadded '' ([ConsoleColor]::Gray)
            $linesWritten++
        }
    }

    return $linesWritten
}

function Start-SfdlDownloads {
    param(
        $Connection,
        [System.Collections.IList]$Items,
        [int]$MaxThreads,
        [bool]$Resume,
        [int]$MaxRetry,
        [int]$RetryWaitSeconds
    )

    $tracked = New-Object System.Collections.Generic.List[object]
    $queue = New-SfdlSafeQueue
    foreach ($item in ($Items | Where-Object { $_.Selected -and $_.Status -ne 'AlreadyDownloaded' })) {
        if ($Resume -and (Test-Path -LiteralPath $item.LocalFile)) {
            try {
                $existing = (Get-Item -LiteralPath $item.LocalFile).Length
                if ($existing -gt 0) { $item.SizeDownloaded = [long]$existing }
            }
            catch { }
        }
        $tracked.Add($item)
        Add-SfdlSafeQueueItem -Queue $queue -Item $item
    }

    $total = $tracked.Count
    if ($total -eq 0) {
        Write-SfdlLog WARN 'Keine Dateien zum Download ausgewählt.'
        return $true
    }

    $baselineDownloaded = 0L
    $totalBytes = 0L
    foreach ($item in $tracked) {
        $baselineDownloaded += [long]$item.SizeDownloaded
        $totalBytes += [long]$item.FileSize
    }

    Write-SfdlLog INFO ("Starte Download von {0} Datei(en) ({1}) mit {2} Thread(s)..." -f `
        $total, (Format-ByteSize $totalBytes), $MaxThreads)
    Write-SfdlLog INFO 'Abbruch mit STRG+C stoppt alle Downloads.'

    # Session-Abbruch zurücksetzen
    $script:SfdlAborting = $false
    try {
        $script:SfdlCancelEvent.Reset()
    }
    catch {
        $script:SfdlCancelEvent = New-Object System.Threading.ManualResetEventSlim $false
    }
    if ($null -ne $global:SfdlSessionState) {
        $global:SfdlSessionState['CancelEvent'] = $script:SfdlCancelEvent
        $global:SfdlSessionState['ActiveRequests'] = $script:SfdlActiveRequests
        $global:SfdlSessionState['WorkerPipes'] = $script:SfdlWorkerPipes
    }
    try { [SfdlNativeCancel]::SetGate($script:SfdlCancelEvent) } catch { }
    try { $script:SfdlActiveRequests.Clear() } catch { }
    try { $script:SfdlWorkerPipes.Clear() } catch { }

    $cancelEvent = $script:SfdlCancelEvent
    $activeRequests = $script:SfdlActiveRequests
    $startedAt = Get-Date
    $wasCancelled = $false

    $stats = [hashtable]::Synchronized(@{
        Completed = 0
        Failed    = 0
        Stopped   = 0
        Lock      = (New-Object object)
        LogQueue  = New-SfdlSafeQueue
    })
    $connClone = $Connection

    $helperSource = @"
function Format-ByteSize {
    param([long]`$Bytes)
    if (`$Bytes -ge 1GB) { return '{0:N2} GB' -f (`$Bytes / 1GB) }
    if (`$Bytes -ge 1MB) { return '{0:N2} MB' -f (`$Bytes / 1MB) }
    if (`$Bytes -ge 1KB) { return '{0:N2} KB' -f (`$Bytes / 1KB) }
    return "`$Bytes B"
}
function Format-Speed {
    param([double]`$BytesPerSecond)
    if (`$BytesPerSecond -ge 1GB) { return '{0:N2} GB/s' -f (`$BytesPerSecond / 1GB) }
    if (`$BytesPerSecond -ge 1MB) { return '{0:N2} MB/s' -f (`$BytesPerSecond / 1MB) }
    if (`$BytesPerSecond -ge 1KB) { return '{0:N2} KB/s' -f (`$BytesPerSecond / 1KB) }
    return ('{0:N0} B/s' -f [Math]::Max(0, `$BytesPerSecond))
}
function Get-FtpUri {
    param(`$Connection, [string]`$RemotePath = '/')
    `$hostPart = [string]`$Connection.Host
    if (`$hostPart -match ':' -and -not `$hostPart.StartsWith('[')) { `$hostPart = "[`$hostPart]" }
    `$port = `$Connection.Port
    `$path = (`$RemotePath -replace '\\', '/')
    if ([string]::IsNullOrWhiteSpace(`$path)) { `$path = '/' }
    if (-not `$path.StartsWith('/')) { `$path = '/' + `$path }
    `$encodedSegments = foreach (`$seg in (`$path -split '/')) {
        if (`$seg -eq '') { '' } else { [Uri]::EscapeDataString(`$seg) }
    }
    `$encodedPath = (`$encodedSegments -join '/')
    if (-not `$encodedPath.StartsWith('/')) { `$encodedPath = '/' + `$encodedPath }
    return [Uri]("ftp://`${hostPart}:`${port}`${encodedPath}")
}
function Set-FtpRequestCredentials {
    param(`$Request, `$Connection)
    `$hasUser = -not [string]::IsNullOrWhiteSpace(`$Connection.Username)
    if (`$Connection.AuthRequired -or `$hasUser) {
        `$user = if (`$hasUser) { `$Connection.Username } else { 'anonymous' }
        `$pass = if ([string]::IsNullOrWhiteSpace(`$Connection.Password)) { 'sfdl@anon.net' } else { `$Connection.Password }
        `$Request.Credentials = New-Object System.Net.NetworkCredential(`$user, `$pass)
    } else {
        `$Request.Credentials = New-Object System.Net.NetworkCredential('anonymous', 'sfdl@anon.net')
    }
}
function New-FtpRequest {
    param(`$Connection, [string]`$RemotePath, [string]`$Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile, [long]`$RestartOffset = 0)
    `$uri = Get-FtpUri -Connection `$Connection -RemotePath `$RemotePath
    `$req = [System.Net.FtpWebRequest]::Create(`$uri)
    `$req.Method = `$Method
    `$req.UseBinary = (`$Connection.DataType -ne 'ASCII')
    `$req.UsePassive = (`$Connection.DataConnectionType -ne 'Active')
    `$req.KeepAlive = `$false
    `$req.Timeout = [Math]::Max(10000, `$Connection.ConnectTimeout * 1000)
    `$req.ReadWriteTimeout = [Math]::Max(30000, `$Connection.CommandTimeout * 1000)
    if (`$Connection.SSLProtocol -and `$Connection.SSLProtocol -ne 'None') { `$req.EnableSsl = `$true }
    Set-FtpRequestCredentials -Request `$req -Connection `$Connection
    if (`$RestartOffset -gt 0) { `$req.ContentOffset = `$RestartOffset }
    return `$req
}
function Test-SfdlFileHash {
    param([string]`$FilePath, [string]`$HashType, [string]`$ExpectedHash)
    if ([string]::IsNullOrWhiteSpace(`$HashType) -or `$HashType -eq 'None') { return `$true }
    if ([string]::IsNullOrWhiteSpace(`$ExpectedHash)) { return `$true }
    if (-not (Test-Path -LiteralPath `$FilePath)) { return `$false }
    `$algoName = switch -Regex (`$HashType) {
        '^(?i)MD5$' { 'MD5' }; '^(?i)SHA1$' { 'SHA1' }; '^(?i)SHA256$' { 'SHA256' }
        '^(?i)SHA384$' { 'SHA384' }; '^(?i)SHA512$' { 'SHA512' }; default { `$null }
    }
    if (-not `$algoName) { return `$true }
    `$algo = [System.Security.Cryptography.HashAlgorithm]::Create(`$algoName)
    if (-not `$algo) { return `$true }
    try {
        `$fs = [IO.File]::OpenRead(`$FilePath)
        try { `$hashBytes = `$algo.ComputeHash(`$fs) } finally { `$fs.Dispose() }
        `$actual = ([BitConverter]::ToString(`$hashBytes) -replace '-', '').ToLowerInvariant()
        `$expected = (`$ExpectedHash -replace '[\s-]', '').ToLowerInvariant()
        return (`$actual -eq `$expected)
    } finally { `$algo.Dispose() }
}
function Invoke-FtpFileDownload {
    param(
        `$Connection,
        `$Item,
        [bool]`$Resume = `$true,
        [int]`$BufferSize = 8192,
        `$CancelEvent = `$null,
        `$ActiveRequests = `$null
    )
    if (`$CancelEvent -and `$CancelEvent.IsSet) {
        `$Item.Status = 'Stopped'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
        throw 'DownloadCancelled'
    }
    `$remotePath = `$Item.FullPath
    if ([string]::IsNullOrWhiteSpace(`$remotePath)) { throw "Kein FullPath für `$(`$Item.FileName)" }
    `$localDir = Split-Path -Parent `$Item.LocalFile
    if (-not (Test-Path -LiteralPath `$localDir)) { New-Item -ItemType Directory -Path `$localDir -Force | Out-Null }
    `$restart = 0L
    `$fileMode = [IO.FileMode]::Create
    if (`$Resume -and (Test-Path -LiteralPath `$Item.LocalFile)) {
        `$existing = (Get-Item -LiteralPath `$Item.LocalFile).Length
        if (`$Item.FileSize -gt 0 -and `$existing -eq `$Item.FileSize) {
            if (-not (Test-SfdlFileHash -FilePath `$Item.LocalFile -HashType `$Item.HashType -ExpectedHash `$Item.FileHash)) {
                Remove-Item -LiteralPath `$Item.LocalFile -Force -ErrorAction SilentlyContinue
                `$restart = 0L; `$fileMode = [IO.FileMode]::Create; `$Item.SizeDownloaded = 0
            } else {
                `$Item.Status = 'Completed'; `$Item.SizeDownloaded = `$Item.FileSize; `$Item.Progress = 100
                `$Item.BytesPerSecond = 0; `$Item.Speed = ''; return `$Item
            }
        }
        elseif (`$Item.FileSize -gt 0 -and `$existing -gt `$Item.FileSize) {
            `$restart = 0L; `$fileMode = [IO.FileMode]::Create; `$Item.SizeDownloaded = 0
        }
        elseif (`$Item.FileSize -gt 0 -and `$existing -gt 0 -and `$existing -lt `$Item.FileSize) {
            `$restart = `$existing; `$fileMode = [IO.FileMode]::Append; `$Item.SizeDownloaded = `$existing
        }
        elseif (`$Item.FileSize -eq 0 -and `$existing -gt 0) {
            `$restart = 0L; `$fileMode = [IO.FileMode]::Create; `$Item.SizeDownloaded = 0
        }
    }
    `$Item.Status = 'Running'
    `$start = Get-Date
    `$requestId = [guid]::NewGuid().ToString()
    `$req = New-FtpRequest -Connection `$Connection -RemotePath `$remotePath -Method ([System.Net.WebRequestMethods+Ftp]::DownloadFile) -RestartOffset `$restart
    if (`$ActiveRequests) { `$ActiveRequests[`$requestId] = `$req }
    `$response = `$null; `$remoteStream = `$null; `$localStream = `$null
    try {
        `$response = `$req.GetResponse()
        `$remoteStream = `$response.GetResponseStream()
        `$localStream = New-Object IO.FileStream(`$Item.LocalFile, `$fileMode, [IO.FileAccess]::Write, [IO.FileShare]::None, `$BufferSize, `$false)
        `$buffer = New-Object byte[] `$BufferSize
        while (`$true) {
            if (`$CancelEvent -and `$CancelEvent.IsSet) {
                try { `$req.Abort() } catch { }
                `$Item.Status = 'Stopped'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
                throw 'DownloadCancelled'
            }
            `$read = `$remoteStream.Read(`$buffer, 0, `$buffer.Length)
            if (`$read -le 0) { break }
            `$localStream.Write(`$buffer, 0, `$read)
            `$Item.SizeDownloaded += `$read
            `$elapsed = ((Get-Date) - `$start).TotalSeconds
            `$sessionBytes = [Math]::Max([long]0, `$Item.SizeDownloaded - `$restart)
            `$bps = if (`$elapsed -gt 0) { `$sessionBytes / `$elapsed } else { 0 }
            `$Item.BytesPerSecond = `$bps
            `$Item.Speed = Format-Speed `$bps
            if (`$Item.FileSize -gt 0) { `$Item.Progress = [Math]::Round(100.0 * `$Item.SizeDownloaded / `$Item.FileSize, 1) }
        }
        if (`$CancelEvent -and `$CancelEvent.IsSet) {
            `$Item.Status = 'Stopped'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
            throw 'DownloadCancelled'
        }
        if (`$localStream) { `$localStream.Flush(); `$localStream.Dispose(); `$localStream = `$null }
        if (`$Item.FileSize -gt 0 -and `$Item.SizeDownloaded -ne `$Item.FileSize) {
            `$Item.Status = 'Failed'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
            throw ("Größenmismatch: erwartet {0}, erhalten {1}" -f `$Item.FileSize, `$Item.SizeDownloaded)
        }
        if (-not (Test-SfdlFileHash -FilePath `$Item.LocalFile -HashType `$Item.HashType -ExpectedHash `$Item.FileHash)) {
            `$Item.Status = 'Failed'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
            throw ("Hash-Prüfung fehlgeschlagen ({0})" -f `$Item.HashType)
        }
        `$Item.Status = 'Completed'; `$Item.Progress = 100; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
    } catch {
        if ((`$CancelEvent -and `$CancelEvent.IsSet) -or `$_.Exception.Message -eq 'DownloadCancelled') {
            `$Item.Status = 'Stopped'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''
            throw 'DownloadCancelled'
        }
        `$Item.Status = 'Failed'; `$Item.BytesPerSecond = 0; `$Item.Speed = ''; throw
    } finally {
        if (`$ActiveRequests -and `$ActiveRequests.ContainsKey(`$requestId)) {
            `$ActiveRequests.Remove(`$requestId)
        }
        if (`$localStream) { `$localStream.Dispose() }
        if (`$remoteStream) { `$remoteStream.Dispose() }
        if (`$response) { `$response.Close() }
    }
    return `$Item
}
"@

    $scriptBlock = {
        param($Queue, $Connection, $Resume, $MaxRetry, $RetryWait, $Stats, $Helpers, $CancelEvent, $ActiveRequests)

        . ([scriptblock]::Create($Helpers))

        function Get-SfdlSafeQueueItem {
            param($Queue)
            $lockTaken = $false
            try {
                [System.Threading.Monitor]::Enter($Queue.Sync, [ref]$lockTaken)
                if ($Queue.Items.Count -eq 0) { return $null }
                $value = $Queue.Items[0]
                $Queue.Items.RemoveAt(0)
                return $value
            }
            finally {
                if ($lockTaken) { [System.Threading.Monitor]::Exit($Queue.Sync) }
            }
        }
        function Add-SfdlSafeQueueItem {
            param($Queue, $Item)
            $lockTaken = $false
            try {
                [System.Threading.Monitor]::Enter($Queue.Sync, [ref]$lockTaken)
                [void]$Queue.Items.Add($Item)
            }
            finally {
                if ($lockTaken) { [System.Threading.Monitor]::Exit($Queue.Sync) }
            }
        }

        while (-not $CancelEvent.IsSet) {
            $item = Get-SfdlSafeQueueItem -Queue $Queue
            if ($null -eq $item) { break }
            if ($CancelEvent.IsSet) {
                $item.Status = 'Stopped'
                $item.BytesPerSecond = 0
                $item.Speed = ''
                [System.Threading.Monitor]::Enter($Stats.Lock)
                try { $Stats.Stopped++ } finally { [System.Threading.Monitor]::Exit($Stats.Lock) }
                break
            }

            $ok = $false
            $stopped = $false
            $attempt = 0
            # MaxRetry = Anzahl Wiederholungen nach dem ersten Versuch (gesamt: MaxRetry + 1)
            while (-not $ok -and -not $stopped -and $attempt -le $MaxRetry) {
                if ($CancelEvent.IsSet) {
                    $stopped = $true
                    $item.Status = 'Stopped'
                    $item.BytesPerSecond = 0
                    $item.Speed = ''
                    break
                }
                try {
                    if ($attempt -gt 0) {
                        # Abbruch auch während Retry-Wartezeit prüfen
                        if ($CancelEvent.Wait($RetryWait * 1000)) {
                            $stopped = $true
                            $item.Status = 'Stopped'
                            $item.BytesPerSecond = 0
                            $item.Speed = ''
                            break
                        }
                    }
                    Invoke-FtpFileDownload -Connection $Connection -Item $item -Resume:$Resume `
                        -CancelEvent $CancelEvent -ActiveRequests $ActiveRequests | Out-Null
                    $ok = ($item.Status -eq 'Completed')
                    if ($item.Status -eq 'Stopped') { $stopped = $true }
                }
                catch {
                    if ($_.Exception.Message -eq 'DownloadCancelled' -or $CancelEvent.IsSet) {
                        $stopped = $true
                        $item.Status = 'Stopped'
                        $item.BytesPerSecond = 0
                        $item.Speed = ''
                        break
                    }
                    $item.Status = 'Failed'
                    $item.BytesPerSecond = 0
                    $item.Speed = ''
                    $item.RetryCount = $attempt
                    if ($attempt -ge $MaxRetry) {
                        Add-SfdlSafeQueueItem -Queue $Stats.LogQueue -Item ("[ERR] $($item.FileName): $($_.Exception.Message)")
                    }
                }
                $attempt++
            }

            [System.Threading.Monitor]::Enter($Stats.Lock)
            try {
                if ($ok) { $Stats.Completed++ }
                elseif ($stopped) { $Stats.Stopped++ }
                else { $Stats.Failed++ }
            }
            finally { [System.Threading.Monitor]::Exit($Stats.Lock) }
        }

        # Restliche Queue-Einträge als gestoppt markieren, wenn abgebrochen
        if ($CancelEvent.IsSet) {
            while ($true) {
                $left = Get-SfdlSafeQueueItem -Queue $Queue
                if ($null -eq $left) { break }
                $left.Status = 'Stopped'
                $left.BytesPerSecond = 0
                $left.Speed = ''
                [System.Threading.Monitor]::Enter($Stats.Lock)
                try { $Stats.Stopped++ } finally { [System.Threading.Monitor]::Exit($Stats.Lock) }
            }
        }
    }

    Register-SfdlCancelHandler

    $pool = $null
    $workers = @()

    try {
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
        $pool.ApartmentState = 'MTA'
        $pool.Open()
        $script:SfdlRunspacePool = $pool
        if ($null -ne $global:SfdlSessionState) {
            $global:SfdlSessionState['RunspacePool'] = $pool
        }

        for ($i = 0; $i -lt $MaxThreads; $i++) {
            $ps = [powershell]::Create().AddScript($scriptBlock).
                AddArgument($queue).AddArgument($connClone).
                AddArgument($Resume).AddArgument($MaxRetry).AddArgument($RetryWaitSeconds).
                AddArgument($stats).AddArgument($helperSource).
                AddArgument($cancelEvent).AddArgument($activeRequests)
            $ps.RunspacePool = $pool
            $workerId = [guid]::NewGuid().ToString()
            $script:SfdlWorkerPipes[$workerId] = $ps
            $workers += [pscustomobject]@{ Id = $workerId; Pipe = $ps; Handle = $ps.BeginInvoke() }
        }

        $dashboardLines = 0
        Write-SfdlHostLine -Text ''

        while ($true) {
            if ($cancelEvent.IsSet) {
                $wasCancelled = $true
                Request-SfdlCancel -Reason 'STRG+C'
                break
            }

            $allDone = $true
            foreach ($w in $workers) {
                if (-not $w.Handle.IsCompleted) { $allDone = $false; break }
            }

            while ($true) {
                $logLine = Get-SfdlSafeQueueItem -Queue $stats.LogQueue
                if ($null -eq $logLine) { break }
                if ($dashboardLines -gt 0) {
                    try {
                        $pos = $Host.UI.RawUI.CursorPosition
                        $newTop = [Math]::Max(0, $pos.Y - $dashboardLines)
                        $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 0, $newTop
                    }
                    catch { }
                    for ($c = 0; $c -lt $dashboardLines; $c++) { Write-ConsoleLinePadded '' }
                    $dashboardLines = 0
                }
                Write-SfdlHostLine -Text $logLine -ForegroundColor ([ConsoleColor]::Red)
            }

            try {
                $dashboardLines = Write-SfdlDownloadProgress -TrackedItems $tracked -StartedAt $startedAt `
                    -TotalFiles $total -CompletedFiles $stats.Completed -FailedFiles $stats.Failed `
                    -BaselineDownloaded $baselineDownloaded -DashboardLines $dashboardLines -Final:$allDone
            }
            catch [System.Management.Automation.PipelineStoppedException] {
                $wasCancelled = $true
                Request-SfdlCancel -Reason 'PipelineStopped'
                break
            }

            if ($allDone) { break }

            # Interruptible sleep: wacht bei Cancel sofort auf
            if ($cancelEvent.Wait(300)) {
                $wasCancelled = $true
                Request-SfdlCancel -Reason 'STRG+C'
                break
            }
        }
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        $wasCancelled = $true
        Request-SfdlCancel -Reason 'PipelineStopped'
    }
    catch {
        if ($cancelEvent.IsSet) {
            $wasCancelled = $true
        }
        else {
            throw
        }
    }
    finally {
        # Sofort Handler entfernen, damit STRG+C während Cleanup die Session nicht zerlegt
        Unregister-SfdlCancelHandler

        $prevEa = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        try {
            $wasCancelled = $wasCancelled -or $cancelEvent.IsSet
            if ($wasCancelled) {
                Request-SfdlCancel -Reason 'Cleanup'
            }

            foreach ($w in $workers) {
                if ($null -eq $w.Pipe) { continue }
                try {
                    if ($w.Handle -and -not $w.Handle.IsCompleted) {
                        $w.Pipe.Stop()
                    }
                }
                catch { }
            }

            # Kurz warten, damit Abort/Stop greifen (kein Busy-Spin auf gesetztem Event)
            $deadline = (Get-Date).AddSeconds(5)
            while ((Get-Date) -lt $deadline) {
                $busy = $false
                foreach ($w in $workers) {
                    if ($w.Handle -and -not $w.Handle.IsCompleted) { $busy = $true; break }
                }
                if (-not $busy) { break }
                Start-Sleep -Milliseconds 100
            }

            foreach ($w in $workers) {
                try {
                    # Nach Stop() kein EndInvoke - das hängt/crasht in PS 5.1 häufig.
                    # Stattdessen kurz auf Completion warten, dann Dispose.
                    if ($w.Handle -and -not $w.Handle.IsCompleted -and $w.Handle.AsyncWaitHandle) {
                        try { [void]$w.Handle.AsyncWaitHandle.WaitOne(500) } catch { }
                    }
                }
                catch { }
                finally {
                    try { if ($w.Pipe) { $w.Pipe.Dispose() } } catch { }
                    if ($w.Id -and $script:SfdlWorkerPipes.ContainsKey($w.Id)) {
                        try { $script:SfdlWorkerPipes.Remove($w.Id) } catch { }
                    }
                }
            }

            if ($null -ne $pool) {
                try { $pool.Close() } catch { }
                try { $pool.Dispose() } catch { }
            }
            $script:SfdlRunspacePool = $null
            if ($null -ne $global:SfdlSessionState) {
                $global:SfdlSessionState['RunspacePool'] = $null
            }
            try { $script:SfdlActiveRequests.Clear() } catch { }
            try { $script:SfdlWorkerPipes.Clear() } catch { }
        }
        finally {
            $ErrorActionPreference = $prevEa
        }
    }

    # Laufende Items auf Stopped setzen, falls Abbruch
    if ($wasCancelled) {
        foreach ($item in $tracked) {
            if ($item.Status -eq 'Running' -or $item.Status -eq 'Pending') {
                $item.Status = 'Stopped'
                $item.BytesPerSecond = 0
                $item.Speed = ''
            }
        }
    }

    Write-SfdlHostLine -Text ''
    $elapsedFinal = ConvertTo-Hms ((Get-Date) - $startedAt).TotalSeconds
    if ($wasCancelled) {
        Write-SfdlLog WARN ("Download abgebrochen nach {0}. Fertig: {1}, Gestoppt: {2}, Fehler: {3}" -f `
            $elapsedFinal, $stats.Completed, $stats.Stopped, $stats.Failed)
    }
    else {
        Write-SfdlLog OK ("Download fertig: {0} OK, {1} fehlgeschlagen, Dauer: {2}" -f `
            $stats.Completed, $stats.Failed, $elapsedFinal)
    }

    return (-not $wasCancelled)
}

# ---------------------------------------------------------------------------
# UnRAR
# ---------------------------------------------------------------------------
function Find-UnrarExecutable {
    param([string]$ExplicitPath)
    if ($ExplicitPath -and (Test-Path -LiteralPath $ExplicitPath)) { return (Resolve-Path $ExplicitPath).Path }

    $candidates = @(
        (Join-Path $PSScriptRoot 'bin\unrar.exe')
        (Join-Path $PSScriptRoot 'unrar.exe')
        'unrar.exe'
        'C:\Program Files\WinRAR\UnRAR.exe'
        'C:\Program Files (x86)\WinRAR\UnRAR.exe'
    )
    foreach ($c in $candidates) {
        try {
            $cmd = Get-Command $c -ErrorAction SilentlyContinue
            if ($cmd) { return $cmd.Source }
            if (Test-Path -LiteralPath $c) { return $c }
        }
        catch { }
    }
    return $null
}

function Test-SfdlHasProperty {
    param(
        $Object,
        [Parameter(Mandatory)]
        [string]$Name
    )
    if ($null -eq $Object) { return $false }
    try {
        return ($Object.PSObject.Properties.Match($Name).Count -gt 0)
    }
    catch {
        return $false
    }
}

function Get-UnrarChains {
    param([System.Collections.IList]$Items)

    # Flattern / filtern: nur echte Archiv-Items mit FileName (StrictMode-sicher)
    $normalized = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }

        # Verschachtelte Listen/Arrays (PowerShell-Unrolling) eine Ebene auflösen
        $hasFileName = Test-SfdlHasProperty -Object $it -Name 'FileName'
        if (-not $hasFileName -and $it -is [System.Collections.IEnumerable] -and $it -isnot [string]) {
            foreach ($inner in $it) {
                if ($null -ne $inner -and (Test-SfdlHasProperty -Object $inner -Name 'FileName')) {
                    [void]$normalized.Add($inner)
                }
            }
            continue
        }

        if ($hasFileName) {
            [void]$normalized.Add($it)
        }
    }

    $chains = New-Object System.Collections.Generic.List[object]
    $rars = @($normalized | Where-Object {
        ([IO.Path]::GetExtension([string]$_.FileName)).Equals('.rar', [StringComparison]::OrdinalIgnoreCase)
    })

    foreach ($item in $rars) {
        if ($item.FileName -notmatch '\.part') {
            $base = [Regex]::Escape([IO.Path]::GetFileNameWithoutExtension($item.FileName))
            $pattern = "$base\.r[0-9]{1,2}"
            $members = @($normalized | Where-Object {
                $_.PackageName -eq $item.PackageName -and $_.FileName -match $pattern
            })
            $item.FirstUnRarFile = $true
            [void]$chains.Add([pscustomobject]@{
                Master  = $item
                Members = $members
                Type    = 'Rar'
            })
        }
        else {
            # part01.rar / part1.rar master
            if ($item.FileName -match '^((?!\.part(?!0*1\.rar$)\d+\.rar$).)*\.(?:rar|r?0*1)$') {
                $prefix = $item.FileName.Substring(0, $item.FileName.IndexOf('.part'))
                $pattern = [Regex]::Escape($prefix) + '\.part[0-9]{1,3}\.rar'
                $members = @($normalized | Where-Object {
                    $_.PackageName -eq $item.PackageName -and
                    $_.FileName -ne $item.FileName -and
                    $_.FileName -match $pattern -and
                    $_.FileName.StartsWith($prefix)
                })
                $item.FirstUnRarFile = $true
                [void]$chains.Add([pscustomobject]@{
                    Master  = $item
                    Members = $members
                    Type    = 'Rar'
                })
            }
        }
    }

    # Einzelne .zip-Dateien (keine .z01-Volumes, keine 7-Zip-Splits .zip.001)
    $zips = @($normalized | Where-Object {
        $fn = [string]$_.FileName
        $fn -notmatch '(?i)\.zip\.\d+$' -and
        ([IO.Path]::GetExtension($fn)).Equals('.zip', [StringComparison]::OrdinalIgnoreCase) -and
        $fn -notmatch '(?i)\.z\d{2}$'
    })
    foreach ($item in $zips) {
        $item.FirstUnRarFile = $true
        [void]$chains.Add([pscustomobject]@{
            Master  = $item
            Members = @()
            Type    = 'Zip'
        })
    }

    # 7-Zip Split-Volumes: name.zip.001, name.zip.002, ...
    $splitMasters = @($normalized | Where-Object {
        [string]$_.FileName -match '(?i)^.+\.zip\.0*1$'
    })
    foreach ($item in $splitMasters) {
        if ([string]$item.FileName -notmatch '(?i)^(?<base>.+\.zip)\.(?<num>\d+)$') { continue }
        $baseName = $Matches['base']
        $memberPattern = '(?i)^' + [Regex]::Escape($baseName) + '\.(\d+)$'
        $members = @($normalized | Where-Object {
            $_.PackageName -eq $item.PackageName -and
            $_.FileName -ne $item.FileName -and
            ([string]$_.FileName -match $memberPattern)
        })
        $item.FirstUnRarFile = $true
        [void]$chains.Add([pscustomobject]@{
            Master  = $item
            Members = $members
            Type    = 'ZipSplit'
        })
    }

    return ,$chains
}

function Test-UnrarChainComplete {
    param($Chain)
    $all = @($Chain.Master) + @($Chain.Members)
    foreach ($f in $all) {
        if (-not (Test-Path -LiteralPath $f.LocalFile)) { return $false }
        if ($f.FileSize -gt 0) {
            $len = (Get-Item -LiteralPath $f.LocalFile).Length
            if ($len -ne $f.FileSize) { return $false }
        }
        if ($f.Status -notin @('Completed', 'AlreadyDownloaded')) { return $false }
    }
    return $true
}

function Invoke-SfdlExternalProcess {
    param(
        [string]$FileName,
        [string]$Arguments,
        [Text.Encoding]$OutputEncoding = $null
    )

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $FileName
    $pinfo.Arguments = $Arguments
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    if ($OutputEncoding) {
        $pinfo.StandardOutputEncoding = $OutputEncoding
        # StandardErrorEncoding erst ab .NET Core - unter Framework überspringen
        $errEncProp = $pinfo.GetType().GetProperty('StandardErrorEncoding')
        if ($errEncProp -and $errEncProp.CanWrite) {
            $errEncProp.SetValue($pinfo, $OutputEncoding, $null)
        }
    }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    try {
        $null = $proc.Start()

        # Asynchron lesen, um Deadlocks bei vollen Puffern zu vermeiden
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        $stdout = $outTask.Result
        $stderr = $errTask.Result

        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            StdOut   = $stdout
            StdErr   = $stderr
            Combined = "$stdout`n$stderr"
        }
    }
    finally {
        try { $proc.Dispose() } catch { }
    }
}

function Escape-SfdlProcessArgument {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    # Windows-CommandLine-Quoting: " und \ escapen
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return "`"$escaped`""
}

function Test-SfdlArchiveEntriesSafe {
    param(
        [string[]]$EntryNames,
        [string]$ExtractDir
    )
    foreach ($name in $EntryNames) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $entry = $name.Trim()
        if (-not (Test-SfdlExtractPathSafe -ExtractDir $ExtractDir -EntryName $entry)) {
            Write-SfdlLog WARN "Archiv-Eintrag außerhalb Zielverzeichnis: $entry"
            return $false
        }
    }
    return $true
}

function Get-UnrarArchiveEntryNames {
    param(
        [string]$UnrarExe,
        [string]$ArchivePath,
        [string]$Password
    )
    $archiveArg = Escape-SfdlProcessArgument $ArchivePath
    if ([string]::IsNullOrWhiteSpace($Password)) {
        $pwdArg = '-p-'
    }
    else {
        $pwdArg = '-p' + (Escape-SfdlProcessArgument $Password)
    }
    $result = Invoke-SfdlExternalProcess -FileName $UnrarExe -Arguments "lb -y $pwdArg $archiveArg" `
        -OutputEncoding ([Text.Encoding]::UTF8)
    if ($result.ExitCode -notin @(0, 1)) {
        return $null
    }
    $names = @(
        $result.StdOut -split "`r?`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
    return ,$names
}

function Get-SevenZipArchiveEntryNames {
    param(
        [string]$SevenZipExe,
        [string]$ArchivePath,
        [string]$Password
    )
    $archArg = Escape-SfdlProcessArgument $ArchivePath
    if ([string]::IsNullOrWhiteSpace($Password)) {
        $pwdArg = '-p-'
    }
    else {
        $pwdArg = '-p' + (Escape-SfdlProcessArgument $Password)
    }
    $result = Invoke-SfdlExternalProcess -FileName $SevenZipExe -Arguments "l -slt -y $pwdArg $archArg"
    if ($result.ExitCode -ne 0) {
        return $null
    }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($result.StdOut -split "`r?`n")) {
        if ($line -match '^(?i)Path\s*=\s*(.+)$') {
            $p = $Matches[1].Trim()
            # Erste Path= Zeile ist oft das Archiv selbst
            if ($p -and -not $p.Equals($ArchivePath, [StringComparison]::OrdinalIgnoreCase) -and
                -not ([IO.Path]::GetFileName($ArchivePath)).Equals($p, [StringComparison]::OrdinalIgnoreCase)) {
                $names.Add($p)
            }
        }
    }
    return ,@($names)
}

function Invoke-UnrarExtract {
    param(
        [string]$UnrarExe,
        [string]$ArchivePath,
        [string]$ExtractDir,
        [string]$Password
    )

    $entries = Get-UnrarArchiveEntryNames -UnrarExe $UnrarExe -ArchivePath $ArchivePath -Password $Password
    if ($null -eq $entries) {
        Write-SfdlLog ERROR "UnRAR-Listing fehlgeschlagen: $(Split-Path -Leaf $ArchivePath)"
        return $false
    }
    if (-not (Test-SfdlArchiveEntriesSafe -EntryNames $entries -ExtractDir $ExtractDir)) {
        Write-SfdlLog ERROR "UnRAR abgebrochen (unsichere Pfade): $(Split-Path -Leaf $ArchivePath)"
        return $false
    }

    $archiveArg = Escape-SfdlProcessArgument $ArchivePath
    # Trailing separator: sonst kann UnRAR den letzten Pfadteil als Namenspräfix werten
    $extractTarget = $ExtractDir.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $dirArg = Escape-SfdlProcessArgument $extractTarget
    if ([string]::IsNullOrWhiteSpace($Password)) {
        $pwdArg = '-p-'
    }
    else {
        # UnRAR: -p"password"
        $pwdArg = '-p' + (Escape-SfdlProcessArgument $Password)
    }

    $argLine = "x -o- -y $pwdArg $archiveArg $dirArg"
    $result = Invoke-SfdlExternalProcess -FileName $UnrarExe -Arguments $argLine -OutputEncoding ([Text.Encoding]::UTF8)
    $combined = $result.Combined

    # ExitCode 0 = Erfolg; UnRAR 1 = Warnung (oft OK)
    if ($result.ExitCode -eq 0 -or $result.ExitCode -eq 1) {
        if ($combined -match '(?i)Total errors:\s*([1-9]\d*)') { return $false }
        return $true
    }
    if ($combined -match '(?i)No files to extract') { return $true }
    Write-SfdlLog ERROR "UnRAR-Ausgabe (Exit $($result.ExitCode)):`n$combined"
    return $false
}

function Find-SevenZipExecutable {
    $candidates = @(
        (Join-Path $PSScriptRoot '7za.exe')
        (Join-Path $PSScriptRoot '7z.exe')
        (Join-Path $PSScriptRoot 'bin\7za.exe')
        (Join-Path $PSScriptRoot 'bin\7z.exe')
        '7za.exe'
        '7z.exe'
        'C:\Program Files\7-Zip\7z.exe'
        'C:\Program Files (x86)\7-Zip\7z.exe'
    )
    foreach ($c in $candidates) {
        try {
            if (Test-Path -LiteralPath $c) {
                return (Resolve-Path -LiteralPath $c).Path
            }
            $cmd = Get-Command $c -ErrorAction SilentlyContinue
            if ($cmd) { return $cmd.Source }
        }
        catch { }
    }
    return $null
}

function Invoke-SevenZipExtract {
    param(
        [string]$ArchivePath,
        [string]$ExtractDir,
        [string]$Password = ''
    )

    $sevenZip = Find-SevenZipExecutable
    if (-not $sevenZip) {
        Write-SfdlLog WARN "7za/7z nicht gefunden - übersprungen: $(Split-Path -Leaf $ArchivePath)"
        return $false
    }

    if (-not (Test-Path -LiteralPath $ExtractDir)) {
        New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($Password)) {
        $pwdArg = '-p-'
    }
    else {
        $pwdArg = '-p' + (Escape-SfdlProcessArgument $Password)
    }

    $entries = Get-SevenZipArchiveEntryNames -SevenZipExe $sevenZip -ArchivePath $ArchivePath -Password $Password
    if ($null -eq $entries) {
        Write-SfdlLog DEBUG "7-Zip Listing fehlgeschlagen: $(Split-Path -Leaf $ArchivePath)"
        return $false
    }
    if (-not (Test-SfdlArchiveEntriesSafe -EntryNames $entries -ExtractDir $ExtractDir)) {
        Write-SfdlLog ERROR "7-Zip abgebrochen (unsichere Pfade): $(Split-Path -Leaf $ArchivePath)"
        return $false
    }

    $outArg = '-o' + (Escape-SfdlProcessArgument $ExtractDir)
    $archArg = Escape-SfdlProcessArgument $ArchivePath
    $argLine = "x -y -bsp0 -bse1 $pwdArg $outArg $archArg"
    $result = Invoke-SfdlExternalProcess -FileName $sevenZip -Arguments $argLine

    # 0 = OK, 1 = Warnung (oft trotzdem erfolgreich)
    if ($result.ExitCode -eq 0 -or $result.ExitCode -eq 1) {
        return $true
    }

    Write-SfdlLog DEBUG "7-Zip Fehler (Exit $($result.ExitCode)): $($result.Combined)"
    return $false
}

function Test-SfdlExtractPathSafe {
    param(
        [string]$ExtractDir,
        [string]$EntryName
    )
    if ([string]::IsNullOrWhiteSpace($EntryName)) { return $false }
    # Absolute Pfade und Parent-Traversal ablehnen
    if ([IO.Path]::IsPathRooted($EntryName)) { return $false }
    if ($EntryName -match '(^|[\\/])\.\.([\\/]|$)') { return $false }

    $extractFull = [IO.Path]::GetFullPath($ExtractDir).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $targetFull = [IO.Path]::GetFullPath((Join-Path $ExtractDir $EntryName))
    return $targetFull.StartsWith($extractFull, [StringComparison]::OrdinalIgnoreCase) -or
           $targetFull.TrimEnd('\', '/').Equals($extractFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-ZipExtract {
    param(
        [string]$ArchivePath,
        [string]$ExtractDir,
        [string]$Password = '',
        [switch]$ForceSevenZip
    )

    if (-not (Test-Path -LiteralPath $ExtractDir)) {
        New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null
    }

    $fileName = Split-Path -Leaf $ArchivePath
    $isSplitZip = $fileName -match '(?i)\.zip\.\d+$'

    # Mehrteilige 7-Zip-Volumes (.zip.001) und Passwort-ZIPs über 7za
    if ($ForceSevenZip -or $isSplitZip -or -not [string]::IsNullOrWhiteSpace($Password)) {
        return (Invoke-SevenZipExtract -ArchivePath $ArchivePath -ExtractDir $ExtractDir -Password $Password)
    }

    # Ohne Passwort: Einträge einzeln und pfadsicher extrahieren (Zip-Slip-Schutz)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        try {
            foreach ($entry in $zip.Entries) {
                if (-not (Test-SfdlExtractPathSafe -ExtractDir $ExtractDir -EntryName $entry.FullName)) {
                    Write-SfdlLog WARN "ZIP-Eintrag außerhalb Zielverzeichnis übersprungen: $($entry.FullName)"
                    continue
                }
                $target = Join-Path $ExtractDir $entry.FullName
                $targetDir = Split-Path -Parent $target
                if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                    if (-not (Test-Path -LiteralPath $target)) {
                        New-Item -ItemType Directory -Path $target.TrimEnd('\', '/') -Force | Out-Null
                    }
                    continue
                }
                if ($targetDir -and -not (Test-Path -LiteralPath $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
            }
        }
        finally {
            $zip.Dispose()
        }
        return $true
    }
    catch {
        # Fallback: ggf. dennoch mit 7za versuchen
        Write-SfdlLog DEBUG "ZIP (.NET) fehlgeschlagen, versuche 7za: $($_.Exception.Message)"
        return (Invoke-SevenZipExtract -ArchivePath $ArchivePath -ExtractDir $ExtractDir -Password $Password)
    }
}

function Remove-SfdlArchiveFiles {
    param([object[]]$Files)

    foreach ($file in $Files) {
        try {
            if (-not $file.LocalFile -or -not (Test-Path -LiteralPath $file.LocalFile)) { continue }
            $removed = $false
            foreach ($attempt in 1..5) {
                try {
                    Remove-Item -LiteralPath $file.LocalFile -Force -ErrorAction Stop
                    $removed = $true
                    break
                }
                catch {
                    Start-Sleep -Milliseconds (150 * $attempt)
                }
            }
            if ($removed) {
                Write-SfdlLog INFO "Archiv gelöscht: $($file.FileName)"
            }
            else {
                Write-SfdlLog WARN "Archiv konnte nicht gelöscht werden: $($file.FileName)"
            }
        }
        catch {
            Write-SfdlLog WARN "Archiv konnte nicht gelöscht werden ($($file.FileName)): $($_.Exception.Message)"
        }
    }
}

function Expand-SfdlArchiveChain {
    param(
        $Chain,
        [string]$UnrarExe,
        [System.Collections.IList]$Passwords
    )

    $extractDir = Split-Path -Parent $Chain.Master.LocalFile
    $name = $Chain.Master.FileName
    Write-SfdlLog INFO "Entpacke $name ($($Chain.Type)) ..."

    if ($Chain.Type -eq 'Zip' -or $Chain.Type -eq 'ZipSplit') {
        foreach ($pw in $Passwords) {
            $ok = Invoke-ZipExtract -ArchivePath $Chain.Master.LocalFile -ExtractDir $extractDir `
                -Password $pw -ForceSevenZip:($Chain.Type -eq 'ZipSplit')
            if ($ok) {
                Write-SfdlLog OK "Entpackt: $name"
                return $true
            }
            if ([string]::IsNullOrWhiteSpace($pw) -and $Passwords.Count -eq 1) { break }
        }
    }
    else {
        if (-not $UnrarExe) {
            Write-SfdlLog WARN "unrar.exe fehlt - übersprungen: $name"
            return $false
        }
        foreach ($pw in $Passwords) {
            if (Invoke-UnrarExtract -UnrarExe $UnrarExe -ArchivePath $Chain.Master.LocalFile `
                    -ExtractDir $extractDir -Password $pw) {
                Write-SfdlLog OK "Entpackt: $name"
                return $true
            }
        }
    }

    Write-SfdlLog ERROR "Entpacken fehlgeschlagen: $name"
    return $false
}

function Get-SfdlDiskArchiveItems {
    param([string[]]$RootDirs)

    $list = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    foreach ($root in @($RootDirs)) {
        $rootPath = [string]$root
        if ([string]::IsNullOrWhiteSpace($rootPath) -or -not (Test-Path -LiteralPath $rootPath)) { continue }

        $files = @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -ErrorAction SilentlyContinue)
        foreach ($file in $files) {
            if ($null -eq $file) { continue }
            $ext = [string]$file.Extension
            if ([string]::IsNullOrEmpty($ext)) { continue }

            $isArchive =
                $ext.Equals('.zip', [StringComparison]::OrdinalIgnoreCase) -or
                $ext.Equals('.rar', [StringComparison]::OrdinalIgnoreCase) -or
                ($ext -match '^\.r\d{1,2}$') -or
                ([string]$file.Name -match '(?i)\.zip\.\d+$')
            if (-not $isArchive) { continue }

            $full = [string]$file.FullName
            if ($seen.ContainsKey($full)) { continue }
            $seen[$full] = $true

            [void]$list.Add([pscustomobject]@{
                FileName       = [string]$file.Name
                LocalFile      = $full
                FileSize       = 0L
                Status         = 'Completed'
                PackageName    = [string]$file.DirectoryName
                SizeDownloaded = [long]$file.Length
                FirstUnRarFile = $false
                HashType       = 'None'
                FileHash       = ''
            })
        }
    }

    return ,$list
}

function Get-SfdlExtractScanRoots {
    param([System.Collections.IList]$Items)

    $roots = @{}
    foreach ($item in @($Items)) {
        if ($null -eq $item -or -not (Test-SfdlHasProperty -Object $item -Name 'LocalFile')) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$item.LocalFile)) { continue }
        $dir = [string](Split-Path -Parent $item.LocalFile)
        if (-not [string]::IsNullOrWhiteSpace($dir)) {
            $roots[$dir] = $true
        }
    }
    $result = New-Object System.Collections.ArrayList
    foreach ($k in $roots.Keys) {
        [void]$result.Add([string]$k)
    }
    return , @($result.ToArray())
}

function Start-SfdlUnrar {
    param(
        [System.Collections.IList]$Items,
        [string]$UnrarExe,
        [string]$Password,
        [string[]]$PasswordList,
        [switch]$DeleteAfterUnRar
    )

    $passwords = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Password)) { $passwords.Add($Password) }
    foreach ($p in $PasswordList) {
        if ($p -and $passwords -notcontains $p) { $passwords.Add($p) }
    }
    $passwords.Insert(0, '')

    $chains = Get-UnrarChains -Items $Items
    $rarChains = @($chains | Where-Object { (Test-SfdlHasProperty -Object $_ -Name 'Type') -and $_.Type -eq 'Rar' })
    $zipSplitChains = @($chains | Where-Object { (Test-SfdlHasProperty -Object $_ -Name 'Type') -and $_.Type -eq 'ZipSplit' })
    if ($rarChains.Count -gt 0 -and -not $UnrarExe) {
        Write-SfdlLog WARN 'unrar.exe nicht gefunden - RAR-Entpacken übersprungen (ZIP wird trotzdem versucht).'
    }
    if ($zipSplitChains.Count -gt 0 -and -not (Find-SevenZipExecutable)) {
        Write-SfdlLog WARN '7za.exe nicht gefunden - mehrteilige ZIP-Archive (.zip.001) werden übersprungen.'
    }

    if ($null -eq $chains -or $chains.Count -eq 0) {
        Write-SfdlLog INFO 'Keine RAR-/ZIP-Archive in den Downloads gefunden.'
    }
    else {
        foreach ($chain in $chains) {
            if (-not (Test-SfdlHasProperty -Object $chain -Name 'Master')) { continue }
            if (-not (Test-UnrarChainComplete -Chain $chain)) {
                Write-SfdlLog WARN "Archiv unvollständig: $($chain.Master.FileName)"
                continue
            }
            if (Expand-SfdlArchiveChain -Chain $chain -UnrarExe $UnrarExe -Passwords $passwords) {
                Remove-SfdlArchiveFiles -Files (@($chain.Master) + @($chain.Members))
            }
        }
    }

    # Verschachtelte Archive: nach dem Entpacken erneut scannen, entpacken, löschen
    $scanRoots = @()
    foreach ($r in @(Get-SfdlExtractScanRoots -Items $Items)) {
        $rootPath = [string]$r
        if (-not [string]::IsNullOrWhiteSpace($rootPath)) {
            $scanRoots += $rootPath
        }
    }
    if ($scanRoots.Count -eq 0) { return }

    $failed = @{}
    $maxRounds = 20

    for ($round = 1; $round -le $maxRounds; $round++) {
        $diskList = Get-SfdlDiskArchiveItems -RootDirs ([string[]]$scanRoots)
        if ($null -eq $diskList -or $diskList.Count -eq 0) { break }

        $allNested = Get-UnrarChains -Items $diskList
        $nestedChains = @()
        if ($null -ne $allNested) {
            foreach ($cand in $allNested) {
                if (-not (Test-SfdlHasProperty -Object $cand -Name 'Master')) { continue }
                $path = [string]$cand.Master.LocalFile
                if ([string]::IsNullOrWhiteSpace($path)) { continue }
                if ($failed.ContainsKey($path)) { continue }
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $nestedChains += $cand
            }
        }

        if ($nestedChains.Count -eq 0) { break }

        Write-SfdlLog INFO ("Verschachtelte Archive - Runde {0}: {1} Archiv(e)" -f $round, $nestedChains.Count)

        $progress = $false
        foreach ($chain in $nestedChains) {
            $masterPath = [string]$chain.Master.LocalFile
            if (-not (Test-Path -LiteralPath $masterPath)) { continue }

            if (-not (Test-UnrarChainComplete -Chain $chain)) {
                Write-SfdlLog WARN "Archiv unvollständig: $($chain.Master.FileName)"
                $failed[$masterPath] = $true
                continue
            }

            if (Expand-SfdlArchiveChain -Chain $chain -UnrarExe $UnrarExe -Passwords $passwords) {
                Remove-SfdlArchiveFiles -Files (@($chain.Master) + @($chain.Members))
                $progress = $true
            }
            else {
                $failed[$masterPath] = $true
            }
        }

        if (-not $progress) { break }
    }
}

# ---------------------------------------------------------------------------
# Speedreport
# ---------------------------------------------------------------------------
function Write-SfdlSpeedreport {
    param(
        $Container,
        [System.Collections.IList]$Items,
        [datetime]$Started,
        [datetime]$Stopped,
        [string]$SfdlFileName,
        [string]$LocalRoot
    )

    $downloaded = @($Items | Where-Object { $_.SizeDownloaded -gt 0 })
    if ($downloaded.Count -eq 0) {
        Write-SfdlLog INFO 'Kein Speedreport (nichts heruntergeladen).'
        return
    }

    $totalBytes = ($downloaded | Measure-Object -Property SizeDownloaded -Sum).Sum
    $seconds = [Math]::Max(1, ($Stopped - $Started).TotalSeconds)
    $sizeMb = [Math]::Round(($totalBytes / 1MB), 2)
    $speedKBs = [Math]::Round((($totalBytes / 1KB) / $seconds), 2)

    $report = $script:SpeedreportTemplate
    $report = $report.Replace('%%USERNAME%%', $env:USERNAME)
    $report = $report.Replace('%%CONNECTION%%', '')
    $report = $report.Replace('%%COMMENT%%', '')
    $report = $report.Replace('%%SPEED%%', "$speedKBs KB/s")
    $report = $report.Replace('%%SFDL_FILENAME%%', $SfdlFileName)
    $report = $report.Replace('%%SFDL_UPPER%%', $Container.Uploader)
    $report = $report.Replace('%%DLTIME%%', (ConvertTo-Hms $seconds))
    $report = $report.Replace('%%SFDL_SIZE%%', "$sizeMb MB")

    $path = Join-Path $LocalRoot 'speedreport.txt'
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [IO.File]::WriteAllText($path, $report, $utf8Bom)
    Write-SfdlLog OK "Speedreport: $path"
    Write-SfdlHostLine -Text $report -ForegroundColor ([ConsoleColor]::Gray)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Show-DownloadItemTable {
    param([System.Collections.IList]$Items)
    $Items | Select-Object PackageName, FileName,
        @{n='Size';e={ Format-ByteSize $_.FileSize }},
        Selected, Status, ExcludeReason, LocalFile |
        Format-Table -AutoSize | Out-String -Width ([Math]::Max(120, (Get-ConsoleLineWidth))) |
        ForEach-Object {
            foreach ($line in ($_ -split "`r?`n")) {
                Write-SfdlHostLine -Text $line -ForegroundColor ([ConsoleColor]::Gray)
            }
        }
}

try {
    Initialize-SfdlConsoleEncoding
    Test-SfdlScriptEncoding

    $sfdlPath = (Resolve-Path -LiteralPath $SfdlFile).Path
    Write-SfdlLog INFO "SFDL.PS PowerShell - $sfdlPath"
    Write-SfdlLog INFO "Zielverzeichnis: $DownloadDirectory"

    $container = Read-SfdlContainer -Path $sfdlPath

    if ($container.Encrypted) {
        Write-SfdlLog INFO 'Container ist verschlüsselt.'
        $pw = Resolve-SfdlPassword -Container $container -ProvidedPassword $Password
        Decrypt-SfdlContainer -Container $container -Password $pw
        Write-SfdlLog OK 'Container entschlüsselt.'
    }

    Write-SfdlLog INFO ("Host: {0}:{1}  User: {2}  Auth: {3}  SSL: {4}  Mode: {5}" -f `
        $container.Connection.Host,
        $container.Connection.Port,
        $(if ($container.Connection.Username) { $container.Connection.Username } else { '(anonymous)' }),
        $container.Connection.AuthRequired,
        $container.Connection.SSLProtocol,
        $container.Connection.DataConnectionType)

    Expand-SfdlBulkFolders -Container $container

    $displayName = if (-not [string]::IsNullOrWhiteSpace($container.Description)) {
        $container.Description
    }
    else {
        [IO.Path]::GetFileNameWithoutExtension($sfdlPath)
    }

    $localRoot = Join-Path $DownloadDirectory (Sanitize-FileName $displayName)

    $excludeMalicious = -not $IncludeMalicious.IsPresent
    $malicious = if ($excludeMalicious) { $script:DefaultMaliciousBlacklist } else { @() }
    $items = New-DownloadItemList -Container $container -LocalRoot $localRoot `
        -CreatePackageSubfolder:$PackageSubfolder `
        -UserBlacklist $Blacklist -MaliciousBlacklist $malicious `
        -ExcludeMalicious:$excludeMalicious

    $totalSize = 0L
    foreach ($it in $items) { $totalSize += [long]$it.FileSize }
    Write-SfdlLog INFO ("{0} Datei(en), Gesamtgröße {1}, Download-Root: {2}" -f `
        $items.Count, (Format-ByteSize $totalSize), $localRoot)

    Show-DownloadItemTable -Items $items

    if ($ListOnly) {
        Write-SfdlLog OK 'ListOnly - kein Download.'
        return
    }

    if (-not (Test-Path -LiteralPath $localRoot)) {
        New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    }

    $threads = if ($MaxThreads -gt 0) { $MaxThreads } else { [Math]::Max(1, $container.MaxDownloadThreads) }
    $resume = -not $Overwrite.IsPresent

    if (-not (Test-FtpPort -HostName $container.Connection.Host -Port $container.Connection.Port)) {
        throw "FTP-Port $($container.Connection.Host):$($container.Connection.Port) nicht erreichbar."
    }

    $started = Get-Date
    $downloadOk = Start-SfdlDownloads -Connection $container.Connection -Items $items `
        -MaxThreads $threads -Resume:$resume -MaxRetry $MaxRetry -RetryWaitSeconds $RetryWaitSeconds
    $stopped = Get-Date

    if (-not $downloadOk) {
        $stoppedCount = @($items | Where-Object { $_.Status -eq 'Stopped' }).Count
        Write-SfdlLog WARN ("Download abgebrochen ({0} Datei(en) gestoppt). Session bleibt aktiv." -f $stoppedCount)
        Complete-SfdlScript -ExitCode 130
        return
    }

    if (-not $SkipUnrar) {
        $unrar = Find-UnrarExecutable -ExplicitPath $UnrarPath
        Start-SfdlUnrar -Items $items -UnrarExe $unrar -Password $UnrarPassword `
            -PasswordList $UnrarPasswordList -DeleteAfterUnRar:$DeleteAfterUnRar
    }

    Write-SfdlSpeedreport -Container $container -Items $items -Started $started -Stopped $stopped `
        -SfdlFileName ([IO.Path]::GetFileName($sfdlPath)) -LocalRoot $localRoot

    $okCount = @($items | Where-Object { $_.Status -in @('Completed', 'AlreadyDownloaded') }).Count
    $failCount = @($items | Where-Object { $_.Status -eq 'Failed' }).Count

    # SFDL nach erfolgreichem Download immer entfernen
    if ($failCount -eq 0 -and $okCount -gt 0) {
        try {
            Remove-Item -LiteralPath $sfdlPath -Force -ErrorAction Stop
            Write-SfdlLog INFO 'SFDL-Datei gelöscht.'
        }
        catch {
            Write-SfdlLog WARN ("SFDL-Datei konnte nicht gelöscht werden: {0}" -f $_.Exception.Message)
        }
    }
    elseif ($okCount -eq 0) {
        Write-SfdlLog WARN 'SFDL-Datei nicht gelöscht (keine erfolgreich verarbeiteten Dateien).'
    }
    else {
        Write-SfdlLog WARN ("SFDL-Datei nicht gelöscht ({0} fehlgeschlagene Datei(en))." -f $failCount)
    }

    Write-SfdlLog OK "Fertig. Erfolgreich: $okCount  Fehlgeschlagen: $failCount  Dauer: $(ConvertTo-Hms (($stopped - $started).TotalSeconds))"
}
catch [System.Management.Automation.PipelineStoppedException] {
    Request-SfdlCancel -Reason 'PipelineStopped'
    Write-SfdlLog WARN 'Abbruch durch Benutzer (STRG+C). Session bleibt aktiv.'
    Complete-SfdlScript -ExitCode 130
    return
}
catch {
    Request-SfdlCancel -Reason 'Exception'
    Write-SfdlLog ERROR $_.Exception.Message
    if ($_.ScriptStackTrace) { Write-SfdlLog DEBUG $_.ScriptStackTrace }
    Complete-SfdlScript -ExitCode 1
    return
}
finally {
    Clear-SfdlDownloadSession
}
