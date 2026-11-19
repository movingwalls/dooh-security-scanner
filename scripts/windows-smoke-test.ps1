<#
.SYNOPSIS
  Tests a PUBLISHED Windows release of the DOOH Security Scanner on this machine, the way a user would use it.

.DESCRIPTION
  Downloads dooh-security-scanner-<version>-windows-x64.zip from the GitHub release, verifies its SHA-256, extracts it
  and checks, against simulated devices on 127.0.0.1 (nothing outside this computer is scanned):
    1. the exe starts and reports the right version
    2. an open ADB + VNC device is reported FAIL with a CRITICAL finding (the bundled Nuclei works, offline)
    3. an ADB that asks for authorisation is FAIL but NOT critical
    4. a "nuclei.exe" planted in the folder you run from is never executed
    5. a tampered Nuclei next to the app is refused (never executed) when downloads are off
  Everything happens in a new folder under %TEMP%, which is deleted at the end (use -Keep to keep it).

  Run in Windows PowerShell 5.1 or PowerShell 7 (no admin rights needed):
      powershell -ExecutionPolicy Bypass -File .\windows-smoke-test.ps1 -Tag v1.0.0-rc3
  Antivirus may flag nuclei.exe (security tools often are). If so, allow it and run again.
#>
param(
    [string]$Tag = "v1.0.0-rc3",
    [switch]$Keep
)

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$version = $Tag.TrimStart("v")
$base = "https://github.com/movingwalls/dooh-security-scanner/releases/download/$Tag"
$zipName = "dooh-security-scanner-$version-windows-x64.zip"
$root = Join-Path $env:TEMP ("dooh-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $root | Out-Null
$results = New-Object System.Collections.ArrayList
$jobs = @()

function Record($name, $ok, $detail) {
    [void]$results.Add([pscustomobject]@{ Test = $name; Result = $(if ($ok) { "PASS" } else { "FAIL" }); Detail = $detail })
    $colour = if ($ok) { "Green" } else { "Red" }
    Write-Host ("[{0}] {1}  {2}" -f $(if ($ok) { "PASS" } else { "FAIL" }), $name, $detail) -ForegroundColor $colour
}

# Fake device: listens on 127.0.0.1:5555 (ADB) and :5900 (VNC). $adbMode = "open" or "auth".
function Start-FakeDevice($adbMode) {
    $adb = if ($adbMode -eq "open") {
        [byte[]]([Text.Encoding]::ASCII.GetBytes("CNXN") + (New-Object byte[] 20) + [Text.Encoding]::ASCII.GetBytes("device::") + [byte]0)
    } else {
        [byte[]]([Text.Encoding]::ASCII.GetBytes("AUTH") + (New-Object byte[] 20) + [byte[]](1, 0, 0, 0))
    }
    $vnc = [byte[]][Text.Encoding]::ASCII.GetBytes("RFB 003.008`n")
    $script = {
        param($port, $reply)
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
        $listener.Start()
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                if ($port -eq 5555) {
                    $client.ReceiveTimeout = 2000
                    $buf = New-Object byte[] 64
                    try { [void]$stream.Read($buf, 0, 64) } catch { }
                }
                $stream.Write($reply, 0, $reply.Length)
                $stream.Flush()
                Start-Sleep -Milliseconds 300
            } catch { } finally { $client.Close() }
        }
    }
    $j = @((Start-Job -ScriptBlock $script -ArgumentList 5555, $adb), (Start-Job -ScriptBlock $script -ArgumentList 5900, $vnc))
    Start-Sleep -Seconds 2
    return $j
}

function Stop-FakeDevice($j) {
    foreach ($x in $j) { Stop-Job $x -ErrorAction SilentlyContinue; Remove-Job $x -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
}

# Runs the scanner; returns exit code and combined output.
function Invoke-Scanner($exe, $workDir, $argLine) {
    $out = Join-Path $root ("out-" + [guid]::NewGuid().ToString("N").Substring(0, 6) + ".txt")
    $err = $out + ".err"
    $env:DOOH_SCANNER_HOME = Join-Path $root "home"   # empty cache: nothing but the bundle can supply Nuclei
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $workDir -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $text = (Get-Content $out -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content $err -Raw -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Code = $p.ExitCode; Text = $text }
}

try {
    Write-Host "== Windows smoke test of $Tag on $([Environment]::OSVersion.VersionString), $env:PROCESSOR_ARCHITECTURE (PowerShell $($PSVersionTable.PSVersion))"
    Write-Host "== Working in $root"

    # --- download + verify
    $zip = Join-Path $root $zipName
    Invoke-WebRequest -Uri "$base/$zipName" -OutFile $zip -UseBasicParsing
    $expected = ((Invoke-WebRequest -Uri "$base/$zipName.sha256" -UseBasicParsing).Content -split "\s+")[0].Trim().ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
    Record "download + SHA-256 matches the .sha256 file" ($expected -eq $actual) $actual.Substring(0, 16)
    if ($expected -ne $actual) { throw "Checksum mismatch; stopping." }

    Expand-Archive -Path $zip -DestinationPath (Join-Path $root "app") -Force
    $appDir = (Get-ChildItem (Join-Path $root "app") -Directory | Select-Object -First 1).FullName
    $exe = Join-Path $appDir "dooh-security-scanner.exe"
    Record "bundle contains the exe and nuclei.exe" ((Test-Path $exe) -and (Test-Path (Join-Path $appDir "app\nuclei.exe"))) $appDir

    # --- 1. version
    $r = Invoke-Scanner $exe $root "--version"
    Record "1. --version reports $version" ($r.Text -match [regex]::Escape($version)) ($r.Text.Trim() -split "`n")[0]

    # --- a "nuclei.exe" planted in the folder the user runs from: it writes a marker file if it is ever executed
    $work = Join-Path $root "Downloads"
    New-Item -ItemType Directory -Path $work | Out-Null
    $marker = Join-Path $root "PLANTED_RAN.txt"
    $src = 'public class P { public static void Main() { System.IO.File.WriteAllText(@"' + $marker + '", "ran"); System.Console.WriteLine("Nuclei Engine Version: v3.4.10"); } }'
    $planted = Join-Path $work "nuclei.exe"
    $canPlant = $true
    try { Add-Type -TypeDefinition $src -OutputType ConsoleApplication -OutputAssembly $planted -ErrorAction Stop }
    catch { $canPlant = $false; Write-Host "   (could not build a planted nuclei.exe here: $($_.Exception.Message))" -ForegroundColor Yellow }

    # --- 2. open ADB + VNC, planted nuclei.exe in the working folder, downloads forbidden
    $jobs = Start-FakeDevice "open"
    $out2 = Join-Path $root "scans2"
    $r = Invoke-Scanner $exe $work ("-h 127.0.0.1 --yes --offline --out `"$out2`"")
    Stop-FakeDevice $jobs
    Record "2. open ADB + VNC device: FAIL with a CRITICAL finding" (($r.Code -eq 1) -and ($r.Text -match "CRITICAL") -and ($r.Text -match "\[FAIL\]")) ("exit " + $r.Code)
    Record "2b. the bundled Nuclei was used without downloading or warnings" (($r.Text -notmatch "Skipping") -and ($r.Text -notmatch "not checked against the official build") -and ($r.Text -notmatch "Downloading")) ""
    if ($canPlant) { Record "4. the planted nuclei.exe in the working folder was NOT executed" (-not (Test-Path $marker)) $(if (Test-Path $marker) { "IT RAN" } else { "marker file absent" }) }

    # --- 3. ADB that asks for authorisation
    $jobs = Start-FakeDevice "auth"
    $r = Invoke-Scanner $exe $work ("-h 127.0.0.1 --yes --offline --out `"" + (Join-Path $root "scans3") + "`"")
    Stop-FakeDevice $jobs
    Record "3. ADB that asks for authorisation: FAIL, HIGH, not CRITICAL" (($r.Code -eq 1) -and ($r.Text -match "HIGH") -and ($r.Text -notmatch "CRITICAL")) ("exit " + $r.Code)

    # --- 5. tampered Nuclei next to the app, downloads forbidden: must be refused and never run
    $tamperedApp = Join-Path $root "tampered"
    Copy-Item $appDir $tamperedApp -Recurse
    $bundled = Join-Path $tamperedApp "app\nuclei.exe"
    if ($canPlant) {
        if (Test-Path $marker) { Remove-Item $marker -Force }
        Copy-Item $planted $bundled -Force
        $r = Invoke-Scanner (Join-Path $tamperedApp "dooh-security-scanner.exe") $work ("-h 127.0.0.1 --yes --offline --out `"" + (Join-Path $root "scans5") + "`"")
        Record "5. a tampered Nuclei next to the app is refused" (($r.Text -match "Skipping") -and ($r.Code -eq 3) -and (-not (Test-Path $marker))) ("exit " + $r.Code)
    }
}
catch {
    Record "unexpected error" $false $_.Exception.Message
}
finally {
    Stop-FakeDevice $jobs
    Remove-Item Env:\DOOH_SCANNER_HOME -ErrorAction SilentlyContinue
    if (-not $Keep) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue } else { Write-Host "Kept: $root" }
}

Write-Host ""
$results | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object { $_.Result -eq "FAIL" }).Count
if ($failed -eq 0) { Write-Host "ALL $($results.Count) CHECKS PASSED" -ForegroundColor Green; exit 0 }
Write-Host "$failed of $($results.Count) CHECKS FAILED. Copy this whole output back." -ForegroundColor Red
exit 1
