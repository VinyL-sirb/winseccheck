# malicious-port-checker.ps1
param([switch]$ExportCsv)

# Configuration
$VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Get from: https://www.virustotal.com/gui/join-us
$CACHE_FILE = "$env:TEMP\port-check-cache.json"
$KNOWN_MALICIOUS_PORTS = @(4444, 5555, 6666, 7777, 8080, 31337, 12345, 27374, 12346) # Common malware ports

function Get-NetstatConnections {
    Write-Host "Collecting network connections..." -ForegroundColor Cyan
    $connections = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)\s+.+?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+(\w+)'
    
    $results = @()
    foreach ($match in $connections) {
        $results += [PSCustomObject]@{
            Protocol = $match.Groups[1].Value
            LocalIP = $match.Groups[2].Value
            LocalPort = $match.Groups[3].Value
            RemoteIP = $match.Groups[4].Value
            RemotePort = $match.Groups[5].Value
            State = $match.Groups[6].Value
            PID = (netstat -abno | Select-String -Pattern "$($match.Groups[2].Value):$($match.Groups[3].Value)\s+$($match.Groups[4].Value):$($match.Groups[5].Value)").ToString().Split()[-1]
            ProcessName = (Get-Process -Id $PID -ErrorAction SilentlyContinue).ProcessName
        }
    }
    return $results
}

function Check-PortAgainstKnownList($port) {
    # Check against known malicious port list
    if ($KNOWN_MALICIOUS_PORTS -contains $port) {
        return @{Risk = "High"; Reason = "Known malicious port"}
    }
    
    # Check for suspicious port ranges
    if ($port -gt 49151) { return @{Risk = "Low"; Reason = "Dynamic/private port"} }
    if ($port -lt 1024) { return @{Risk = "Low"; Reason = "Well-known port"} }
    
    return $null
}

function Check-IPWithVirusTotal($ip) {
    # Check if IP is private/local
    if ($ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.)') {
        return @{Risk = "None"; Reason = "Private/Local IP"}
    }
    
    # Check cache first
    $cache = Get-Cache
    if ($cache.$ip) { return $cache.$ip }
    
    # VirusTotal API check
    try {
        $headers = @{ "x-apikey" = $VT_API_KEY }
        $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" -Headers $headers
        
        $malicious = $response.data.attributes.last_analysis_stats.malicious
        $suspicious = $response.data.attributes.last_analysis_stats.suspicious
        
        if ($malicious -gt 5) {
            $result = @{Risk = "High"; Reason = "$malicious security vendors flagged as malicious"}
        } elseif ($malicious -gt 0 -or $suspicious -gt 2) {
            $result = @{Risk = "Medium"; Reason = "$malicious malicious, $suspicious suspicious flags"}
        } else {
            $result = @{Risk = "Low"; Reason = "No malicious flags"}
        }
        
        # Update cache
        $cache.$ip = $result
        Set-Cache $cache
        
        return $result
    }
    catch {
        Write-Warning "VirusTotal API error for $ip : $_"
        return @{Risk = "Unknown"; Reason = "API error"}
    }
}

function Get-Cache {
    if (Test-Path $CACHE_FILE) {
        return Get-Content $CACHE_FILE | ConvertFrom-Json -AsHashtable
    }
    return @{}
}

function Set-Cache($cache) {
    $cache | ConvertTo-Json | Set-Content $CACHE_FILE
}

# Main execution
Write-Host "Network Connection Analyzer" -ForegroundColor Green
Write-Host "============================`n"

$connections = Get-NetstatConnections
$results = @()

foreach ($conn in $connections) {
    Write-Host "Analyzing: $($conn.RemoteIP):$($conn.RemotePort)" -ForegroundColor Gray
    
    # Check port
    $portCheck = Check-PortAgainstKnownList $conn.RemotePort
    
    # Check IP
    $ipCheck = Check-IPWithVirusTotal $conn.RemoteIP
    
    $results += [PSCustomObject]@{
        LocalProcess = $conn.ProcessName
        PID = $conn.PID
        Protocol = $conn.Protocol
        LocalEndpoint = "$($conn.LocalIP):$($conn.LocalPort)"
        RemoteEndpoint = "$($conn.RemoteIP):$($conn.RemotePort)"
        State = $conn.State
        PortRisk = if ($portCheck) { "$($portCheck.Risk) - $($portCheck.Reason)" } else { "Low" }
        IPRisk = "$($ipCheck.Risk) - $($ipCheck.Reason)"
        OverallRisk = if ($portCheck.Risk -eq "High" -or $ipCheck.Risk -eq "High") { "High" } 
                     elseif ($portCheck.Risk -eq "Medium" -or $ipCheck.Risk -eq "Medium") { "Medium" }
                     else { "Low" }
    }
}

# Display results
$results | Format-Table -AutoSize -Property LocalProcess, RemoteEndpoint, PortRisk, IPRisk, OverallRisk

# Export if requested
if ($ExportCsv) {
    $exportPath = ".\network-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $results | Export-Csv -Path $exportPath -NoTypeInformation
    Write-Host "`nResults exported to: $exportPath" -ForegroundColor Green
}

# Summary
$highRisk = ($results | Where-Object { $_.OverallRisk -eq "High" }).Count
$mediumRisk = ($results | Where-Object { $_.OverallRisk -eq "Medium" }).Count

Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "  High Risk Connections: $highRisk"
Write-Host "  Medium Risk Connections: $mediumRisk"
Write-Host "  Total Connections Analyzed: $($results.Count)"