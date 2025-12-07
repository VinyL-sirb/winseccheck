<#
.SYNOPSIS
    Analyzes network connections and checks associated processes/remote IPs against VirusTotal
.DESCRIPTION
    This script enumerates TCP/UDP connections, identifies the responsible processes,
    and checks both the process executables and remote IP addresses against VirusTotal
    to identify potential security threats.
.NOTES
    Requires: VirusTotalAnalyzer PowerShell module
    API Key: Free VirusTotal account required (https://www.virustotal.com)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Low", "Medium", "High", "All")]
    [string]$RiskLevel = "Medium"
)

# Initialize VirusTotal module
function Initialize-VirusTotal {
    try {
        # Install module if not present
        if (-not (Get-Module -Name VirusTotalAnalyzer -ListAvailable)) {
            Write-Host "Installing VirusTotalAnalyzer module..." -ForegroundColor Yellow
            Install-Module -Name VirusTotalAnalyzer -Scope CurrentUser -Force
        }
        
        Import-Module VirusTotalAnalyzer -Force
        Write-Host "✓ VirusTotalAnalyzer module loaded" -ForegroundColor Green
    }
    catch {
        Write-Host "Error loading VirusTotalAnalyzer: $_" -ForegroundColor Red
        exit 1
    }
}

# Get network connections with process information
function Get-NetworkConnections {
    $connections = @()
    
    # Get TCP connections with process info (like netstat -naob but in PowerShell)[citation:10]
    $tcpConnections = Get-NetTCPConnection | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Protocol        = "TCP"
            LocalAddress    = $_.LocalAddress
            LocalPort       = $_.LocalPort
            RemoteAddress   = $_.RemoteAddress
            RemotePort      = $_.RemotePort
            State           = $_.State
            ProcessId       = $_.OwningProcess
            ProcessName     = if ($process) { $process.ProcessName } else { "Unknown" }
            ProcessPath     = if ($process) { $process.Path } else { $null }
            CreationTime    = $_.CreationTime
        }
    }
    
    # Get UDP endpoints with process info[citation:10]
    $udpEndpoints = Get-NetUDPEndpoint | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Protocol        = "UDP"
            LocalAddress    = $_.LocalAddress
            LocalPort       = $_.LocalPort
            RemoteAddress   = $null
            RemotePort      = $null
            State           = "Listen"
            ProcessId       = $_.OwningProcess
            ProcessName     = if ($process) { $process.ProcessName } else { "Unknown" }
            ProcessPath     = if ($process) { $process.Path } else { $null }
            CreationTime    = $_.CreationTime
        }
    }
    
    # Combine and filter connections
    $allConnections = $tcpConnections + $udpEndpoints
    $allConnections = $allConnections | Where-Object {
        $_.RemoteAddress -ne "0.0.0.0" -and 
        $_.RemoteAddress -ne "127.0.0.1" -and 
        $_.RemoteAddress -ne $null -and
        $_.RemoteAddress -notmatch "^::"
    }
    
    return $allConnections
}

# Check process file against VirusTotal
function Test-ProcessWithVirusTotal {
    param(
        [string]$ProcessPath,
        [string]$ApiKey
    )
    
    if (-not $ProcessPath -or -not (Test-Path $ProcessPath)) {
        return $null
    }
    
    try {
        # Get file hash for checking
        $fileHash = (Get-FileHash -Path $ProcessPath -Algorithm SHA256).Hash
        
        # Check against VirusTotal[citation:1][citation:5]
        $result = Get-VirusReport -ApiKey $ApiKey -Hash $fileHash
        
        if ($result.data.attributes.last_analysis_stats) {
            $stats = $result.data.attributes.last_analysis_stats
            $total = $stats.malicious + $stats.undetected + $stats.harmless + $stats.suspicious
            $maliciousCount = $stats.malicious
            
            # Calculate threat level[citation:2]
            if ($total -gt 0) {
                $maliciousPercentage = ($maliciousCount / $total) * 100
                
                return [PSCustomObject]@{
                    FilePath          = $ProcessPath
                    MaliciousCount    = $maliciousCount
                    TotalScans        = $total
                    MaliciousPercent  = [math]::Round($maliciousPercentage, 2)
                    ThreatLevel       = Get-ThreatLevel -Percentage $maliciousPercentage
                    Permalink         = $result.data.links.self
                }
            }
        }
    }
    catch {
        Write-Verbose "Error checking process $ProcessPath: $_"
    }
    
    return $null
}

# Check IP address against VirusTotal
function Test-IPWithVirusTotal {
    param(
        [string]$IPAddress,
        [string]$ApiKey
    )
    
    if (-not $IPAddress -or $IPAddress -eq "0.0.0.0") {
        return $null
    }
    
    try {
        # Check IP against VirusTotal[citation:1][citation:5]
        $result = Get-VirusReport -ApiKey $ApiKey -IPAddress $IPAddress
        
        if ($result.data.attributes.last_analysis_stats) {
            $stats = $result.data.attributes.last_analysis_stats
            $total = $stats.malicious + $stats.undetected + $stats.harmless + $stats.suspicious
            $maliciousCount = $stats.malicious
            
            if ($total -gt 0) {
                $maliciousPercentage = ($maliciousCount / $total) * 100
                
                # Get additional IP information if available
                $asn = $result.data.attributes.asn
                $country = $result.data.attributes.country
                $asOwner = $result.data.attributes.as_owner
                
                return [PSCustomObject]@{
                    IPAddress         = $IPAddress
                    MaliciousCount    = $maliciousCount
                    TotalScans        = $total
                    MaliciousPercent  = [math]::Round($maliciousPercentage, 2)
                    ThreatLevel       = Get-ThreatLevel -Percentage $maliciousPercentage
                    ASN               = $asn
                    Country           = $country
                    ASOwner           = $asOwner
                    Permalink         = $result.data.links.self
                }
            }
        }
    }
    catch {
        Write-Verbose "Error checking IP $IPAddress: $_"
    }
    
    return $null
}

# Determine threat level based on detection percentage[citation:2]
function Get-ThreatLevel {
    param([float]$Percentage)
    
    if ($Percentage -eq 0) { return "None" }
    elseif ($Percentage -lt 1) { return "Very Low" }
    elseif ($Percentage -lt 10) { return "Low" }
    elseif ($Percentage -lt 30) { return "Medium" }
    elseif ($Percentage -lt 50) { return "High" }
    else { return "Very High" }
}

# Main execution
function Start-NetworkThreatAnalysis {
    param(
        [string]$ApiKey,
        [string]$RiskLevel
    )
    
    Write-Host "`n=== Network Threat Analysis ===" -ForegroundColor Cyan
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
    
    # Initialize
    Initialize-VirusTotal
    
    # Get network connections
    Write-Host "Enumerating network connections..." -ForegroundColor Yellow
    $connections = Get-NetworkConnections
    Write-Host "Found $($connections.Count) active connections`n"
    
    $results = @()
    $checkedProcesses = @{}
    $checkedIPs = @{}
    
    # Analyze each connection
    foreach ($conn in $connections) {
        Write-Host "Analyzing: $($conn.Protocol) $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Gray
        
        $processResult = $null
        $ipResult = $null
        
        # Check process (cache results)
        if ($conn.ProcessPath -and -not $checkedProcesses.ContainsKey($conn.ProcessPath)) {
            $processResult = Test-ProcessWithVirusTotal -ProcessPath $conn.ProcessPath -ApiKey $ApiKey
            $checkedProcesses[$conn.ProcessPath] = $processResult
        }
        elseif ($conn.ProcessPath) {
            $processResult = $checkedProcesses[$conn.ProcessPath]
        }
        
        # Check remote IP (cache results)
        if ($conn.RemoteAddress -and -not $checkedIPs.ContainsKey($conn.RemoteAddress)) {
            $ipResult = Test-IPWithVirusTotal -IPAddress $conn.RemoteAddress -ApiKey $ApiKey
            $checkedIPs[$conn.RemoteAddress] = $ipResult
        }
        elseif ($conn.RemoteAddress) {
            $ipResult = $checkedIPs[$conn.RemoteAddress]
        }
        
        # Determine overall risk
        $overallRisk = "None"
        if ($processResult -or $ipResult) {
            $maxRisk = 0
            if ($processResult -and $processResult.ThreatLevel -ne "None") {
                $maxRisk = [math]::Max($maxRisk, $processResult.MaliciousPercent)
            }
            if ($ipResult -and $ipResult.ThreatLevel -ne "None") {
                $maxRisk = [math]::Max($maxRisk, $ipResult.MaliciousPercent)
            }
            $overallRisk = Get-ThreatLevel -Percentage $maxRisk
        }
        
        # Add to results if meets risk threshold
        $riskValues = @{"None"=0; "Very Low"=1; "Low"=2; "Medium"=3; "High"=4; "Very High"=5}
        $threshold = $riskValues[$RiskLevel]
        
        if ($riskValues[$overallRisk] -ge $threshold) {
            $results += [PSCustomObject]@{
                Connection      = "$($conn.Protocol)/$($conn.LocalPort)"
                LocalEndpoint   = "$($conn.LocalAddress):$($conn.LocalPort)"
                RemoteEndpoint  = if ($conn.RemoteAddress) { "$($conn.RemoteAddress):$($conn.RemotePort)" } else { "N/A" }
                Process         = $conn.ProcessName
                ProcessRisk     = if ($processResult) { "$($processResult.ThreatLevel) ($($processResult.MaliciousPercent)%)" } else { "Not checked" }
                IPRisk          = if ($ipResult) { "$($ipResult.ThreatLevel) ($($ipResult.MaliciousPercent)%)" } else { "Not checked" }
                OverallRisk     = $overallRisk
                ProcessLink     = if ($processResult) { $processResult.Permalink } else { $null }
                IPLink          = if ($ipResult) { $ipResult.Permalink } else { $null }
            }
        }
        
        # Rate limiting for free API (4 requests per minute)
        Start-Sleep -Seconds 15
    }
    
    # Display results
    if ($results.Count -gt 0) {
        Write-Host "`n=== POTENTIAL THREATS FOUND ===" -ForegroundColor Red
        $results | Format-Table -AutoSize -Property `
            @{Name="Connection"; Expression={$_.Connection}; Width=15},
            @{Name="Process"; Expression={$_.Process}; Width=20},
            @{Name="Local"; Expression={$_.LocalEndpoint}; Width=25},
            @{Name="Remote"; Expression={$_.RemoteEndpoint}; Width=25},
            @{Name="Overall Risk"; Expression={
                switch ($_.OverallRisk) {
                    "High" { Write-Host $_ -ForegroundColor Red -NoNewline; "" }
                    "Medium" { Write-Host $_ -ForegroundColor Yellow -NoNewline; "" }
                    "Low" { Write-Host $_ -ForegroundColor Green -NoNewline; "" }
                    default { $_ }
                }
            }; Width=12}
        
        # Display detailed information for high risks
        $highRisks = $results | Where-Object { $_.OverallRisk -match "High|Very High" }
        if ($highRisks.Count -gt 0) {
            Write-Host "`n=== DETAILED ANALYSIS OF HIGH RISK ITEMS ===" -ForegroundColor Magenta
            foreach ($risk in $highRisks) {
                Write-Host "`nConnection: $($risk.Connection)" -ForegroundColor Yellow
                Write-Host "Process: $($risk.Process)" -ForegroundColor Yellow
                Write-Host "Local: $($risk.LocalEndpoint)" -ForegroundColor Yellow
                Write-Host "Remote: $($risk.RemoteEndpoint)" -ForegroundColor Yellow
                
                if ($risk.ProcessLink) {
                    Write-Host "Process Analysis: $($risk.ProcessLink)" -ForegroundColor Cyan
                }
                if ($risk.IPLink) {
                    Write-Host "IP Analysis: $($risk.IPLink)" -ForegroundColor Cyan
                }
                
                # Suggest actions based on port and risk
                Write-Host "Suggested Actions:" -ForegroundColor Green
                if ($risk.RemoteEndpoint -match ":(\d+)$") {
                    $port = $matches[1]
                    switch -wildcard ($port) {
                        "22" { Write-Host "  - Check SSH connections for unauthorized access" }
                        "23" { Write-Host "  - Telnet is insecure, consider disabling" }
                        "3389" { Write-Host "  - Verify RDP connections are authorized" }
                        "445" { Write-Host "  - SMB port, check for file sharing anomalies" }
                    }
                }
                
                if ($risk.OverallRisk -match "Very High") {
                    Write-Host "  - Consider immediate process termination" -ForegroundColor Red
                    Write-Host "  - Investigate process: $($risk.Process)" -ForegroundColor Red
                    Write-Host "  - Block IP: $($risk.RemoteEndpoint.Split(':')[0])" -ForegroundColor Red
                }
            }
        }
    }
    else {
        Write-Host "`nNo threats found at the '$RiskLevel' risk level or above." -ForegroundColor Green
    }
    
    # Summary
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total connections analyzed: $($connections.Count)"
    Write-Host "Processes checked: $($checkedProcesses.Count)"
    Write-Host "IPs checked: $($checkedIPs.Count)"
    Write-Host "Potential threats found: $($results.Count)"
    Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

# Run the analysis
Start-NetworkThreatAnalysis -ApiKey $ApiKey -RiskLevel $RiskLevel
