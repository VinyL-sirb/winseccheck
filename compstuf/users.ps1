# Requires Run as Administrator
param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath
)

# Function to convert plain text password to SecureString
function ConvertTo-SecureStringFromPlainText {
    param([string]$PlainTextPassword)
    return ConvertTo-SecureString $PlainTextPassword -AsPlainText -Force
}

try {
    # Read CSV file
    $users = Import-Csv -Path $CsvPath
    
    # Get existing local users
    $existingUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    # Remove users not in CSV
    foreach ($user in $existingUsers) {
        if ($users.Username -notcontains $user.Name) {
            Write-Host "Removing user: $($user.Name)"
            Remove-LocalUser -Name $user.Name
        }
    }
    
    # Process each user in CSV
    foreach ($user in $users) {
        $username = $user.Username
        $password = ConvertTo-SecureStringFromPlainText -PlainTextPassword $user.Password
        $isAdmin = [bool]::Parse($user.Admin)
        
        # Create or update user
        if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
            # Update password for existing user
            Set-LocalUser -Name $username -Password $password
            Write-Host "Updated password for: $username"
        } else {
            # Create new user
            New-LocalUser -Name $username -Password $password -AccountNeverExpires
            Write-Host "Created user: $username"
        }
        
        # Manage administrator privileges
        $isMember = (Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -like "*$username" }).Count -gt 0
        
        if ($isAdmin -and !$isMember) {
            Add-LocalGroupMember -Group "Administrators" -Member $username
            Write-Host "Added $username to Administrators group"
        } elseif (!$isAdmin -and $isMember) {
            Remove-LocalGroupMember -Group "Administrators" -Member $username
            Write-Host "Removed $username from Administrators group"
        }
    }
    
    Write-Host "User synchronization completed successfully." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $_"
}