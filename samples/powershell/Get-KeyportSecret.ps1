<#
.SYNOPSIS
    Reads a connection string or credential from Keyport.

.EXAMPLE
    # Prod is port 9446. The API key comes from an env var; never hard-code it.
    $cs = ./Get-KeyportSecret.ps1 -BaseUrl https://keyport.corp.local:9446 -Name billing/sql-main -Kind connections
    $cred = ./Get-KeyportSecret.ps1 -BaseUrl https://keyport.corp.local:9446 -Name batch/svc-account -Kind credentials -AsPSCredential

.NOTES
    The Keyport CA must be trusted by the machine:
      Import-Certificate -FilePath keyport-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BaseUrl,
    [Parameter(Mandatory)] [string] $Name,
    [ValidateSet('connections', 'credentials', 'secrets')] [string] $Kind = 'connections',
    [string] $ApiKey = $env:KEYPORT_API_KEY,
    [switch] $AsPSCredential
)

if (-not $ApiKey) { throw 'Set KEYPORT_API_KEY or pass -ApiKey.' }

$uri = '{0}/api/v1/{1}/{2}' -f $BaseUrl.TrimEnd('/'), $Kind, $Name
try {
    $r = Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $ApiKey" } -Method Get -TimeoutSec 10
}
catch {
    $code = $_.Exception.Response.StatusCode.value__
    switch ($code) {
        401 { throw "API key rejected for this environment port ($BaseUrl)." }
        404 { throw "Secret '$Name' not found or not granted to this client." }
        default { throw }
    }
}

switch ($Kind) {
    'connections' { $r.connectionString }
    'credentials' {
        if ($AsPSCredential) {
            $user = if ($r.domain) { "$($r.domain)\$($r.username)" } else { $r.username }
            New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $r.password -AsPlainText -Force))
        }
        else { $r }
    }
    default { $r }
}
