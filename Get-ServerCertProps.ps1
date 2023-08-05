[CmdletBinding()]
param(
    $openssl_path = 'C:\Program Files\Git\usr\bin\openssl.exe',
    $server = "www.mit.edu:443",
    [Parameter(Mandatory)]
    [ValidateSet('json','json-compressed','table')]
    [string]$format='json'    
)


if (-not(Test-Path -Path $openssl_path)) {
    write-host "Resource file not found: $($openssl_path)"
    exit 1
}

$certfile_path = "$($env:temp)\tmp_cert_file.pem"
if (test-path -path $certfile_path) {
    remove-item -path $certfile_path -force
}

$s_client = Write-Output "q`n" | & $openssl_path s_client -connect $server -status 2>$null

$certificate = @()

# capture content of the server cert
foreach ($line in $s_client) {
   
    if ($line -match '^-----BEGIN CERTIFICATE-----') {
        $inCert = $true
    }

    if ($inCert -eq $true) {
        $certificate += $line
    }

    if ($line -match '^-----END CERTIFICATE-----') {
        $inCert = $false
        # clean the captured content
    }
}

# write server certificate to tmp file
$certfile_path = "$($env:temp)\tmp_cert_file.pem"
$certificate | Set-Content -Path $certfile_path

if (-not($certificate)) {
    write-host "s_client connection to server failed."
    break
} else {
    # export content of certificate
    $x509 = & $openssl_path x509 -in $certfile_path -text 2>$null

    # create object in which to store extracted entities
    $records = New-Object System.Collections.ArrayList

    $records.add([ordered]@{server = $server }) | Out-Null

    # get cert subject
    foreach ($line in $x509) {
        if ($line -match '^\s*Subject\s*:') {
            $cert_subject = $line -replace '^\s*Subject\s*:\s*', ''
            $records.add([ordered]@{cert_subject = $cert_subject }) | Out-Null
            break
        }
    }

    # get cert serialno
    $lineBefore = $false
    foreach ($line in $x509) {
        if ($line -match '^\s*Serial Number\s*:') {
            $lineBefore = $true
            continue
        }
        if ($lineBefore -eq $true) {
            $cert_serial = $line.trim()
            $records.add([ordered]@{cert_serial = $cert_serial }) | Out-Null
            break
        }
    } 
    
    # get cert issuer
    foreach ($line in $x509) {
        if ($line -match '^\s*Issuer\s*:') {
            $cert_issuer = $line -replace '^\s*Issuer\s*:\s*', ''
            $records.add([ordered]@{cert_issuer = $cert_issuer }) | Out-Null
            break
        }
    }

    # get cert validity - before
    foreach ($line in $x509) {
        if ($line -match "^\s+Not Before\s*:") {
            $not_before = $line -replace '^[^\:]+:\s*', ''
            $records.add([ordered]@{not_before = $not_before }) | Out-Null
            break
        }
    }

    # get cert validity - after
    foreach ($line in $x509) {
        if ($line -match "^\s+Not After\s*:") {
            $not_after = $line -replace '^[^\:]+:\s*', ''
            $records.add([ordered]@{not_after = $not_after }) | Out-Null
            break
        }
    }
    
    # get cert Subject Alternative Name entries
    foreach ($line in $x509) {
        $entry = $line | Select-String -Pattern "^\s+DNS\s*:"
        if ($entry) {
            $entry = $entry.tostring().TrimStart()
            $entries = $entry -split ", "
            $counter = 0
            foreach ($entry in $entries) {
                $counter++
                $dns_entry = $entry -replace '^DNS:', ''
                $records.add([ordered]@{"dns_entry_$($counter)" = $dns_entry }) | Out-Null
            }
        }
    }
}

if ($format -eq "json") {
    $records | ConvertTo-Json 
}

if ($format -eq "json-compressed") {
    $records | ConvertTo-Json -Compress
}

if ($format -eq "table") {
    $records | Format-Table
}
