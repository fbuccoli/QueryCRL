# Check the Certificate Revocation List for a given website
# and report if the certificate is valid or has been revoked.
# Created for test only by Francesco V. Buccoli

param(
    [string]$url = "https://example.com"
)

function Check-CertificateRevocation {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

    $chain.Build($cert)
    $chain.ChainStatus
}

function Get-ServerCertificate {
    param(
        [string]$url
    )

    $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($url)
    $ServicePoint.Certificate | Out-Null
    $ServicePoint.Close()
    
    return $ServicePoint.Certificate
}

try {
    Write-Host "Fetching certificate for URL: $url"
    $cert = Get-ServerCertificate -url $url
    if ($null -eq $cert) {
        Write-Host "No certificate found for the URL: $url"
        exit
    }

    $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
    $chainStatus = Check-CertificateRevocation -cert $cert2

    foreach ($status in $chainStatus) {
        if ($status.Status -eq "Revoked") {
            Write-Host "The certificate has been revoked."
            exit
        }
    }

    Write-Host "The certificate is valid."
} catch {
    Write-Host "An error occurred: $_"
}
