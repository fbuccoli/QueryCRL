# Query CRL for a certificate
# for test and troubleshooting purposes only
# Created: 2014-04-22
# Modified: 2024-01-15
# Author: Francesco V. Buccoli

param(
    [string]$url = "https://www.microsoft.com",
    [int]$timeout = 10000
)

try {
    # Create an HttpWebRequest object
    $request = [System.Net.HttpWebRequest]::Create($url)
    $request.ServicePoint.ConnectionLimit = 1
    $request.Method = "HEAD"
    $request.Timeout = $timeout  # Set timeout from parameter (default is 10 seconds)

    # Retrieve the ServicePoint to access the certificate
    $servicePoint = $request.ServicePoint

    # Make a dummy request to force the ServicePoint to receive the certificate
    $response = $request.GetResponse()
    $response.Close()

    # Retrieve the certificate from the ServicePoint
    $certificate = $servicePoint.Certificate

    # Check if the certificate is null
    if ($null -eq $certificate) {
        Write-Host "No certificate found."
        return
    }

    # Output certificate information
    Write-Host "Certificate Issuer: $($certificate.Issuer)"
    Write-Host "Certificate Subject: $($certificate.Subject)"

    # Check certificate revocation status
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    $chain.ChainPolicy.UrlRetrievalTimeout = new-timespan -Seconds 30
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $chain.Build($certificate)

    foreach ($status in $chain.ChainStatus) {
        if ($status.Status -ne "NoError") {
            Write-Host "Certificate Problem: $($status.StatusInformation.Trim())"
        }
    }

    if ($chain.ChainStatus.Length -eq 0) {
        Write-Host "Certificate is valid."
    }
}
catch {
    Write-Host "Error: $_"
}
