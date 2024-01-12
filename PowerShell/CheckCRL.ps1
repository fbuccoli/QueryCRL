param(
    [Parameter(Mandatory = $true)]
    [string]$URL
)

function Validate-UrlFormat {
    param(
        [string]$url
    )

    if (-not ($url -match '^https?://')) {
        $url = "https://$url"
    }
    return $url
}

function Get-CertificateDetails {
    param(
        [string]$url
    )

    try {
        # Ignoring SSL errors for the purpose of fetching the certificate
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

        $request = [Net.HttpWebRequest]::Create($url)
        $request.GetResponse() | Out-Null

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$request.ServicePoint.Certificate
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllFlags

        $chain.Build($cert)

        $crlEntry = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "CRL Distribution Points"}

        $details = @{
            "Issuer" = $cert.Issuer
            "ValidFrom" = $cert.NotBefore
            "ValidTo" = $cert.NotAfter
            "CRLDistributionUrl" = $crlEntry.Format($false)
            "IsRevoked" = $chain.ChainStatus -match "Revoked"
        }

        return $details
    }
    catch {
        Write-Host "Error: $_"
    }
}

$url = Validate-UrlFormat -url $URL
$certificateDetails = Get-CertificateDetails -url $url

$certificateDetails.GetEnumerator() | ForEach-Object {
    Write-Host "$($_.Key): $($_.Value)"
}
