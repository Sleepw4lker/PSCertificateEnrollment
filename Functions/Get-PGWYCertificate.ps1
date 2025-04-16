<#
    .SYNOPSIS
    Allows for Submission of a Certificate Request to a Nexus Certificate Manager (CM) REST API.

    .PARAMETER CertificateRequest
    The BASE64 encoded Certificate Request to be submitted to the Nexus CM.

    .PARAMETER ComputerName
    The Host name of the CM API endpoint.

    .PARAMETER Port
    The TCP Port of the CM API endpoint. Defaults to 8444.

    .PARAMETER Suffix
    The URI suffix of the CM API endpoint to be used. Should end with "pkcs10".

    .PARAMETER ClientCertificate
    The virtual Registration Officer (vRO) certificate to authenticate to the CM API.

    .PARAMETER SignerCertificate
    The virtual Registration Officer (vRO) certificate to sign certificate requests prior to submission to the CM API.
    If CM API requires a signature and this is not specified, we try to sign with the ClientCertificate.

    .NOTES
    API documentation is to be found at https://doc.nexusgroup.com/pub/certificate-manager-cm-rest-api
#>
function Get-PGWYCertificate {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory=$True, ValuefromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateRequest,

        [Parameter(Mandatory=$True)]
        [String]
        $ComputerName,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,65535)]
        [Int]
        $Port = 8444,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Suffix = "api/pkcs10",

        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $ClientCertificate,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $SignerCertificate
    )

    process {

        $Response = Invoke-PGWYPKCS10Operation `
            -Uri "https://$($ComputerName):$($Port)/$($Suffix)" `
            -CertificateRequest $(, [System.Convert]::FromBase64String((ConvertFrom-PemToBase64 -String $CertificateRequest))) `
            -ClientCertificate $(Get-CertificateByThumbprint -Thumbprint $ClientCertificate)

        $ApiResponse = $Response.Content | ConvertFrom-Json

        if ($ApiResponse.msg -eq "Sign request and send again") {
        
            if (-not $SignerCertificate) {
                $SignerCertificate = $ClientCertificate
            }

            $SignedData = New-SignedCms `
                -DataToSign $(, $([Convert]::FromBase64String($ApiResponse.DataToSign))) `
                -SignerCertificate $(Get-CertificateByThumbprint -Thumbprint $SignerCertificate)

            $Response = Invoke-PGWYPKCS10Operation `
                -Uri "https://$($ComputerName):$($Port)/$($Suffix)" `
                -CertificateRequest $(, [System.Convert]::FromBase64String((ConvertFrom-PemToBase64 -String $CertificateRequest))) `
                -ClientCertificate $(Get-CertificateByThumbprint -Thumbprint $ClientCertificate) `
                -SignedData $(, $SignedData)
        }

        if ($Response.Headers["Content-Type"] -eq "application/pkix-cert") {
            
            $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]]$Response.Content)
            return $Certificate
        }

        # Dump Response in failure case
        $Response
    }
}