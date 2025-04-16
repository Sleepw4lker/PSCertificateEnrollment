<#
    https://doc.nexusgroup.com/pub/certificate-manager-cm-rest-api
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