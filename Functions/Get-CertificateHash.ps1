<#
    .SYNOPSIS
    Calculates the Hash Value for a given Byte Array
    The native GetCertHhash seems to work since .NET 4.8 which is not guaranteed to be present
    https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.getcerthash
#>
function Get-CertificateHash {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]
        $Bytes,

        [Parameter(Mandatory=$False)]
        [String]
        [ValidateSet("MD5","SHA1","SHA256","SHA512")]
        $HashAlgorithm = "SHA1"
    )

    begin {}

    process {

        $HashString = ''
        $AlgorithmObject = [System.Security.Cryptography.HashAlgorithm]::Create($HashAlgorithm)
        $HashBytes = $AlgorithmObject.ComputeHash($Bytes)
        $HashBytes | ForEach-Object -Process { $HashString += $_.ToString("X") }
        return $HashString

    }

    end {}

}