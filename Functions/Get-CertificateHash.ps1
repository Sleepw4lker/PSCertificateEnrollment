<#
    .SYNOPSIS
    Calculates the Hash Value for a given Byte Array (e.g. a DER encoded Certificate)
    The native GetCertHash seems only to work since .NET 4.8 which is not guaranteed to be present
    https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.getcerthash

    .PARAMETER Bytes
    The Byte Array to calculate the Hash Value for.

    .Parameter HashAlgorithm
    The Algorithm used to calculate the Hash Value.

    .OUTPUTS
    The calculated Hash Value as a String.
#>
function Get-CertificateHash {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]
        $Bytes,

        [Parameter(Mandatory=$False)]
        [String]
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
        $HashAlgorithm = "SHA1"
    )

    begin {}

    process {

        # https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm
        $AlgorithmObject = [System.Security.Cryptography.HashAlgorithm]::Create($HashAlgorithm)

        $HashBytes = $AlgorithmObject.ComputeHash($Bytes)

        $HashString = [String]::Empty

        $HashBytes | ForEach-Object -Process {
            $HashString += $_.ToString("X")
        }

        return $HashString

    }

    end {}

}