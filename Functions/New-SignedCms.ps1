function New-SignedCms {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]
        $DataToSign,

        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $SignerCertificate,

        [Switch]
        $Detached
    )

    $CmsSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner($SignerCertificate)
    $ContentInfo = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo(, $DataToSign)
    $SignedCms = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms($ContentInfo, $Detached.IsPresent);
    $SignedCms.ComputeSignature($CmsSigner);

    return $SignedCms.Encode()
}