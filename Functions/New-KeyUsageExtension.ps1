function New-KeyUsageExtension {

    param(
        [Parameter(Mandatory=$True)]
        [ValidateSet(
            "CrlSign",
            "DataEncipherment",
            "DecipherOnly",
            "DigitalSignature",
            "EncipherOnly",
            "KeyAgreement",
            "KeyCertSign",
            "KeyEncipherment",
            "None",
            "NonRepudiation"
            )]
        [String[]]
        $KeyUsage
    )

    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsageFlags = $KeyUsage

    $KeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage

    try {
        $KeyUsageExtension.InitializeEncode([Int]$KeyUsageFlags)

        return $KeyUsageExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    }
    finally {
        $KeyUsageExtension | Unregister-ComObject
    }
}