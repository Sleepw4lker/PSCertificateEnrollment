function New-SmimeCapabilitiesExtension {
    param(
        [Alias("SmimeCapabilities")]
        [Parameter(Mandatory=$True)]
        [ValidateSet(
            "des",
            "des3",
            "rc2",
            "rc4",
            "des3wrap",
            "rc2wrap",
            "aes128",
            "aes192",
            "aes256",
            "aes128wrap",
            "aes192wrap",
            "aes256wrap",
            "md5",
            "sha1",
            "sha256",
            "sha384",
            "sha512"
            )]
        [String[]]
        $Smime
    )

    $SmimeExtension = New-Object -ComObject X509Enrollment.CX509ExtensionSmimeCapabilities
    $SmimeCapabilitiesObject = New-Object -ComObject X509Enrollment.CSmimeCapabilities

    try {

        $Smime | ForEach-Object -Process {

            # The Bit length is only relevant for RC2 and RC4. We use the same defaults as Microsoft does.
            If ($_ -in ("rc2","rc2wrap","rc4")) { $BitCount = 128 } Else { $BitCount = 0 }

            $OidObject = New-Object -ComObject X509Enrollment.CObjectId
            $OidObject.InitializeFromValue($SmimeCapabilityToOidTable[$_])

            $SmimeCapabilityObject = New-Object -ComObject X509Enrollment.CSmimeCapability
            $SmimeCapabilityObject.Initialize($OidObject, $BitCount)
            $SmimeCapabilitiesObject.Add($SmimeCapabilityObject)

            $SmimeCapabilityObject | Unregister-ComObject
            $OidObject | Unregister-ComObject
        }

        $SmimeExtension.InitializeEncode($SmimeCapabilitiesObject)

        return $SmimeExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    }
    finally {
        $SmimeExtension | Unregister-ComObject
        $SmimeCapabilitiesObject | Unregister-ComObject
    }
}