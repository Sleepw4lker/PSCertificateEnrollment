function New-ExtendedKeyUsageExtension {

    param(
        [Alias("ExtendedKeyUsage")]
        [Alias("EnhancedKeyUsage")]
        [Parameter(Mandatory=$True)]
        [ValidateSet(
            "EnrollmentAgent",
            "ClientAuthentication",
            "CodeSigning",
            "LifeTimeSigning",
            "DocumentSigning",
            "DocumentEncryption",
            "EncryptingFileSystem",
            "FileRecovery",
            "IPSecEndSystem",
            "IPSecIKEIntermediate",
            "IPSecTunnelEndpoint",
            "IPSecUser",
            "KeyRecovery",
            "KDCAuthentication",
            "SecureEmail",
            "ServerAuthentication",
            "SmartCardLogon",
            "TimeStamping",
            "OCSPSigning",
            "RemoteDesktopAuthentication",
            "PrivateKeyArchival"
            )]
        [String[]]
        $Eku
    )
 
    $EnhancedKeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
    $EnhancedKeyUsageOids = New-Object -ComObject X509Enrollment.CObjectIds.1

    try {

        # Get-Unique is case-sensitive but ValidateSet is not, so dedupe with Sort-Object -Unique instead
        $Eku | Sort-Object -Unique | ForEach-Object -Process {

            $OidObject = New-Object -ComObject X509Enrollment.CObjectId
            $OidObject.InitializeFromValue($EkuNameToOidTable[$_])
            $EnhancedKeyUsageOids.Add($OidObject)
            $OidObject | Unregister-ComObject

        }

        $EnhancedKeyUsageExtension.InitializeEncode($EnhancedKeyUsageOids)

        return $EnhancedKeyUsageExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    }
    finally {
        $EnhancedKeyUsageExtension | Unregister-ComObject
        $EnhancedKeyUsageOids | Unregister-ComObject
    }
}