function New-ApplicationPoliciesExtension {
    param(
        [Alias("ApplicationPolicy")]
        [Parameter(Mandatory=$true)]
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
        $ApplicationPolicies
    )

    $ApplicationPoliciesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionMSApplicationPolicies

    try {

        $ApplicationPolicyOids = New-Object -ComObject X509Enrollment.CCertificatePolicies.1
        
        $ApplicationPolicies | Sort-Object | Get-Unique | ForEach-Object -Process {
        
            $ApplicationPolicyOid = New-Object -ComObject X509Enrollment.CObjectId
            $ApplicationPolicyOid.InitializeFromValue($EkuNameToOidTable[$_])
        
            $CertificatePolicy = New-Object -ComObject X509Enrollment.CCertificatePolicy
            $CertificatePolicy.Initialize($ApplicationPolicyOid)
            $ApplicationPolicyOids.Add($CertificatePolicy)

            $CertificatePolicy | Unregister-ComObject
            $ApplicationPolicyOid | Unregister-ComObject
        }
        
        $ApplicationPoliciesExtension.InitializeEncode($ApplicationPolicyOids)

        return $ApplicationPoliciesExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    }
    finally {
        $ApplicationPoliciesExtension | Unregister-ComObject
    }
}