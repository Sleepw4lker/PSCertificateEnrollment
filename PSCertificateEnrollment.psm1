# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
New-Variable -Option Constant -Name CR_IN_BASE64HEADER -Value 0
New-Variable -Option Constant -Name CR_IN_BASE64 -Value 1
New-Variable -Option Constant -Name CR_IN_BINARY -Value 2
New-Variable -Option Constant -Name CR_IN_ENCODEANY -Value 0xff

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getcertificate
New-Variable -Option Constant -Name CR_OUT_BASE64HEADER -Value 0
New-Variable -Option Constant -Name CR_OUT_BASE64 -Value 1
New-Variable -Option Constant -Name CR_OUT_BINARY -Value 2

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
New-Variable -Option Constant -Name CR_DISP_INCOMPLETE -Value 0
New-Variable -Option Constant -Name CR_DISP_ERROR -Value 1
New-Variable -Option Constant -Name CR_DISP_DENIED -Value 2
New-Variable -Option Constant -Name CR_DISP_ISSUED -Value 3
New-Variable -Option Constant -Name CR_DISP_ISSUED_OUT_OF_BAND -Value 4
New-Variable -Option Constant -Name CR_DISP_UNDER_SUBMISSION -Value 5

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest2-getfullresponseproperty
New-Variable -Option Constant -Name FR_PROP_NONE -Value 0
New-Variable -Option Constant -Name FR_PROP_FULLRESPONSE -Value 1
New-Variable -Option Constant -Name FR_PROP_STATUSINFOCOUNT -Value 2
New-Variable -Option Constant -Name FR_PROP_BODYPARTSTRING -Value 3
New-Variable -Option Constant -Name FR_PROP_STATUS -Value 4
New-Variable -Option Constant -Name FR_PROP_STATUSSTRING -Value 5
New-Variable -Option Constant -Name FR_PROP_OTHERINFOCHOICE -Value 6
New-Variable -Option Constant -Name FR_PROP_FAILINFO -Value 7
New-Variable -Option Constant -Name FR_PROP_PENDINFOTOKEN -Value 8
New-Variable -Option Constant -Name FR_PROP_PENDINFOTIME -Value 9
New-Variable -Option Constant -Name FR_PROP_ISSUEDCERTIFICATEHASH -Value 10
New-Variable -Option Constant -Name FR_PROP_ISSUEDCERTIFICATE -Value 11
New-Variable -Option Constant -Name FR_PROP_ISSUEDCERTIFICATECHAIN -Value 12
New-Variable -Option Constant -Name FR_PROP_ISSUEDCERTIFICATECRLCHAIN -Value 13
New-Variable -Option Constant -Name FR_PROP_ENCRYPTEDKEYHASH -Value 14
New-Variable -Option Constant -Name FR_PROP_FULLRESPONSENOPKCS7 -Value 15
New-Variable -Option Constant -Name FR_PROP_CAEXCHANGECERTIFICATEHASH -Value 16
New-Variable -Option Constant -Name FR_PROP_CAEXCHANGECERTIFICATE -Value 17
New-Variable -Option Constant -Name FR_PROP_CAEXCHANGECERTIFICATECHAIN -Value 18
New-Variable -Option Constant -Name FR_PROP_CAEXCHANGECERTIFICATECRLCHAIN -Value 19
New-Variable -Option Constant -Name FR_PROP_ATTESTATIONCHALLENGE -Value 20
New-Variable -Option Constant -Name FR_PROP_ATTESTATIONPROVIDERNAME -Value 21

New-Variable -Option Constant -Name PROPTYPE_LONG -Value 1
New-Variable -Option Constant -Name PROPTYPE_DATE -Value 2
New-Variable -Option Constant -Name PROPTYPE_BINARY -Value 3
New-Variable -Option Constant -Name PROPTYPE_STRING -Value 4

# https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/ne-certenroll-x500nameflags
# https://docs.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.x500nameflags?view=hpc-sdk-5.1.6115
New-Variable -Option Constant -Name XCN_CERT_NAME_STR_NONE -Value 0
New-Variable -Option Constant -Name XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG -Value 0x80000
New-Variable -Option Constant -Name XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG -Value 0x100000

# https://blog.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_UNKNOWN -Value 0
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_OTHER_NAME -Value 1
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_RFC822_NAME -Value 2
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DIRECTORY_NAME -Value 5
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_URL -Value 7
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_IP_ADDRESS -Value 8
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_REGISTERED_ID -Value 9
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_GUID -Value 10
New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa379367(v=vs.85).aspx
New-Variable -Option Constant -Name XCN_OID_CRL_DIST_POINTS -Value '2.5.29.31'
New-Variable -Option Constant -Name XCN_OID_AUTHORITY_INFO_ACCESS -Value '1.3.6.1.5.5.7.1.1'

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
New-Variable -Option Constant -Name XCN_OID_ANY_APPLICATION_POLICY -Value "1.3.6.1.4.1.311.10.12.1"
New-Variable -Option Constant -Name XCN_OID_AUTO_ENROLL_CTL_USAGE -Value "1.3.6.1.4.1.311.20.1"
New-Variable -Option Constant -Name XCN_OID_DRM -Value "1.3.6.1.4.1.311.10.5.1"
New-Variable -Option Constant -Name XCN_OID_DS_EMAIL_REPLICATION -Value "1.3.6.1.4.1.311.21.19"
New-Variable -Option Constant -Name XCN_OID_EFS_RECOVERY -Value "1.3.6.1.4.1.311.10.3.4.1"
New-Variable -Option Constant -Name XCN_OID_EMBEDDED_NT_CRYPTO -Value "1.3.6.1.4.1.311.10.3.8"
New-Variable -Option Constant -Name XCN_OID_ENROLLMENT_AGENT -Value "1.3.6.1.4.1.311.20.2.1"
New-Variable -Option Constant -Name XCN_OID_IPSEC_KP_IKE_INTERMEDIATE -Value "1.3.6.1.5.5.8.2.2"
New-Variable -Option Constant -Name XCN_OID_KP_CA_EXCHANGE -Value "1.3.6.1.4.1.311.21.5"
New-Variable -Option Constant -Name XCN_OID_KP_CTL_USAGE_SIGNING -Value "1.3.6.1.4.1.311.10.3.1"
New-Variable -Option Constant -Name XCN_OID_KP_DOCUMENT_SIGNING -Value "1.3.6.1.4.1.311.10.3.12"
New-Variable -Option Constant -Name XCN_OID_KP_EFS -Value "1.3.6.1.4.1.311.10.3.4"
New-Variable -Option Constant -Name XCN_OID_KP_KEY_RECOVERY -Value "1.3.6.1.4.1.311.10.3.11"
New-Variable -Option Constant -Name XCN_OID_KP_KEY_RECOVERY_AGENT -Value "1.3.6.1.4.1.311.21.6"
New-Variable -Option Constant -Name XCN_OID_KP_LIFETIME_SIGNING -Value "1.3.6.1.4.1.311.10.3.13"
New-Variable -Option Constant -Name XCN_OID_KP_QUALIFIED_SUBORDINATION -Value "1.3.6.1.4.1.311.10.3.10"
New-Variable -Option Constant -Name XCN_OID_KP_SMARTCARD_LOGON -Value "1.3.6.1.4.1.311.20.2.2"
New-Variable -Option Constant -Name XCN_OID_KP_TIME_STAMP_SIGNING -Value "1.3.6.1.4.1.311.10.3.2"
New-Variable -Option Constant -Name XCN_OID_LICENSE_SERVER -Value "1.3.6.1.4.1.311.10.6.2"
New-Variable -Option Constant -Name XCN_OID_LICENSES -Value "1.3.6.1.4.1.311.10.6.1"
New-Variable -Option Constant -Name XCN_OID_NT5_CRYPTO -Value "1.3.6.1.4.1.311.10.3.7"
New-Variable -Option Constant -Name XCN_OID_OEM_WHQL_CRYPTO -Value "1.3.6.1.4.1.311.10.3.7"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_CLIENT_AUTH -Value "1.3.6.1.5.5.7.3.2"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_CODE_SIGNING -Value "1.3.6.1.5.5.7.3.3"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_EMAIL_PROTECTION -Value "1.3.6.1.5.5.7.3.4"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_IPSEC_END_SYSTEM -Value "1.3.6.1.5.5.7.3.5"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_IPSEC_TUNNEL -Value "1.3.6.1.5.5.7.3.6"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_IPSEC_USER -Value "1.3.6.1.5.5.7.3.7"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_OCSP_SIGNING -Value "1.3.6.1.5.5.7.3.9"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_SERVER_AUTH -Value "1.3.6.1.5.5.7.3.1"
New-Variable -Option Constant -Name XCN_OID_PKIX_KP_TIMESTAMP_SIGNING -Value "1.3.6.1.5.5.7.3.8"
New-Variable -Option Constant -Name XCN_OID_ROOT_LIST_SIGNER -Value "1.3.6.1.4.1.311.10.3.9"
New-Variable -Option Constant -Name XCN_OID_WHQL_CRYPTO -Value "1.3.6.1.4.1.311.10.3.5"

# Own Definition
New-Variable -Option Constant -Name XCN_OID_KP_KDC -Value "1.3.6.1.5.2.3.5"
New-Variable -Option Constant -Name XCN_OID_KP_RDC -Value "1.3.6.1.4.1.311.54.1.2"

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64HEADER -Value 0
New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1
New-Variable -Option Constant -Name XCN_CRYPT_STRING_BINARY -Value 2
New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64REQUESTHEADER -Value 3
New-Variable -Option Constant -Name XCN_CRYPT_STRING_HEX -Value 4

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-objectidgroupid
New-Variable -Option Constant -Name XCN_CRYPT_HASH_ALG_OID_GROUP_ID -Value 1

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-objectidpublickeyflags
New-Variable -Option Constant -Name XCN_CRYPT_OID_INFO_PUBKEY_ANY -Value 0

# https://docs.microsoft.com/en-us/windows/release-information/
New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_7 -Value 7601
New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_8_1 -Value 9600
New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_10 -Value 10240

# https://docs.microsoft.com/en-us/windows/win32/api/certpol/ne-certpol-x509scepdisposition
New-Variable -Option Constant -Name X509SCEPDisposition -Value @{
    SCEPDispositionUnknown = -1
    SCEPDispositionSuccess = 0
    SCEPDispositionFailure = 2
    SCEPDispositionPending = 3
    SCEPDispositionPendingChallenge = 11
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509privatekeyverify
New-Variable -Option Constant -Name X509PrivateKeyVerify -Value @{ 
    VerifyNone = 0
    VerifySilent = 1
    VerifySmartCardNone = 2
    VerifySmartCardSilent = 4
    VerifyAllowUI = 8
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-algorithmflags
New-Variable -Option Constant -Name AlgorithmFlags -Value @{
    AlgorithmFlagsNone = 0
    AlgorithmFlagsWrap = 1
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-installresponserestrictionflags
New-Variable -Option Constant -Name InstallResponseRestrictionFlags -Value @{
    AllowNone = 0
    AllowNoOutstandingRequest = 1
    AllowUntrustedCertificate = 2
    AllowUntrustedRoot = 4
}

# https://docs.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.x509enrollmentauthflags?view=hpc-sdk-5.1.6115
# https://gist.github.com/ctkirkman/77729328070ee1e1057fa1e2a64121a5
New-Variable -Option Constant -Name X509EnrollmentAuthFlags -Value  @{ 
    X509AuthNone = 0
    X509AuthAnonymous = 1
    X509AuthKerberos = 2
    X509AuthUsername = 4
    X509AuthCertificate = 8
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializefromcertificate
New-Variable -Option Constant -Name X509RequestInheritOptions -Value @{
    InheritDefault = 0x00000000
    InheritRenewalCertificateFlag = 0x00000020
    InheritTemplateFlag = 0x00000040
    InheritSubjectFlag = 0x00000080
    InheritExtensionsFlag = 0x00000100
    InheritSubjectAltNameFlag = 0x00000200   
}

# https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.4
New-Variable -Option Constant -Name SCEPFailInfo -Value @(

    @{
        Code = 0
        Message = "badAlg"
        Description = "Unrecognized or unsupported algorithm identifier"
    }
    @{
        Code = 1
        Message = "badMessageCheck"
        Description = "integrity check failed"
    }
    @{
        Code = 2
        Message = "badRequest"
        Description = "transaction not permitted or supported"
    }
    @{
        Code = 3
        Message = "badTime"
        Description = "The signingTime attribute from the PKCS#7 authenticatedAttributes was not sufficiently close to the system time."
    }
    @{
        Code = 4
        Message = "badCertId"
        Description = "No certificate could be identified matching the provided criteria."
    }

)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
New-Variable -Option Constant EkuNameToOidTable -Value @{

    EnrollmentAgent = $XCN_OID_ENROLLMENT_AGENT
    ClientAuthentication = $XCN_OID_PKIX_KP_CLIENT_AUTH
    CodeSigning = $XCN_OID_PKIX_KP_CODE_SIGNING
    DocumentSigning = $XCN_OID_KP_DOCUMENT_SIGNING
    EncryptingFileSystem = $XCN_OID_KP_EFS
    FileRecovery = $XCN_OID_EFS_RECOVERY
    IPSecEndSystem = $XCN_OID_PKIX_KP_IPSEC_END_SYSTEM
    IPSecIKEIntermediate = $XCN_OID_IPSEC_KP_IKE_INTERMEDIATE
    IPSecTunnelEndpoint = $XCN_OID_PKIX_KP_IPSEC_TUNNEL
    IPSecUser = $XCN_OID_PKIX_KP_IPSEC_USER
    KeyRecovery = $XCN_OID_KP_KEY_RECOVERY
    KDCAuthentication = $XCN_OID_KP_KDC
    SecureEmail = $XCN_OID_PKIX_KP_EMAIL_PROTECTION
    ServerAuthentication = $XCN_OID_PKIX_KP_SERVER_AUTH
    SmartCardLogon = $XCN_OID_KP_SMARTCARD_LOGON
    TimeStamping = $XCN_OID_PKIX_KP_TIMESTAMP_SIGNING
    OCSPSigning = $XCN_OID_PKIX_KP_OCSP_SIGNING
    RemoteDesktopAuthentication = $XCN_OID_KP_RDC
    PrivateKeyArchival = $XCN_OID_KP_CA_EXCHANGE
    
}

$ModuleRoot = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Import Public Functions
. $ModuleRoot\Functions\Get-NDESOTP.ps1
. $ModuleRoot\Functions\Get-NDESCertificate.ps1
. $ModuleRoot\Functions\New-CertificateRequest.ps1

# Import Private Functions
. $ModuleRoot\Functions\Test-KSPAvailability.ps1
. $ModuleRoot\Functions\Convert-DERToBASE64.ps1
. $ModuleRoot\Functions\Convert-StringToCertificateSerialNumber.ps1
. $ModuleRoot\Functions\Convert-StringToDER.ps1
. $ModuleRoot\Functions\Convert-StringToHex.ps1
. $ModuleRoot\Functions\Get-Asn1LengthOctets.ps1
. $ModuleRoot\Functions\New-AiaExtension.ps1
. $ModuleRoot\Functions\New-CdpExtension.ps1