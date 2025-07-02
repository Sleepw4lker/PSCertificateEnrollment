# https://docs.microsoft.com/en-us/windows/release-information/
New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_7 -Value 7601
New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_8_1 -Value 9600
New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_10 -Value 10240

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-objectidgroupid
New-Variable -Option Constant -Name ObjectIdGroupId -Value @{
    XCN_CRYPT_ANY_GROUP_ID = 0
    XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 1
    XCN_CRYPT_FIRST_ALG_OID_GROUP_ID = 1
    XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2
    XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3
    XCN_CRYPT_SIGN_ALG_OID_GROUP_ID = 4
    XCN_CRYPT_LAST_ALG_OID_GROUP_ID = 4
    XCN_CRYPT_RDN_ATTR_OID_GROUP_ID = 5
    XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6
    XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7
    XCN_CRYPT_POLICY_OID_GROUP_ID = 8
    XCN_CRYPT_TEMPLATE_OID_GROUP_ID = 9
    XCN_CRYPT_KDF_OID_GROUP_ID = 10
    XCN_CRYPT_LAST_OID_GROUP_ID = 10
    XCN_CRYPT_OID_INFO_OID_GROUP_BIT_LEN_SHIFT = 16
    XCN_CRYPT_GROUP_ID_MASK = 65535
    XCN_CRYPT_OID_INFO_OID_GROUP_BIT_LEN_MASK = 268369920
    XCN_CRYPT_OID_DISABLE_SEARCH_DS_FLAG = 0x80000000
    XCN_CRYPT_KEY_LENGTH_MASK = 268369920
    XCN_CRYPT_OID_PREFER_CNG_ALGID_FLAG = 1073741824
}

#  https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-objectidpublickeyflags
New-Variable -Option Constant -Name ObjectIdPublicKeyFlags -Value @{
    XCN_CRYPT_OID_INFO_PUBKEY_ANY = 0
    XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = 0x80000000
    XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = 0x40000000 
}

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest2-getcaproperty
New-Variable -Option Constant -Name PropType -Value @{
    PROPTYPE_LONG = 1
    PROPTYPE_DATE = 2
    PROPTYPE_BINARY = 3
    PROPTYPE_STRING = 4
}

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394.aspx
New-Variable -Option Constant -Name X500NameFlags -Value @{
    XCN_CERT_NAME_STR_NONE = 0
    XCN_CERT_SIMPLE_NAME_STR = 1
    XCN_CERT_OID_NAME_STR = 2
    XCN_CERT_X500_NAME_STR = 3
    XCN_CERT_XML_NAME_STR = 4
    XCN_CERT_NAME_STR_SEMICOLON_FLAG = 0x40000000
    XCN_CERT_NAME_STR_NO_PLUS_FLAG = 0x20000000
    XCN_CERT_NAME_STR_NO_QUOTING_FLAG = 0x10000000
    XCN_CERT_NAME_STR_CRLF_FLAG = 0x8000000
    XCN_CERT_NAME_STR_COMMA_FLAG = 0x4000000
    XCN_CERT_NAME_STR_REVERSE_FLAG = 0x2000000
    XCN_CERT_NAME_STR_FORWARD_FLAG = 0x1000000
    XCN_CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG = 0x10000
    XCN_CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG = 0x20000
    XCN_CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = 0x40000
    XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = 0x80000
    XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG = 0x100000
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-objectidgroupid
New-Variable -Option Constant -Name Oid -Value @{

    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379367(v=vs.85).aspx
    XCN_OID_CRL_DIST_POINTS = '2.5.29.31'
    XCN_OID_AUTHORITY_INFO_ACCESS = '1.3.6.1.5.5.7.1.1'
    XCN_OID_ENHANCED_KEY_USAGE = "2.5.29.37"
    XCN_OID_SUBJECT_ALT_NAME2 =  "2.5.29.17"
    XCN_OID_FRESHEST_CRL = "2.5.29.46"
    XCN_OID_CERTSRV_CA_VERSION = "1.3.6.1.4.1.311.21.1"
    XCN_OID_CRL_NEXT_PUBLISH = "1.3.6.1.4.1.311.21.4"
    
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
    XCN_OID_ANY_APPLICATION_POLICY = "1.3.6.1.4.1.311.10.12.1"
    XCN_OID_AUTO_ENROLL_CTL_USAGE = "1.3.6.1.4.1.311.20.1"
    XCN_OID_DRM = "1.3.6.1.4.1.311.10.5.1"
    XCN_OID_DS_EMAIL_REPLICATION = "1.3.6.1.4.1.311.21.19"
    XCN_OID_EFS_RECOVERY = "1.3.6.1.4.1.311.10.3.4.1"
    XCN_OID_EMBEDDED_NT_CRYPTO = "1.3.6.1.4.1.311.10.3.8"
    XCN_OID_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
    XCN_OID_IPSEC_KP_IKE_INTERMEDIATE = "1.3.6.1.5.5.8.2.2"
    XCN_OID_KP_CA_EXCHANGE = "1.3.6.1.4.1.311.21.5"
    XCN_OID_KP_CTL_USAGE_SIGNING = "1.3.6.1.4.1.311.10.3.1"
    XCN_OID_KP_DOCUMENT_SIGNING = "1.3.6.1.4.1.311.10.3.12"
    XCN_OID_KP_EFS = "1.3.6.1.4.1.311.10.3.4"
    XCN_OID_KP_KEY_RECOVERY = "1.3.6.1.4.1.311.10.3.11"
    XCN_OID_KP_KEY_RECOVERY_AGENT = "1.3.6.1.4.1.311.21.6"
    XCN_OID_KP_LIFETIME_SIGNING = "1.3.6.1.4.1.311.10.3.13"
    XCN_OID_KP_QUALIFIED_SUBORDINATION = "1.3.6.1.4.1.311.10.3.10"
    XCN_OID_KP_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    XCN_OID_KP_TIME_STAMP_SIGNING = "1.3.6.1.4.1.311.10.3.2"
    XCN_OID_LICENSE_SERVER = "1.3.6.1.4.1.311.10.6.2"
    XCN_OID_LICENSES = "1.3.6.1.4.1.311.10.6.1"
    XCN_OID_NT5_CRYPTO = "1.3.6.1.4.1.311.10.3.7"
    XCN_OID_OEM_WHQL_CRYPTO = "1.3.6.1.4.1.311.10.3.7"
    XCN_OID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    XCN_OID_PKIX_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
    XCN_OID_PKIX_KP_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
    XCN_OID_PKIX_KP_IPSEC_END_SYSTEM = "1.3.6.1.5.5.7.3.5"
    XCN_OID_PKIX_KP_IPSEC_TUNNEL = "1.3.6.1.5.5.7.3.6"
    XCN_OID_PKIX_KP_IPSEC_USER = "1.3.6.1.5.5.7.3.7"
    XCN_OID_PKIX_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
    XCN_OID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    XCN_OID_PKIX_KP_TIMESTAMP_SIGNING = "1.3.6.1.5.5.7.3.8"
    XCN_OID_ROOT_LIST_SIGNER = "1.3.6.1.4.1.311.10.3.9"
    XCN_OID_WHQL_CRYPTO = "1.3.6.1.4.1.311.10.3.5"

    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionsmimecapabilities
    XCN_OID_OIWSEC_desCBC = "1.3.14.3.2.7"
    XCN_OID_RSA_DES_EDE3_CBC = "1.2.840.113549.3.7"
    XCN_OID_RSA_RC2CBC = "1.2.840.113549.3.2"
    XCN_OID_RSA_RC4 = "1.2.840.113549.3.4"
    XCN_OID_RSA_SMIMEalgCMS3DESwrap = "1.2.840.113549.1.9.16.3.6"
    XCN_OID_RSA_SMIMEalgCMSRC2wrap = "1.2.840.113549.1.9.16.3.7"
    XCN_OID_NIST_AES128_CBC = "2.16.840.1.101.3.4.1.2"
    XCN_OID_NIST_AES192_CBC = "2.16.840.1.101.3.4.1.22"
    XCN_OID_NIST_AES256_CBC = "2.16.840.1.101.3.4.1.42"
    XCN_OID_NIST_AES128_WRAP = "2.16.840.1.101.3.4.1.5"
    XCN_OID_NIST_AES192_WRAP = "2.16.840.1.101.3.4.1.25"
    XCN_OID_NIST_AES256_WRAP = "2.16.840.1.101.3.4.1.45"

    # Own Definition
    XCN_OID_KP_KDC = "1.3.6.1.5.2.3.5"
    XCN_OID_KP_RDC = "1.3.6.1.4.1.311.54.1.2"
    XCN_OID_KP_DOCUMENT_ENCRYPTION = "1.3.6.1.4.1.311.80.1"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
    md5NoSign = "1.2.840.113549.2.5"
    sha1NoSign = "1.3.14.3.2.26"
    sha256NoSign = "2.16.840.1.101.3.4.2.1"
    sha384NoSign = "2.16.840.1.101.3.4.2.2"
    sha512NoSign = "2.16.840.1.101.3.4.2.3"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/e168a474-7de2-421c-b460-91adf87692a3
    szOID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"

    OcspNoRevocationCheck = "1.3.6.1.5.5.7.48.1.5"
}

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest2-getfullresponseproperty
New-Variable -Option Constant -Name FullResponseProperty -Value @{
    FR_PROP_NONE = 0
    FR_PROP_FULLRESPONSE = 1
    FR_PROP_STATUSINFOCOUNT = 2
    FR_PROP_BODYPARTSTRING = 3
    FR_PROP_STATUS = 4
    FR_PROP_STATUSSTRING = 5
    FR_PROP_OTHERINFOCHOICE = 6
    FR_PROP_FAILINFO = 7
    FR_PROP_PENDINFOTOKEN = 8
    FR_PROP_PENDINFOTIME = 9
    FR_PROP_ISSUEDCERTIFICATEHASH = 10
    FR_PROP_ISSUEDCERTIFICATE = 11
    FR_PROP_ISSUEDCERTIFICATECHAIN = 12
    FR_PROP_ISSUEDCERTIFICATECRLCHAIN = 13
    FR_PROP_ENCRYPTEDKEYHASH = 14
    FR_PROP_FULLRESPONSENOPKCS7 = 15
    FR_PROP_CAEXCHANGECERTIFICATEHASH = 16
    FR_PROP_CAEXCHANGECERTIFICATE = 17
    FR_PROP_CAEXCHANGECERTIFICATECHAIN = 18
    FR_PROP_CAEXCHANGECERTIFICATECRLCHAIN = 19
    FR_PROP_ATTESTATIONCHALLENGE = 20
    FR_PROP_ATTESTATIONPROVIDERNAME = 21
}

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getcertificate
# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/CertCli.h
New-Variable -Option Constant -Name RequestFlags -Value @{
    CR_IN_BASE64HEADER = 0
    CR_IN_BASE64 = 1
    CR_IN_BINARY = 2
    CR_IN_ENCODEANY = 0xff
    CR_IN_MACHINE = 0x100000
    CR_OUT_BASE64HEADER = 0
    CR_OUT_BASE64 = 1
    CR_OUT_BINARY = 2
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-alternativenametype
New-Variable -Option Constant -Name AlternativeNameType -Value @{
    XCN_CERT_ALT_NAME_UNKNOWN = 0
    XCN_CERT_ALT_NAME_OTHER_NAME = 1
    XCN_CERT_ALT_NAME_RFC822_NAME = 2
    XCN_CERT_ALT_NAME_DNS_NAME = 3
    XCN_CERT_ALT_NAME_DIRECTORY_NAME = 5
    XCN_CERT_ALT_NAME_URL = 7
    XCN_CERT_ALT_NAME_IP_ADDRESS = 8
    XCN_CERT_ALT_NAME_REGISTERED_ID = 9
    XCN_CERT_ALT_NAME_GUID = 10
    XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME = 11
}

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
New-Variable -Option Constant -Name DispositionType -Value @{
    CR_DISP_INCOMPLETE = 0
    CR_DISP_ERROR = 1
    CR_DISP_DENIED = 2
    CR_DISP_ISSUED = 3
    CR_DISP_ISSUED_OUT_OF_BAND = 4
    CR_DISP_UNDER_SUBMISSION = 5
    CR_DISP_REVOKED = 6
}

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
New-Variable -Option Constant -Name EncodingType -Value @{
    XCN_CRYPT_STRING_NOCR = [Int]::MinValue
    XCN_CRYPT_STRING_BASE64HEADER = 0
    XCN_CRYPT_STRING_BASE64 = 1
    XCN_CRYPT_STRING_BINARY = 2
    XCN_CRYPT_STRING_BASE64REQUESTHEADER = 3
    XCN_CRYPT_STRING_HEX = 4
    XCN_CRYPT_STRING_HEXASCII = 5
    XCN_CRYPT_STRING_BASE64_ANY = 6
    XCN_CRYPT_STRING_ANY = 7
    XCN_CRYPT_STRING_HEX_ANY = 8
    XCN_CRYPT_STRING_BASE64X509CRLHEADER = 9
    XCN_CRYPT_STRING_HEXADDR = 10
    XCN_CRYPT_STRING_HEXASCIIADDR = 11
    XCN_CRYPT_STRING_HEXRAW = 12
    XCN_CRYPT_STRING_BASE64URI = 13
    XCN_CRYPT_STRING_ENCODEMASK = 255
    XCN_CRYPT_STRING_CHAIN = 256
    XCN_CRYPT_STRING_TEXT = 512
    XCN_CRYPT_STRING_PERCENTESCAPE = 134217728
    XCN_CRYPT_STRING_HASHDATA = 268435456
    XCN_CRYPT_STRING_STRICT = 536870912
    XCN_CRYPT_STRING_NOCRLF = 1073741824
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509keyspec
New-Variable -Option Constant -Name X509KeySpec -Value @{
    XCN_AT_NONE = 0
    XCN_AT_KEYEXCHANGE = 1
    XCN_AT_SIGNATURE = 2
}

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

# https://docs.microsoft.com/en-us/windows/win32/api/certcli/ne-certcli-x509enrollmentauthflags
# https://docs.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.x509enrollmentauthflags
# https://gist.github.com/ctkirkman/77729328070ee1e1057fa1e2a64121a5
New-Variable -Option Constant -Name X509EnrollmentAuthFlags -Value  @{ 
    X509AuthNone = 0
    X509AuthAnonymous = 1
    X509AuthKerberos = 2
    X509AuthUsername = 4
    X509AuthCertificate = 8
}

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificateenrollmentcontext
New-Variable -Option Constant -Name X509CertificateEnrollmentContext -Value  @{ 
    ContextNone = 0
    ContextUser = 1
    ContextMachine = 2
    ContextAdministratorForceMachine = 3
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

# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-enrollmentenrollstatus
New-Variable -Option Constant -Name EnrollmentEnrollStatus -Value @{
    Enrolled = 0x00000001
    EnrollPended = 0x00000002
    EnrollUIDeferredEnrollmentRequired = 0x00000004
    EnrollError = 0x00000010
    EnrollUnknown = 0x00000020
    EnrollSkipped = 0x00000040
    EnrollDenied = 0x00000100 
}

# https://docs.microsoft.com/bs-latn-ba/windows/win32/api/certenroll/ne-certenroll-innerrequestlevel
New-Variable -Option Constant -Name InnerRequestLevel -Value @{
    LevelInnermost = 0
    LevelNext = 1
}

# https://docs.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_run_flags
New-Variable -Option Constant -Name TaskRunFlags -Value @{
    TASK_RUN_NO_FLAGS = 0
    TASK_RUN_AS_SELF = 1
    TASK_RUN_IGNORE_CONSTRAINTS = 2
    TASK_RUN_USE_SESSION_ID = 3
    TASK_RUN_USER_SID = 4
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

# Built from the Error Codes I observed whilst testing Get-NDESCertificate
# Stored as String as this gets compared against a text that is returned from the API
New-Variable -Option Constant -Name NDESErrorCode -Value @{
    CERT_E_WRONG_USAGE = "0x800b0110"
    TRUST_E_CERT_SIGNATURE = "0x80096004"
    ERROR_NOT_FOUND = "0x80070490"
    CERTSRV_E_BAD_REQUESTSUBJECT = "0x80094001"
    RPC_S_SERVER_UNAVAILABLE = "0x800706ba"
}

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
New-Variable -Option Constant -Name EkuNameToOidTable -Value @{
    EnrollmentAgent = $Oid.XCN_OID_ENROLLMENT_AGENT
    ClientAuthentication = $Oid.XCN_OID_PKIX_KP_CLIENT_AUTH
    CodeSigning = $Oid.XCN_OID_PKIX_KP_CODE_SIGNING
    LifeTimeSigning = $Oid.XCN_OID_KP_LIFETIME_SIGNING
    DocumentSigning = $Oid.XCN_OID_KP_DOCUMENT_SIGNING
    DocumentEncryption = $Oid.XCN_OID_KP_DOCUMENT_ENCRYPTION
    EncryptingFileSystem = $Oid.XCN_OID_KP_EFS
    FileRecovery = $Oid.XCN_OID_EFS_RECOVERY
    IPSecEndSystem = $Oid.XCN_OID_PKIX_KP_IPSEC_END_SYSTEM
    IPSecIKEIntermediate = $Oid.XCN_OID_IPSEC_KP_IKE_INTERMEDIATE
    IPSecTunnelEndpoint = $Oid.XCN_OID_PKIX_KP_IPSEC_TUNNEL
    IPSecUser = $Oid.XCN_OID_PKIX_KP_IPSEC_USER
    KeyRecovery = $Oid.XCN_OID_KP_KEY_RECOVERY
    KDCAuthentication = $Oid.XCN_OID_KP_KDC
    SecureEmail = $Oid.XCN_OID_PKIX_KP_EMAIL_PROTECTION
    ServerAuthentication = $Oid.XCN_OID_PKIX_KP_SERVER_AUTH
    SmartCardLogon = $Oid.XCN_OID_KP_SMARTCARD_LOGON
    TimeStamping = $Oid.XCN_OID_PKIX_KP_TIMESTAMP_SIGNING
    OCSPSigning = $Oid.XCN_OID_PKIX_KP_OCSP_SIGNING
    RemoteDesktopAuthentication = $Oid.XCN_OID_KP_RDC
    PrivateKeyArchival = $Oid.XCN_OID_KP_CA_EXCHANGE
}

New-Variable -Option Constant -Name SmimeCapabilityToOidTable -Value @{
    des = $Oid.XCN_OID_OIWSEC_desCBC
    des3 = $Oid.XCN_OID_RSA_DES_EDE3_CBC
    rc2 = $Oid.XCN_OID_RSA_RC2CBC
    rc4 = $Oid.XCN_OID_RSA_RC4
    des3wrap = $Oid.XCN_OID_RSA_SMIMEalgCMS3DESwrap
    rc2wrap = $Oid.XCN_OID_RSA_SMIMEalgCMSRC2wrap
    aes128 = $Oid.XCN_OID_NIST_AES128_CBC
    aes192 = $Oid.XCN_OID_NIST_AES192_CBC
    aes256 = $Oid.XCN_OID_NIST_AES256_CBC
    aes128wrap = $Oid.XCN_OID_NIST_AES128_WRAP
    aes192wrap = $Oid.XCN_OID_NIST_AES192_WRAP
    aes256wrap = $Oid.XCN_OID_NIST_AES256_WRAP
    md5 = $Oid.md5noSign
    sha1 = $Oid.sha1noSign
    sha256 = $Oid.sha256noSign
    sha384 = $Oid.sha384noSign
    sha512 = $Oid.sha512noSign
}

$ModuleRoot = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Import Public Functions
. $ModuleRoot\Functions\Get-NDESOTP.ps1
. $ModuleRoot\Functions\Get-SCEPCertificate.ps1
. $ModuleRoot\Functions\Get-KeyStorageProvider.ps1
. $ModuleRoot\Functions\Get-IssuedCertificate.ps1
. $ModuleRoot\Functions\New-CertificateRequest.ps1
. $ModuleRoot\Functions\New-SignedCertificateRequest.ps1
. $ModuleRoot\Functions\Install-IssuedCertificate.ps1
. $ModuleRoot\Functions\Undo-CertificateArchival.ps1
. $ModuleRoot\Functions\Get-RemoteDesktopCertificate.ps1
. $ModuleRoot\Functions\Set-RemoteDesktopCertificate.ps1
. $ModuleRoot\Functions\Invoke-AutoEnrollmentTask.ps1
. $ModuleRoot\Functions\Get-ESTCertificate.ps1
. $ModuleRoot\Functions\Get-ESTCACertificates.ps1
. $ModuleRoot\Functions\Get-XCEPEnrollmentPolicy.ps1
. $ModuleRoot\Functions\New-EnrollmentPolicy.ps1
. $ModuleRoot\Functions\Get-EnrollmentPolicy.ps1
. $ModuleRoot\Functions\Remove-EnrollmentPolicy.ps1
. $ModuleRoot\Functions\Clear-EnrollmentPolicyCache.ps1
. $ModuleRoot\Functions\Get-WSTEPResponse.ps1
. $ModuleRoot\Functions\Grant-PrivateKeyPermission.ps1
. $ModuleRoot\Functions\Get-PGWYCertificate.ps1

# Import Private Functions
. $ModuleRoot\Functions\Convert-DERToBASE64.ps1
. $ModuleRoot\Functions\Convert-StringToCertificateSerialNumber.ps1
. $ModuleRoot\Functions\Convert-StringToDER.ps1
. $ModuleRoot\Functions\Convert-StringToHex.ps1
. $ModuleRoot\Functions\Get-Asn1LengthOctets.ps1
. $ModuleRoot\Functions\Get-Hash.ps1
. $ModuleRoot\Functions\New-AiaExtension.ps1
. $ModuleRoot\Functions\New-CdpExtension.ps1
. $ModuleRoot\Functions\New-SanExtension.ps1
. $ModuleRoot\Functions\New-SidExtension.ps1
. $ModuleRoot\Functions\Invoke-PGWYPKCS10Operation.ps1
. $ModuleRoot\Functions\Get-CertificateByThumbprint.ps1
. $ModuleRoot\Functions\ConvertFrom-Base64ToPem.ps1
. $ModuleRoot\Functions\ConvertFrom-PemToBase64.ps1
. $ModuleRoot\Functions\New-SignedCms.ps1