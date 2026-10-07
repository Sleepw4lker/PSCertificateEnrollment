<#
    .SYNOPSIS
    Creates a new Certificate Signing Request (CSR) based on the given Parameters.
    The CSR can directly be signed by a given Signing Certificate.
    Can also be used to create self-signed Certificates.

    .PARAMETER MachineContext
    By default, the Key for Certificate Request gets created in the current User's Context.
    By specifying this Parameter, it will be created as a Machine Key.
    You must execute the Command with Elevation (Run as Administrator) then.

    .PARAMETER Subject
    Specifies the Subject DN for the Certificate.
    May be left empty if you specify a DnsName, Upn or IP instead.

    .PARAMETER CertificateTemplate
    Specifies the Object Identifier of a Certificate Template to be written into the Certificate Template Information Extension.

    .PARAMETER Eku
    Specifies or or more Enhanced Key Usage to be included in the Certificate Request.
    They get identified by their Friendly Name.
    Especially useful when creating a Certificate with the Cmdlet.

    .PARAMETER AppPolicy
    Specifies one or more Application Policies to be included in the Certificate Request.
    They get identified by their Friendly Name.

    .PARAMETER Dns
    Specifies one or more DNS Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, Upn, Email or IP instead.

    .PARAMETER Upn
    Specifies one or more User Principal Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, DnsName, Email or IP instead.

    .PARAMETER Email
    Specifies one or more E-Mail addresses (RFC 822) to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, DnsName, Upn or IP instead.

    .PARAMETER IP
    Specifies or more IP Addresses to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, DnsName, Email or Upn instead.

    .PARAMETER Smime
    Specifies the S/MIME Capabilities the requestor supports.

    .PARAMETER Aki
    Specifies the Authority Key Identifier Attribute to be included in the Request.
    If supported by the CA, it will sign the Certificate Request with the specified Key instead of the default one.
    This is especially useful for creating OCSP Certificate Requests.

    .PARAMETER Cdp
    Specifies one or more URLs to be included in the CRL Distribution Points Extension.
    Especially useful when creating a Certificate with the Cmdlet.

    .PARAMETER Aia
    Specifies one or more URLs to be included in the Authority Information Access Extension.
    Especially useful when creating a Certificate with the Cmdlet.

    .PARAMETER KeyUsage
    Specified the Key Usage of the Certificate.
    This usually gets overwritten by the CA, therefore this is intended for creating a Certificate.
    Default is DigitalSignature for Leaf Certificates and keyCertSign plus keyCrlSign for CA Certificates.

    .PARAMETER Ksp
    Specifies the Cryptographic Service Provider (CSP) or Key Storage Provider (KSP) to be used for the Private Key of the Certificate.
    You can specify any CSP or KSP that is installed on the System.
    Defaults to the Microsoft Software Key Storage Provider.

    .PARAMETER SigningCert
    Specifies the Signing Certificate used to sign the Certificate Request and thus creating a certificate.

    .PARAMETER KeyAlgorithm
    Specifies the Algorithm to be used when creating the Key Pair.
    Defaults to "RSA".

    .PARAMETER KeyLength
    Specifies the Key Length for the Key pair of the Certificate.
    Gets applied only when KeyAlgorithm is "RSA".
    Defaults to 3072 Bits.

    .PARAMETER PrivateKeyExportable
    Specifies if the Private Key of the Certificate shall be marked as exportable.
    Defaults to the Key being not marked as exportable.

    .PARAMETER SignatureHashAlgorithm
    Specifies the Hash Algorithm that is being used to sign the Certificate Request or the Certificate.
    Defaults to SHA-256.

    .PARAMETER CA
    Instructs the CmdLet to include the bits relevant to a CA Certificate.

    .PARAMETER ValidityPeriod
    Specifies the Validity Period when creating a Certificate.
    Defaults to "Years".

    .PARAMETER ValidityPeriodUnits
    Specifies the Validity Period Unit when creating a Certificate.
    Defaults to 1.

    .PARAMETER ClockSkew
    Specifies the Clock Skew to use when creating a Certificate.
    Defaults to 10 (Minutes).

    .PARAMETER SerialNumber
    Specifies the Serial Number to use when creating a Certificate.
    Will use a random Serial Number if not specified.

    .PARAMETER SubjectEncoding
    Specifies the Subject Encoding to be used.
    Defaults to PrintableString.

    .PARAMETER PathLength
    Specifies the Path Length Constraint to be used when creating a CA Certificate.
    Defaults to none.

    .PARAMETER SelfSign
    Instructs the Cmdlet to Self-Sign the request, thus creating a Certificate.

    .PARAMETER OcspNoRevocationCheck
    Adds the id-pkix-ocsp-nocheck extension to the certificate request.

    .OUTPUTS
    System.String or System.Security.Cryptography.X509Certificates.X509Certificate.
    Either the BASE64-encoded Certificate Signing Request, or the Certificate as an Object.

#>
Function New-CertificateRequest {

    [cmdletbinding()]
    param (
        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Subject,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^([0-2])((\.0)|(\.[1-9][0-9]*))*$")]
        [String]
        $CertificateTemplate,

        [Alias("EnhancedKeyUsage")]
        [Parameter(Mandatory=$False)]
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
        $Eku,

        [Alias("ApplicationPolicy")]
        [Parameter(Mandatory=$False)]
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
        $AppPolicy,

        [Alias("DnsName")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $_ | ForEach-Object -Process {
                [System.Uri]::CheckHostName($_) -eq [System.UriHostnameType]::Dns
            }
        })]
        [String[]]
        $Dns,

        [Alias("UniformResourceIdentifier")]
        [Alias("Url")]
        [ValidateNotNullOrEmpty()]
        [System.Uri[]]
        $Uri,

        [Alias("UserPrincipalName")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Upn,

        [Alias("RFC822Name")]
        [Alias("E-Mail")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Email,

        [Alias("IPAddress")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [System.Net.IPAddress[]]
        $IP,

        [Alias("SmimeCapabilities")]
        [Parameter(Mandatory=$False)]
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
        $Smime,

        [Alias("SecurityIdentifier")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^S-1-5-21-[0-9]*-[0-9]*-[0-9]*-[0-9]*$")]
        [String]
        $Sid,

        [Alias("AuthorityKeyIdentifier")]
        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Aki,

        [Alias("CrlDistributionPoint")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()] # anyone has a http and ldap regex?
        [String[]]
        $Cdp,

        [Alias("AuthorityInformationAccess")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()] # anyone has a http and ldap regex?
        [String[]]
        $Aia,

        [Parameter(Mandatory=$False)]
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
        $KeyUsage = "DigitalSignature",

        [Alias("KeyStorageProvider")]
        [Parameter(Mandatory=$False)]
        [ValidateScript({
            $Ksp = $_
            [bool](Get-KeyStorageProvider | Where-Object { $_.Name -eq $Ksp })}
        )]
        [String]
        $Ksp = "Microsoft Software Key Storage Provider",

        [Parameter(Mandatory=$False)]
        [ValidateScript({($_.HasPrivateKey) -and ($null -ne $_.PSParentPath)})]
        [Security.Cryptography.X509Certificates.X509Certificate2]
        $SigningCert,

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "RSA",
            "ECDSA_P256",
            "ECDSA_P384",
            "ECDSA_P521",
            "ECDH_P256",
            "ECDH_P384",
            "ECDH_P521",
            "ML-DSA:44",
            "ML-DSA:65",
            "ML-DSA:87"
            )]
        [String]
        $KeyAlgorithm = "RSA",

        [Alias("KeySize")]
        [Parameter(Mandatory=$False)]
        [ValidateSet(512,1024,2048,3072,4096,8192)]
        [Int]
        $KeyLength = 3072,

        [Alias("Exportable")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $PrivateKeyExportable = $False,

        [Alias("Hash")]
        [Alias("HashAlgorithm")]
        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512")]
        [String]
        $SignatureHashAlgorithm = "SHA256",

        [Parameter(Mandatory=$False)]
        [Switch]
        $CA = $False,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $ValidityPeriod = "Years",

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,1000)]
        [Int]
        $ValidityPeriodUnits = 1,

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,1440)] # One Day should be more than enough 
        [Int]
        $ClockSkew = 10,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{1,40}$")]
        [String]
        $SerialNumber,

        [Parameter(Mandatory=$False)]
        [ValidateSet("PrintableString","utf8")]
        [String]
        $SubjectEncoding = "PrintableString",

        [Parameter(Mandatory=$False)]
        [ValidateRange(-1,16)]
        [Int]
        $PathLength = -1, # -1 means none

        [Parameter(Mandatory=$False)]
        [Switch]
        $SelfSign,

        [Parameter(Mandatory=$False)]
        [Switch]
        $OcspNoRevocationCheck
    )

    process {

        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($MachineContext.IsPresent) {
            
            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }
        }

        If ((-not $Dns) -and (-not $Uri) -and (-not $Upn) -and (-not $Email) -and (-not $IP) -and (-not $Subject)) {
            Write-Error -Message "You must provide an Identity, either in Form ob a Subject or Subject Alternative Name!"
            return
        }

        # We first create the Private Key
        # Setting the Provider Attribute on the CertRequest Object afterwards seems not to work with Key Storage Providers...why?
        $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
        
        $PrivateKey.ProviderName = $Ksp
        $PrivateKey.MachineContext = [int]($MachineContext.IsPresent)
        $PrivateKey.ExportPolicy = [int]($PrivateKeyExportable.IsPresent)
        
        If ($False -eq (Get-KeyStorageProvider | Where-Object { $_.Name -eq $Ksp }).LegacyCsp) {

            # The intended use is not identified. This value is set if the provider that supports the key is a 
            # Cryptography API: Next Generation (CNG) key storage provider (KSP).
            $PrivateKey.KeySpec = $X509KeySpec.XCN_AT_NONE

        }
        Else {

            # A Legacy CSP is being used

            # The key can be used for signing.
            $PrivateKey.KeySpec = $X509KeySpec.XCN_AT_SIGNATURE

            If (-not $CA.IsPresent) {

                $KeyUsage | ForEach-Object -Process {

                    If ($_ -in ("KeyEncipherment","KeyAgreement","DataEncipherment","EncipherOnly")) {

                        # The key can be used to encrypt (including key exchange) or sign depending on the algorithm. 
                        # For RSA algorithms, if this value is set, the key can be used for both signing and encryption. 
                        # For other algorithms, signing may not be supported. Further, only encryption for key exchange may be supported.
                        $PrivateKey.KeySpec = $X509KeySpec.XCN_AT_KEYEXCHANGE
                    }
                }
            }
        }

        If ($KeyAlgorithm -ne "RSA") {

            $Algorithm = New-Object -ComObject X509Enrollment.CObjectId

            $Algorithm.InitializeFromAlgorithmName(
                $ObjectIdGroupId.XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID,
                $ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                $AlgorithmFlags.AlgorithmFlagsNone,
                $KeyAlgorithm
            )

            $PrivateKey.Algorithm = $Algorithm

            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($Algorithm))
        }

        # Key Length is only relevant when Key Type is "RSA"
        If ($KeyAlgorithm -eq "RSA") {

            $PrivateKey.Length = $KeyLength
        }

        Try {
            $PrivateKey.Create()
        }
        Catch {
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($PrivateKey))
            Write-Error -Message $PSItem.Exception.Message
            return
        }

        # Begin Assembling the Certificate Signing Request
        If (($SelfSign.IsPresent) -or ($SigningCert)) {
            # Enables you to create a certificate directly without applying to a certification authority (CA).
            $CertificateRequestPkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
        }
        Else {
            # Represents a PKCS #10 certificate request. A PKCS #10 request can be sent directly to a CA, 
            # or it can be wrapped by a PKCS #7 or CMC request.
            $CertificateRequestPkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        }

        $CertificateRequestPkcs10.InitializeFromPrivateKey([int]($MachineContext.IsPresent)+1, $PrivateKey, [String]::Empty)

        # Determine if we shall encode Subject and Issuer in PrintableString
        # (Default for AD CS, non-default for CX509CertificateRequestCertificate) or UTF-8
        # This is required for matching with the CRL if you mess with a CA Key
        If ($SubjectEncoding -eq "PrintableString") {
            $SubjectEncodingFlag = $X500NameFlags.XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG
        }
        ElseIf ($SubjectEncoding -eq "utf8") {
            $SubjectEncodingFlag = $X500NameFlags.XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG
        }

        # Set Certificate Subject Name
        Try {
            $SubjectDnObject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
            $SubjectDnObject.Encode(
                $Subject,
                $SubjectEncodingFlag
            )
            $CertificateRequestPkcs10.Subject = $SubjectDnObject
        }
        Catch {
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertificateRequestPkcs10))
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($SubjectDnObject))
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($PrivateKey))
            Write-Error -Message "Invalid Subject Distinguished Name supplied!"
            return
        }

        If ($SelfSign.IsPresent) {
            $CertificateRequestPkcs10.Issuer = $SubjectDnObject
        }

        If ($SigningCert) {

            $SignerCertificate =  New-Object -ComObject X509Enrollment.CSignerCertificate
            $SignerCertificate.Initialize(
                [int]($SigningCert.PSParentPath -match "Machine"),
                $X509PrivateKeyVerify.VerifyNone, # We did this already during Parameter Validation
                $EncodingType.XCN_CRYPT_STRING_BASE64,
                [Convert]::ToBase64String($SigningCert.RawData)
            )
            $CertificateRequestPkcs10.SignerCertificate = $SignerCertificate

            # If we have a Signing Certificate, we copy its Subject to the Target Certificates Issuer
            $IssuerDnObject = New-Object -ComObject X509Enrollment.CX500DistinguishedName

            # We must have the DN encoded as printableString instead of UTF-8, otherwise CRL verification will fail
            # During certificate chain validation (from the end entity to a trusted root) the KeyId is used to create 
            # the certificate chain and it works independently of the subject and issuer codification (PrintableString or UTF8)
            # During revocation status validation, a binary comparison is made between the certificate issuer and the CRL issuer,
            # so both fields must use the same codification in order to match (PrintableString or UTF8)
            $IssuerDnObject.Encode($SigningCert.Subject, $SubjectEncodingFlag)
            $CertificateRequestPkcs10.Issuer = $IssuerDnObject

        }

        # These apply to all cases where a Certificate will be generated instead of a Signing Request
        If (($SelfSign.IsPresent) -or ($SigningCert)) {

            # Validity Periods are always written into the Cert as Universal Time
            $Now = (Get-Date).ToUniversalTime()

            Switch ($ValidityPeriod) {
                "Minutes"   { $NotAfter = $Now.AddMinutes($ValidityPeriodUnits) }
                "Hours"     { $NotAfter = $Now.AddHours($ValidityPeriodUnits) }
                "Days"      { $NotAfter = $Now.AddDays($ValidityPeriodUnits) }
                "Weeks"     { $NotAfter = $Now.AddWeeks($ValidityPeriodUnits) }
                "Months"    { $NotAfter = $Now.AddMonths($ValidityPeriodUnits) }
                "Years"     { $NotAfter = $Now.AddYears($ValidityPeriodUnits) }
            }

            # Backup $ClockSkew in Minutes (Default: 10) to avoid timing issues
            $CertificateRequestPkcs10.NotBefore = $Now.AddMinutes($ClockSkew * -1)
            $CertificateRequestPkcs10.NotAfter = $NotAfter.AddMinutes($ClockSkew) 

            # Set Serial Number of the Certificate if specified as Argument, otherwise use a random SN
            If ($SerialNumber) {

                $CertificateRequestPkcs10.SerialNumber.InvokeSet(
                    $(Convert-StringToCertificateSerialNumber -SerialNumber $SerialNumber), 
                    $EncodingType.XCN_CRYPT_STRING_BASE64
                )
            }
        }

        $X509Extensions = @{}

        # Set the Subject Alternative Names Extension if specified as Argument
        If ($Upn -or $Email -or $Dns -or $IP -or $Uri) {

            $SubjectAlternativeNamesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

            Foreach ($Entry in $Upn) {
            
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromString(
                    $AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, 
                    $Entry
                )
                $Sans.Add($AlternativeNameObject)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

            }

            Foreach ($Entry in $Email) {
            
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromString(
                    $AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME, 
                    $Entry
                )
                $Sans.Add($AlternativeNameObject)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

            }

            Foreach ($Entry in $Dns) {
            
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromString(
                    $AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                    $Entry
                )
                $Sans.Add($AlternativeNameObject)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

            }

            Foreach ($Entry in $Uri) {
            
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromString(
                    $AlternativeNameType.XCN_CERT_ALT_NAME_URL,
                    $Entry.ToString()
                )
                $Sans.Add($AlternativeNameObject)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

            }

            Foreach ($Entry in $IP) {

                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromRawData(
                    $AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS,
                    $EncodingType.XCN_CRYPT_STRING_BASE64,
                    [Convert]::ToBase64String($Entry.GetAddressBytes())
                )
                $Sans.Add($AlternativeNameObject)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

            }
            
            $SubjectAlternativeNamesExtension.Critical = $True
            $SubjectAlternativeNamesExtension.InitializeEncode($Sans)

            # Adding the Extension to the Certificate
            $CertificateRequestPkcs10.X509Extensions.Add($SubjectAlternativeNamesExtension)

        }

        If ($CA.IsPresent) {
            $KeyUsage = @("KeyCertSign", "CrlSign")

            # TODO: This should be critical
            $X509Extensions.Add($Oid.szOID_BASIC_CONSTRAINTS2, $(New-BasicConstraintsExtension -IsCA -PathLength $PathLength))
        }

        $X509Extensions.Add($Oid.szOID_KEY_USAGE, $(New-KeyUsageExtension -KeyUsage $KeyUsage))

        If ($CertificateTemplate) {
            $X509Extensions.Add($Oid.szOID_CERTIFICATE_TEMPLATE, $(New-TemplateExtension -ObjectIdentifier $CertificateTemplate))
        }

        If ($Eku) {
            $X509Extensions.Add($Oid.XCN_OID_ENHANCED_KEY_USAGE, $(New-ExtendedKeyUsageExtension -Eku $Eku))
        }

        If ($AppPolicy) {
            $X509Extensions.Add($Oid.szOID_APPLICATION_CERT_POLICIES, $(New-ApplicationPoliciesExtension -ApplicationPolicies $AppPolicy))
        }

        If ($Smime) {
            $X509Extensions.Add($Oid.SmimeCapabilities, $(New-SmimeCapabilitiesExtension -Smime $Smime))
        }

        If ($Aki) {
            $X509Extensions.Add($Oid.szOID_AUTHORITY_KEY_IDENTIFIER2, $(New-AkiExtension -Aki $Aki))
        }

        If ($Sid) {
            $X509Extensions.Add($Oid.szOID_NTDS_CA_SECURITY_EXT, $(New-SidExtension -Sid $Sid))
        }

        If ($Cdp) {
            $X509Extensions.Add($Oid.XCN_OID_CRL_DIST_POINTS, $(New-CdpExtension -Url $Cdp))
        }

        If ($Aia) {
            $X509Extensions.Add($Oid.XCN_OID_AUTHORITY_INFO_ACCESS, $(New-AiaExtension -Url $Aia))
        }

        If ($OcspNoRevocationCheck) {
            $X509Extensions.Add($Oid.OcspNoRevocationCheck, $null)
        }

        $X509Extensions.GetEnumerator() | ForEach-Object -Process {

            $X509Extension = New-Object -ComObject X509Enrollment.CX509Extension
            $X509ExtensionOid = New-Object -ComObject X509Enrollment.CObjectId

            try {
                $X509ExtensionOid.InitializeFromValue($_.Key)
                $X509Extension.Critical = $False # TODO: Support Critical Extensions
                $X509Extension.Initialize($X509ExtensionOid, $EncodingType.XCN_CRYPT_STRING_BASE64, $_.Value)
                $CertificateRequestPkcs10.X509Extensions.Add($X509Extension)
            }
            finally {
                $X509Extension | Unregister-ComObject
                $X509ExtensionOid | Unregister-ComObject
            }
        }

        # Specifying the Hashing Algorithm to use for the Request / the Certificate
        $HashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
        $HashAlgorithmObject.InitializeFromAlgorithmName(
            $ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
            $ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
            $AlgorithmFlags.AlgorithmFlagNone,
            $SignatureHashAlgorithm
        )
        $CertificateRequestPkcs10.HashAlgorithm = $HashAlgorithmObject

        $CertificateRequestPkcs10.Encode()

        # Building the Certificate Request
        $EnrollmentObject = New-Object -ComObject X509Enrollment.CX509Enrollment
        $EnrollmentObject.InitializeFromRequest($CertificateRequestPkcs10)
        $CertificateRequest = $EnrollmentObject.CreateRequest($EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER)

        # Either presenting the CSR, or signing ist as a Certificate
        If (($SelfSign.IsPresent) -or ($SigningCert)) {

            # Signing the Certificate
            $EnrollmentObject.InstallResponse(
                $InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                $CertificateRequest, 
                $EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER,
                [String]::Empty # No Password
            )

            # We load the Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $CertificateObject = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                [Convert]::FromBase64String($EnrollmentObject.Certificate()))
            
            # Return the resulting Certificate
            If ($MachineContext.IsPresent) {
                Get-ChildItem -Path "Cert:\LocalMachine\My\$($CertificateObject.Thumbprint)"
            }
            Else {
                Get-ChildItem -Path "Cert:\CurrentUser\My\$($CertificateObject.Thumbprint)"
            }

        }
        Else {
            # Return the Certificate Signing Request
            $CertificateRequest
        }

        # Cleaning up the COM Objects, avoiding any User Errors to be reported
        $CertificateRequestPkcs10,
        $SubjectDnObject,
        $PrivateKey,
        $SignerCertificate,
        $IssuerDnObject,
        $HashAlgorithmObject,
        $EnrollmentObject | Unregister-ComObject
    }

    end {}
}