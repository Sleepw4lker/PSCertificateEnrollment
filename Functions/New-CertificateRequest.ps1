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

    .PARAMETER Eku
    Specifies or or more Enhanced Key Usage to be included in the Certificate Request.
    They get identified by their Friendly Name.
    Especially useful when creating a Certificate with the Cmdlet.

    .PARAMETER Dns
    Specifies one or more DNS Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, Upn or IP instead.

    .PARAMETER Upn
    Specifies one or more User Principal Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, DnsName or IP instead.

    .PARAMETER IP
    Specifies or more IP Addresses to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject, DnsName or Upn instead.

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

    .PARAMETER KeyLength
    Specifies the Key Length for the Key pair of the Certificate.
    Defaults to 2048 Bits RSA. ECC is not implemented as of now.

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
        $MachineContext = $False,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Subject,

        [Alias("EnhancedKeyUsage")]
        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "EnrollmentAgent",
            "ClientAuthentication",
            "CodeSigning",
            "DocumentSigning",
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

        [Alias("DnsName")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_ | ForEach-Object -Process {
            [System.Uri]::CheckHostName($_) -eq [System.UriHostnameType]::Dns
        }})]
        [String[]]
        $Dns,

        [Alias("UserPrincipalName")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Upn,

        [Alias("IPAddress")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [System.Net.IPAddress[]]
        $IP,

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
        [ValidateScript({Test-KSPAvailability -Name $_})]
        [String]
        $Ksp = "Microsoft Software Key Storage Provider",

        [Parameter(Mandatory=$False)]
        [ValidateScript({($_.HasPrivateKey) -and ($null -ne $_.PSParentPath)})]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $SigningCert,

        [Parameter(Mandatory=$False)]
        [ValidateSet(512,1024,3072,4096,8192)]
        [Int]
        $KeyLength = 2048,

        [Alias("Exportable")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $PrivateKeyExportable = $False,

        [Alias("Hash")]
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
        [ValidatePattern("^[0-9a-fA-F]{1,100}$")] # Why 100? RFC?
        [String]
        $SerialNumber,

        [Parameter(Mandatory=$False)]
        [ValidateSet("PrintableString","utf8")]
        [String]
        $SubjectEncoding = "PrintableString",

        [Parameter(Mandatory=$False)]
        [ValidateRange(-1,16)] # Should be sufficient...? RFC?
        [Int]
        $PathLength = -1, # -1 means none

        [Parameter(Mandatory=$False)]
        [Switch]
        $SelfSign
    )

    begin {}

    process {

        # Ensuring the Code will be executed on a supported Operating System
        # Operating Systems prior to Windows 8.1 don't contain the IX509SCEPEnrollment Interface
        If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_7) {
            Write-Error -Message "This must be executed on Windows 7/Windows Server 2008 R2 or newer!"
            return 
        }

        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($MachineContext.IsPresent) {
            
            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }
        }

        If ((-not $Dns) -and (-not $Upn) -and (-not $IP) -and ((-not $Subject) -or ($Subject -eq "CN="))) {
            Write-Error -Message "You must provide an Identity, either in Form ob a Subject or Subject Alternative Name!"
            return
        }

        # We first create the Private Key
        # Setting the Provider Attribute on the CertRequest Object afterwards seems not to work with Key Storage Providers...why?
        $PrivateKey = New-Object -ComObject 'X509Enrollment.CX509PrivateKey'
        
        $PrivateKey.ProviderName = $Ksp
        $PrivateKey.KeySpec = [int]($CA.IsPresent) + 1
        $PrivateKey.MachineContext = [int]($MachineContext.IsPresent)
        $PrivateKey.ExportPolicy = [int]($PrivateKeyExportable.IsPresent)
        $PrivateKey.Length = $KeyLength

        Try {
            $PrivateKey.Create()
        }
        Catch {
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($PrivateKey))
            Write-Error -Message $PSItem.Exception
            return
        }

        # Begin Assembling the Certificate Signing Request
        # https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/certificate-request-functions
        If (($SelfSign.IsPresent) -or ($SigningCert)) {
            # Enables you to create a certificate directly without applying to a certification authority (CA).
            $CertificateRequestObject = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate'
        }
        Else {
            # Represents a PKCS #10 certificate request. A PKCS #10 request can be sent directly to a CA, or it can be wrapped by a PKCS #7 or CMC request.
            $CertificateRequestObject = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestPkcs10'
        }

        $CertificateRequestObject.InitializeFromPrivateKey(
            [int]($MachineContext.IsPresent)+1,
            $PrivateKey, 
            [String]::Empty
        )

        # Determine if we shall encode Subject and Issuer in PrintableString
        # (Default for AD CS, non-default for CX509CertificateRequestCertificate) or UTF-8
        # This is required for matching with the CRL if you mess with a CA Key
        If ($SubjectEncoding -eq "PrintableString") {
            $SubjectEncodingFlag = $XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG
        }
        ElseIf ($SubjectEncoding -eq "utf8") {
            $SubjectEncodingFlag = $XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG
        }

        # Set Certificate Subject Name
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx

        Try {
            # To Do: implement Validation of the Subject RDN
            $SubjectDnObject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
            $SubjectDnObject.Encode(
                $Subject,
                $SubjectEncodingFlag
            )
            $CertificateRequestObject.Subject = $SubjectDnObject
        }
        Catch {
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertificateRequestObject))
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($SubjectDnObject))
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($PrivateKey))
            Write-Error -Message "Invalid Subject DN supplied!"
            return
        }

        If ($SelfSign.IsPresent) {
            # If thee Certificate is intended to be Self-Signed, it is its own Issuer
            $CertificateRequestObject.Issuer = $SubjectDnObject
        }

        If ($SigningCert) {

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376832(v=vs.85).aspx
            $SignerCertificate =  New-Object -ComObject 'X509Enrollment.CSignerCertificate'
            $SignerCertificate.Initialize(
                [int]($SigningCert.PSParentPath -match "Machine")+1,
                $X509PrivateKeyVerify.VerifyNone, # We did this already during Parameter Validation
                $XCN_CRYPT_STRING_BASE64,
                [Convert]::ToBase64String($SigningCert.RawData)
            )
            $CertificateRequestObject.SignerCertificate = $SignerCertificate

            # If we have a Signing Certificate, we copy its Subject to the Target Certificates Issuer
            $IssuerDnObject = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName'

            # We must have the DN encoded as printableString instead of UTF-8, otherwise CRL verification will fail
            # During certificate chain validation (from the end entity to a trusted root) the KeyId is used to create 
            # the certificate chain and it works independently of the subject and issuer codification (PrintableString or UTF8)
            # During revocation status validation, a binary comparison is made between the certificate issuer and the CRL issuer,
            # so both fields must use the same codification in order to match (PrintableString or UTF8)
            # https://social.technet.microsoft.com/Forums/windowsserver/en-US/0459983f-4f19-48ee-b099-dfd484483176/active-directory-certificate-services-cannot-verify-certificate-chain-bad-cert-issuer-base-crl?forum=winserversecurity
            # https://msdn.microsoft.com/en-us/library/windows/desktop/bb540814(v=vs.85).aspx
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx

            $IssuerDnObject.Encode(
                $SigningCert.Subject,
                $SubjectEncodingFlag
            )
            $CertificateRequestObject.Issuer = $IssuerDnObject

        }

        # These apply to all cases where a Certificate will be generated instead of a Signing Request
        If (($SelfSign.IsPresent) -or ($SigningCert)) {

            # Set Certificate Validity Period

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
            $CertificateRequestObject.NotBefore = $Now.AddMinutes($ClockSkew * -1)
            $CertificateRequestObject.NotAfter = $NotAfter.AddMinutes($ClockSkew) 

            # Set Serial Number of the Certificate if specified as Argument, otherwise use a random SN
            If ($SerialNumber) {

                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializedecode
                $CertificateRequestObject.SerialNumber.InvokeSet(
                    $(Convert-StringToCertificateSerialNumber -SerialNumber $SerialNumber), 
                    $XCN_CRYPT_STRING_BASE64
                )

            }

        }

        # Set the Key Usage Extension

        If ($CA.IsPresent) {

            # CA Certifcate Key Usages
            # Add these to the Parameters (if not $CA or look if different default Values can be applied)

            # https://security.stackexchange.com/questions/49229/root-certificate-key-usage-non-self-signed-end-entity
            # https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509keyusageflags(v=vs.110).aspx
            # Since a CA is supposed to issue certificate and CRL, it should have, on a general basis, the keyCertSign and cRLSign flags. 
            # These two flags are sufficient.
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsageFlags = "KeyCertSign, CrlSign"

        }
        Else {

            # Leaf Certificate Key Usages
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsageFlags = $KeyUsage

        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionkeyusage
        $KeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $KeyUsageExtension.InitializeEncode([Int]$KeyUsageFlags)
        $KeyUsageExtension.Critical = $True

        # Add the Key Usage Extension to the Certificate
        $CertificateRequestObject.X509Extensions.Add($KeyUsageExtension)

        # If we build a CA certificate, set Basic Constraints Extension
        If ($CA.IsPresent) {

            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionbasicconstraints
            $BasicConstraintsExtension = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

            $BasicConstraintsExtension.InitializeEncode(
                $True, # it is a CA
                $PathLength
            )

            # Only mark as critical if it is a CA certificate
            $BasicConstraintsExtension.Critical = $True

            # Adding the Extension to the Certificate
            $CertificateRequestObject.X509Extensions.Add($BasicConstraintsExtension)
        }

        # Set the Enhanced Key Usages Extension if specified as Argument
        If ($Eku) {
    
            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionenhancedkeyusage
            $EnhancedKeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
            $EnhancedKeyUsageOids = New-Object -ComObject X509Enrollment.CObjectIds.1

            $Eku | Sort-Object | Get-Unique | ForEach-Object -Process {

                $EnhancedKeyUsageOid = New-Object -ComObject X509Enrollment.CObjectId
                $EnhancedKeyUsageOid.InitializeFromValue($EkuNameToOidTable[$_])
                $EnhancedKeyUsageOids.Add($EnhancedKeyUsageOid)
    
            }

            $EnhancedKeyUsageExtension.InitializeEncode($EnhancedKeyUsageOids)

            # Adding the Extension to the Certificate
            $CertificateRequestObject.X509Extensions.Add($EnhancedKeyUsageExtension)

        }

        # Set the Subject Alternative Names Extension if specified as Argument
        If ($Upn -or $Dns -or $IP) {

            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionalternativenames
            $SubjectAlternativeNamesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

            Foreach ($Entry in $Upn) {
            
                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromString(
                    $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, 
                    $Entry
                )
                $Sans.Add($AlternativeNameObject)

            }

            Foreach ($Entry in $Dns) {
            
                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromString(
                    $XCN_CERT_ALT_NAME_DNS_NAME,
                    $Entry
                )
                $Sans.Add($AlternativeNameObject)

            }

            Foreach ($Entry in $IP) {

                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
                $AlternativeNameObject.InitializeFromRawData(
                    $XCN_CERT_ALT_NAME_IP_ADDRESS,
                    $XCN_CRYPT_STRING_BASE64,
                    [Convert]::ToBase64String($Entry.GetAddressBytes())
                )
                $Sans.Add($AlternativeNameObject)

            }
            
            $SubjectAlternativeNamesExtension.Critical = $True
            $SubjectAlternativeNamesExtension.InitializeEncode($Sans)

            # Adding the Extension to the Certificate
            $CertificateRequestObject.X509Extensions.Add($SubjectAlternativeNamesExtension)

        }
    
        # Set the Authority Key Identifier Extension if specified as Argument
        If ($Aki) {

            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionauthoritykeyidentifier
            $AkiExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAuthorityKeyIdentifier 

            # https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/nf-certenroll-ix509extensionauthoritykeyidentifier-initializeencode
            $AkiExtension.InitializeEncode(
                $XCN_CRYPT_STRING_BASE64, 
                $(Convert-DERToBASE64 -String $Aki)
            )

            # Adding the Extension to the Certificate
            $CertificateRequestObject.X509Extensions.Add($AkiExtension)

        }

        # Set the CRL Distribution Points Extension if specified as Argument
        If ($Cdp) {

            # No Interface for this OID, see https://msdn.microsoft.com/en-us/library/windows/desktop/aa378077(v=vs.85).aspx
            # Therefore, we will build the data by hand (Function New-CdpExtension)
            $CdpExtension = New-Object -ComObject X509Enrollment.CX509Extension
            $CdpExtensionOid = New-Object -ComObject X509Enrollment.CObjectId
            $CdpExtensionOid.InitializeFromValue($XCN_OID_CRL_DIST_POINTS)
            $CdpExtension.Critical = $False
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378511(v=vs.85).aspx
            $CdpExtension.Initialize(
                $CdpExtensionOid, 
                $XCN_CRYPT_STRING_BASE64, 
                $(New-CdpExtension -Url $Cdp)
            )

            # Adding the Extension to the Certificate
            $CertificateRequestObject.X509Extensions.Add($CdpExtension)

        }

        # Set the Authority Information Access Extension if specified as Argument
        If ($Aia) {

            # No Interface for this OID, see https://msdn.microsoft.com/en-us/library/windows/desktop/aa378077(v=vs.85).aspx
            # Therefore, we will build the data by hand (Function New-AiaExtension)
            $AiaExtension = New-Object -ComObject X509Enrollment.CX509Extension
            $AiaExtensionOid = New-Object -ComObject X509Enrollment.CObjectId
            $AiaExtensionOid.InitializeFromValue($XCN_OID_AUTHORITY_INFO_ACCESS)
            $AiaExtension.Critical = $False

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378511(v=vs.85).aspx
            $AiaExtension.Initialize(
                $AiaExtensionOid, 
                $XCN_CRYPT_STRING_BASE64, 
                $(New-AiaExtension -Url $Aia)
            )

            # Adding the Extension to the Certificate
            $CertificateRequestObject.X509Extensions.Add($AiaExtension)

        }

        # Specifying the Hashing Algorithm to use for the Request / the Certificate
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-iobjectid
        $HashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
        $HashAlgorithmObject.InitializeFromAlgorithmName(
            $XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
            $XCN_CRYPT_OID_INFO_PUBKEY_ANY,
            $AlgorithmFlags.AlgorithmFlagNone,
            $SignatureHashAlgorithm
        )
        $CertificateRequestObject.HashAlgorithm = $HashAlgorithmObject

        # Encoding the Certificate Signing Request
        Try {
            $CertificateRequestObject.Encode()
        }
        Catch {
            Write-Error -Message $PSItem.Exception
            return  
        }

        # Building the Certificate Request
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509enrollment
        $EnrollmentObject = New-Object -ComObject 'X509Enrollment.CX509Enrollment'
        $EnrollmentObject.InitializeFromRequest($CertificateRequestObject)
        $CertificateRequest = $EnrollmentObject.CreateRequest($XCN_CRYPT_STRING_BASE64REQUESTHEADER)

        # Either presenting the CSR, or signing ist as a Certificate
        If (($SelfSign.IsPresent) -or ($SigningCert)) {

            # Signing the Certificate
            $EnrollmentObject.InstallResponse(
                $InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                $CertificateRequest, 
                $XCN_CRYPT_STRING_BASE64REQUESTHEADER,
                [String]::Empty # No Password
            )

            # We load the Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CertificateObject.Import([Convert]::FromBase64String($EnrollmentObject.Certificate()))
            
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
        $CertificateRequestObject,
        $SubjectDnObject,
        $PrivateKey,
        $SignerCertificate,
        $IssuerDnObject,
        $BasicConstraintsExtension,
        $EnhancedKeyUsageExtension,
        $EnhancedKeyUsageOids,
        $EnhancedKeyUsageOid,
        $SubjectAlternativeNamesExtension,
        $Sans,
        $AlternativeNameObject,
        $AkiExtension,
        $CdpExtension,
        $CdpExtensionOid,
        $AiaExtension,
        $AiaExtensionOid,
        $HashAlgorithmObject,
        $EnrollmentObject | ForEach-Object -Process {

            Try {
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($_))
            }
            Catch {
                # we don't want to return anything here
            }
        }
    }

    end {}
}