<#
    .SYNOPSIS
    Appends a Signature to a PKCS#10 Certificate Request by putting it into a signed PKCS#7 Message

    .PARAMETER CertificateRequest
    Takes a BASE64 encoded PKCS#10 Certificate Request

    .PARAMETER SigningCert
    Takes a Signing Certificate in form of an X509Certificate2 Object

    .PARAMETER RequesterName
    Optional Parameter to include a Requester Name in Form of DOMAIN\Username here
    This effectively makes it an Enroll on Behalf of (EOBO) Request

    .PARAMETER SignatureHashAlgorithm
    Specifies the Hash Algorithm that is being used to sign the Certificate Request or the Certificate.
    Defaults to SHA-256.

    .OUTPUTS
    BASE64-encoded PKCS#7 Certificate Request containing the signed PKCS#10 Certificate request
#>
function New-SignedCertificateRequest {

    [CmdletBinding()]
    param (

        [Parameter(
            Mandatory=$True,
            ValuefromPipeline=$True
            )]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateRequest,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_.HasPrivateKey) -and ($null -ne $_.PSParentPath)})]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $SigningCert,

        [Alias("Hash")]
        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512")]
        [String]
        $SignatureHashAlgorithm = "SHA256",

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^.*(\\|/)")]
        [String]
        $RequesterName

    )

    begin {
        # Signing a Certificate Request means wrapping the PKCS10 request inside a PKCS7 request
        # https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/certificate-request-functions
        $CertRequestPkcs10 = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestPkcs10'
        $CertRequestPkcs7 = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestPkcs7'
    }

    process {

        # First we must load the given Certificate Request
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializedecode
        Try {
            $CertRequestPkcs10.InitializeDecode(
                $CertificateRequest,
                $EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                )
        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return
        }
    
        # Build the PKCS#7 Message based on the PKCS#10 Certificate Request
        # https://stackoverflow.com/questions/7824408/programmatically-communicating-with-a-certificate-authority
        $CertRequestPkcs7.InitializeFromInnerRequest($CertRequestPkcs10)

        # Create a Signer Certificate Structure
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376832(v=vs.85).aspx
        $SignerCertificate =  New-Object -ComObject 'X509Enrollment.CSignerCertificate'
        $SignerCertificate.Initialize(
            [int]($SigningCert.PSParentPath -match "Machine"),
            $X509PrivateKeyVerify.VerifyNone, # We did this already during Parameter Validation
            $EncodingType.XCN_CRYPT_STRING_BASE64,
            [Convert]::ToBase64String($SigningCert.RawData)
        )
        $CertRequestPkcs7.SignerCertificate = $SignerCertificate

        # Append the Requester Name in Form of DOMAIN\Username here
        If ($RequesterName) {
            $CertRequestPkcs7.RequesterName = $RequesterName
        }

        # Specifying the Hashing Algorithm to use for the CMS message
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-iobjectid
        $HashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
        $HashAlgorithmObject.InitializeFromAlgorithmName(
            $ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
            $ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
            $AlgorithmFlags.AlgorithmFlagNone,
            $SignatureHashAlgorithm
        )
        $CertRequestPkcs7.HashAlgorithm = $HashAlgorithmObject
        
        # The request is encoded by using Distinguished Encoding Rules (DER) as defined by the Abstract Syntax Notation One (ASN.1) standard. 
        # The encoding process creates a byte array. You can retrieve the byte array by calling the RawData property.
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequest-encode
        $CertRequestPkcs7.Encode()

        # Return the signed Certificate Signing Request
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequest-get_rawdata
        "-----BEGIN PKCS #7 SIGNED DATA-----`n" + 
        $CertRequestPkcs7.RawData($RequestFlags.CR_OUT_BASE64) + 
        "-----END PKCS #7 SIGNED DATA-----"

    }

    end {
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequestPkcs10))
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequestPkcs7))
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($HashAlgorithmObject))
    }

}