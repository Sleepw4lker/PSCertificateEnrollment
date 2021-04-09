<#
    .SYNOPSIS
    Allows for Submission of a Certificate Request to a Certification Authority.
    Allows for retrieval of a previously issued Certificate from a Certification Authority.

    .PARAMETER CertificateRequest
    The BASE64 encoded Certificate Request to be submitted to the Certification Authority.

    .PARAMETER RequestId
    The Request Identifier that was given to a previously submitted Certificate Request.

    .PARAMETER ConfigString
    The Comnfiguration String for the Certificate Authority to connect to, 
    in the Form of "<Hostname>\<Common-Name-of-CA>" for a RPC/DCOM Enrollment and
    in for Form of "<https://<Hostname>/<Common-Name-of-CA>_CES_<Authentication-Type/service.svc/CES>"
    for a WSTEP (Certificate Enrollment Web Service) Enrollment.

    .PARAMETER CertificateTemplate
    Optional: The name of the Certificate Template to request a Certificate from.
    Must be used if the Certificate does not contain this information.

    .PARAMETER Credential
    Credentials when performing a WSTEP Enrollment with Username/Password Authentication.

    .PARAMETER ClientCertificate
    Thumbprint of an authentication Certificate when performing a WSTEP Enrollment with Client Certificate Authentication.

    .OUTPUTS
    An object representing the Enrollment/Retrieval result.
#>

Function Get-IssuedCertificate {

    [CmdletBinding()]
    param (

        [Parameter(
            ParameterSetName="Submit",
            Mandatory=$True,
            ValuefromPipeline=$True
            )]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateRequest,

        [Parameter(
            ParameterSetName="Retrieve",
            Mandatory=$True
            )]
        [ValidateRange(1,4294967295)] # According to ADCS Database Schema, maximum should be 32 Bit
        [System.Uint32]
        $RequestId,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ConfigString,
    
        [Parameter(
            ParameterSetName="Submit",
            Mandatory=$False
            )]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateTemplate,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $ClientCertificate
    )
    
    begin {

        $CertRequest = New-Object -ComObject CertificateAuthority.Request

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest3-setcredential
        # WSTEP with Username and Password Authentication
        If ($ConfigString.StartsWith("https://") -and 
            $ConfigString.EndsWith("UsernamePassword/service.svc/CES", [System.StringComparison]::OrdinalIgnoreCase)
        ) {

            If ($Credential) {

                $CertRequest.SetCredential(
                    [Int]$null, # no Window Handle
                    $X509EnrollmentAuthFlags.X509AuthUsername,
                    $Credential.UserName,
                    [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
                    )
                )

            }
            Else {
                Write-Error -Message "You must provide Authentication Credentials."
                return
            }
        }

        # WSTEP with Client Certificate Authentication
        If ($ConfigString.StartsWith("https://") -and 
            $ConfigString.EndsWith("Certificate/service.svc/CES", [System.StringComparison]::OrdinalIgnoreCase)
        ) {

            If ($ClientCertificate) {

                $CertRequest.SetCredential(
                    [Int]$null, # no Window Handle
                    $X509EnrollmentAuthFlags.X509AuthCertificate,
                    $ClientCertificate,
                    [String]::Empty
                )

            }
            Else {
                Write-Error -Message "You must provide a Client Authentication Certificate Thumbprint."
                return
            }
        }

        # WSTEP with Kerberos Authentication
        If ($ConfigString.StartsWith("https://") -and 
            $ConfigString.EndsWith("Kerberos/service.svc/CES", [System.StringComparison]::OrdinalIgnoreCase)
        ) {
 
            $CertRequest.SetCredential(
                [Int]$null, # no Window Handle
                $X509EnrollmentAuthFlags.X509AuthKerberos,
                [String]::Empty,
                [String]::Empty
            )

        }
    }
    
    process {

        # Submit a Certificate Request
        If ($CertificateRequest) {

            If ($CertificateTemplate) {
                $Attributes = "CertificateTemplate:$($CertificateTemplate)"
            }
            Else {
                $Attributes = [String]::Empty
            }

            Try {
                # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
                $Status = $CertRequest.Submit(
                    $RequestFlags.CR_IN_ENCODEANY,
                    $CertificateRequest,
                    $Attributes,
                    $ConfigString
                )
            }
            Catch {
                Write-Error -Message $PSItem.Exception.Message
                return
            }
        }

        # Retrieve a pending Certificate Request
        If ($RequestId) {

            Try {
                # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-retrievepending
                $Status = $CertRequest.RetrievePending(
                    $RequestId,
                    $ConfigString
                )
            }
            Catch {
                Write-Error -Message $PSItem.Exception.Message
                return
            }
        }

        $StatusCode = "0x" + ('{0:x}' -f $CertRequest.GetLastStatus())
        $StatusMessage = (New-Object System.ComponentModel.Win32Exception($CertRequest.GetLastStatus())).Message

        # Process the Submission Result and return it
        Switch ($Status) {

            $DispositionType.CR_DISP_INCOMPLETE {

                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "Request is incomplete"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $null
                    RawCertificate = $null
                }
            }
           
            $DispositionType.CR_DISP_ERROR {

                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "There was an error during submission"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $null
                    RawCertificate = $null
                }
            }

            $DispositionType.CR_DISP_DENIED {

                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "Request was denied"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $null
                    RawCertificate = $null
                }
            }

            $DispositionType.CR_DISP_ISSUED {

                $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $CertificateObject.Import(
                    [Convert]::FromBase64String(
                        $CertRequest.GetCertificate($RequestFlags.CR_OUT_BASE64)
                    )
                )

                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "Certificate was issued"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $CertificateObject
                    RawCertificate = $CertRequest.GetCertificate($RequestFlags.CR_OUT_BASE64HEADER)
                }
            }

            $DispositionType.CR_DISP_ISSUED_OUT_OF_BAND {

                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "Certificate was issued out of band"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $null
                    RawCertificate = $null
                }
            }

            $DispositionType.CR_DISP_UNDER_SUBMISSION {
                
                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "Request was taken under submission"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $null
                    RawCertificate = $null
                }
            }

            $DispositionType.CR_DISP_REVOKED {

                [PSCustomObject]@{
                    RequestId = $CertRequest.GetRequestId()
                    Disposition = $Status
                    Result = "Certificate has been revoked"
                    StatusCode = $StatusCode
                    StatusMessage = $StatusMessage
                    Certificate = $null
                    RawCertificate = $null
                }
            }

            # This should never happen, but just to be on the safe side
            default{
                Write-Error -Message "Retrieved unsupported Disposition Code $Status from the Certification Authority."
            }

        }

    }
    
    end {
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequest))
    }
}