<#
    .SYNOPSIS
    Allows for Submission of a Certificate Request to a Certification Authority.
    Allows for retrieval of a previously issued Certificate from a Certification Authority.

    .PARAMETER CertificateRequest
    The BASE64 encoded Certificate Request to be submitted to the Certification Authority.

    .PARAMETER RequestId
    The Request Identifier that was given to a previously submitted Certificate Request.

    .PARAMETER ConfigString
    The Configuration String for the Certificate Authority to connect to, either
    in the Form of "<Hostname>\<Common-Name-of-CA>" for a RPC/DCOM Enrollment or
    in for Form of "https://<Hostname>/<Common-Name-of-CA>_CES_<Authentication-Type>/service.svc/CES"
    for a WSTEP (Certificate Enrollment Web Service) Enrollment.

    .PARAMETER CertificateTemplate
    Optional: The name of the Certificate Template to request a Certificate from.
    Must be used if the Certificate request does not contain this information.

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
        [ValidateRange(1, [Int]::MaxValue)]
        [Int]
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
        $ClientCertificate,

        [Parameter(
            ParameterSetName="Submit",
            Mandatory=$False
            )]
        [String[]]
        $RequestAttributes
    )
    
    begin {}

    process {

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nn-certcli-icertrequest
        $CertRequest = New-Object -ComObject CertificateAuthority.Request

        # Configuring the Certificate Request Interface when using the WSTEP Protocol
        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest3-setcredential
        If ($ConfigString.StartsWith("https://")) { 

            # WSTEP with Username and Password Authentication
            If ($ConfigString.EndsWith(
                "UsernamePassword/service.svc/CES", 
                [System.StringComparison]::OrdinalIgnoreCase
                )) {

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
            If ($ConfigString.EndsWith(
                "Certificate/service.svc/CES", 
                [System.StringComparison]::OrdinalIgnoreCase
                )) {

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
            If ($ConfigString.EndsWith(
                "Kerberos/service.svc/CES", 
                [System.StringComparison]::OrdinalIgnoreCase
                )) {
    
                $CertRequest.SetCredential(
                    [Int]$null, # no Window Handle
                    $X509EnrollmentAuthFlags.X509AuthKerberos,
                    [String]::Empty,
                    [String]::Empty
                )

            }
        }

        # Submit a Certificate Request
        If ($CertificateRequest) {

            # Additional attributes can be specified here

            # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
            # Names and values must be colon separated, while multiple name, value pairs must be newline separated.
            # For example: CertificateTemplate:User\nEMail:User@Domain.com where the \n sequence is converted to a newline separator.

            If ($CertificateTemplate) {
                $RequestAttributes += "CertificateTemplate:$($CertificateTemplate)" # Names and values must be colon separated
            }

            Try {
                # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
                $Status = $CertRequest.Submit(
                    $RequestFlags.CR_IN_ENCODEANY,
                    $CertificateRequest,
                    $($RequestAttributes -join [Environment]::NewLine), # multiple name, value pairs must be newline separated.
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

        # Properly formatting Return Code and translate into a meaningful message
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

                # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getcertificate
                # https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.import
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

        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertRequest))

    }
    
    end {}
    
}