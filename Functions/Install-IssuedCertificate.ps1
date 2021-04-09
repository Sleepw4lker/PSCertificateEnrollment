<#
    .SYNOPSIS
    Allows for installing a Certificate onto the local Machine after the 
    correspoiding certificate Request was approved by a Certification Authority.

    .PARAMETER Certificate
    The issued Certificate as an X509Certificate2 Data Type.

    .PARAMETER Path
    Path to a Certificate file on the disk.

    .PARAMETER MachineContext
    Specify this if the Certificate Request was created in the Machine Context as 
    opposed to the User Context.

    .OUTPUTS
    The issued Certificate as an X509Certificate2 Data Type.
#>

Function Install-IssuedCertificate {

    [cmdletbinding(DefaultParameterSetName="Certificate")]
    param(
        [Parameter(
            ParameterSetName="Certificate",
            Mandatory=$True,
            ValuefromPipeline = $True
            )]
        [ValidateNotNullorEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(
            ParameterSetName="Path",
            Mandatory=$True,
            ValuefromPipeline = $True
            )]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $Path,

        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext = $False
    )

    begin {
        $EnrollmentObject = New-Object -ComObject X509Enrollment.CX509Enrollment

        $EnrollmentObject.Initialize(
            [int]($MachineContext.IsPresent) + 1
        )
    }

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

        Try {
            If ($Path) {
                $Certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2
                $SigningCertificate.Import($Path)
            }
        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return  
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509enrollment-installresponse
        Try {

            $EnrollmentObject.InstallResponse(
                $InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                [Convert]::ToBase64String($Certificate.RawData),
                $EncodingType.XCN_CRYPT_STRING_BASE64,
                [String]::Empty
            )
        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return  
        }

        # Return the Certificate if successful
        $Certificate

    }

    end {
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($EnrollmentObject))
    }
}