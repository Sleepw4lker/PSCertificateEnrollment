<#
    .SYNOPSIS
    Allows for installing a Certificate onto the local Machine after the 
    correspoiding certificate Request was approved by a Certification Authority.

    .PARAMETER Certificate
    The issued Certificate as an X509Certificate2 Data Type.

    .PARAMETER Path
    Path to a Certificate file on the disk.

    .PARAMETER MachineContext
    Specify this if the Certificate Request was created in the Machine Context as opposed to the User Context.

    .PARAMETER Force
    Normally, installing untrusted Certificates would not be allowed. The -Force Argument allows installing 
    Certificates for which the Chain cannot be built or which do not chain to a trusted Root Certification Authority Certificate.

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

        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext,

        [Parameter(Mandatory=$False)]
        [Switch]
        $Force = $False,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FriendlyName
    )

    begin {}

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

        $EnrollmentObject = New-Object -ComObject X509Enrollment.CX509Enrollment

        $EnrollmentObject.Initialize(
            [int]($MachineContext.IsPresent) + 1
        )

        If ($Path) {

            Try { 
                $Certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2
                $Certificate.Import((Get-ChildItem -Path $Path).FullName) # This is to ensure the Path is always fully qualified
            }
            Catch {
                Write-Error -Message $PSItem.Exception.Message
                return  
            }
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509enrollment-installresponse
        Try {

            If ($Force.IsPresent) {
                $Flags = $InstallResponseRestrictionFlags.AllowUntrustedRoot
            }
            Else {
                $Flags = $InstallResponseRestrictionFlags.AllowNone
            }

            $EnrollmentObject.InstallResponse(
                $Flags,
                [Convert]::ToBase64String($Certificate.RawData),
                $EncodingType.XCN_CRYPT_STRING_BASE64,
                [String]::Empty
            )
        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return  
        }
        Finally {
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($EnrollmentObject))
        }

        if ($MachineContext.IsPresent) {
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My\$($Certificate.Thumbprint)"
        }
        else {
            $Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My\$($Certificate.Thumbprint)"
        }

        if ($FriendlyName) {
            $Certificate.FriendlyName = $FriendlyName
        }

        # Return the Certificate if successful
        $Certificate

    }

    end {}
}