<#
    .SYNOPSIS
    Sets the Certificate for the Remote Desktop Session Host on the local System.

    .PARAMETER Certificate
    The Certificate that is desired to be used by the local System for the Remote Desktop Session Host as an X509Certificate2 Object.
    Must reside in the "My" Folder of the machine Certificate Store.
    Must have a private Key associated.
    Must contain either the Server Authentication or the Remote Desktop Authentication Enhanced Key Usage.

    .OUTPUTS
    Returns True as a boolean Value on success.
#>
function Set-RemoteDesktopCertificate {
    
    [CmdletBinding()]
    param(
        [Parameter(
            ValuefromPipeline=$True,
            Mandatory=$True
        )]
        [ValidateScript({
            ($_.HasPrivateKey) -and 
            ($_.PSParentPath -match "LocalMachine\\My") -and 
            (
                ($_.EnhancedKeyUsageList.ObjectId -contains $Oid.XCN_OID_PKIX_KP_SERVER_AUTH) -or
                ($_.EnhancedKeyUsageList.ObjectId -contains $Oid.XCN_OID_KP_RDC)
            )
        })]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    begin {}

    process {

        If (-not (
            [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error -Message "This must be run with Elevation (Run as Administrator)!" 
            return
        }

        Try {

            $TerminalServicesConfig = Get-CimInstance `
                -ClassName "Win32_TSGeneralSetting" `
                -Namespace root\cimv2\terminalservices `
                -Filter "TerminalName='RDP-tcp'"

            [void](Set-CimInstance -CimInstance $TerminalServicesConfig -Property @{SSLCertificateSHA1Hash="$($Certificate.Thumbprint)"})

            return $True

        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return
        }

    }

    end {}
}