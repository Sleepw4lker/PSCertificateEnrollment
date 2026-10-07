<#
    .SYNOPSIS
    Gets the currently configured Certificate for the Remote Desktop Session Host on the local System.

    .OUTPUTS
    The Certificate that is currently used by the local System for the Remote Desktop Session Host as an X509Certificate2 Object.
#>
function Get-RemoteDesktopCertificate {

    [CmdletBinding()]
    param()

    process {

        $Thumbprint = (Get-CimInstance `
            -ClassName "Win32_TSGeneralSetting" `
            -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SSLCertificateSHA1Hash

        # If no Certificate is set, we get "0000000000000000000000000000000000000000" returned.
        # Nothing at all comes back when the setting could not be read - without a thumbprint, the
        # store lookup below would list every certificate in the store.
        If ($Thumbprint -and ($Thumbprint -ne '0000000000000000000000000000000000000000')) {

            # It can either be in the My or the Remote Desktop Certificate Store
            "My","Remote Desktop" | ForEach-Object -Process {

                return (Get-ChildItem `
                    -Path Cert:\LocalMachine\$($_)\$Thumbprint `
                    -ErrorAction SilentlyContinue)

            }

        }
    }
}