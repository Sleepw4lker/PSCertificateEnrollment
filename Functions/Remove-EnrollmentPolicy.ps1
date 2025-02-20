function Remove-EnrollmentPolicy {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Identifier,

        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext
    )

    begin {}

    process {

        if ($MachineContext.IsPresent) {

            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }

            $RegistryRoot = "HKLM:\Software\Microsoft\Cryptography\PolicyServers"
        }
        else {
            $RegistryRoot = "HKCU:\Software\Microsoft\Cryptography\PolicyServers"
        }

        Remove-Item -Path "$RegistryRoot\$Identifier" -Force

    }

    end {}
}