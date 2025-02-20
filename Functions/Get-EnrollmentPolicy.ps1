function Get-EnrollmentPolicy {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Identifier,

        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext
    )

    if ($MachineContext.IsPresent) {
        $RegistryRoot = "HKLM:\Software\Microsoft\Cryptography\PolicyServers"
    }
    else {
        $RegistryRoot = "HKCU:\Software\Microsoft\Cryptography\PolicyServers"
    }

    if ($Identifier) {
        Get-Item -Path "$RegistryRoot\$Identifier" -ErrorAction SilentlyContinue
    }
    else {
        Get-ChildItem -Path $RegistryRoot -ErrorAction SilentlyContinue
    }
}