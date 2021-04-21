<#
    .SYNOPSIS
    Allows for un-archiving a previously archived Certificate.

    .PARAMETER Thumbprint
    The SHA-1 Thumbprint of the Certificate to be unarchived.

    .PARAMETER CertStoreLocation
    The Certificate Store Location of the Certificate to be unarchived.

    .OUTPUTS
    None.
#>

Function Undo-CertificateArchival {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Thumbprint,

        [Alias("Store")]
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Store]
        $CertStoreLocation
    )

    begin {}

    process {

        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($CertStoreLocation.Name -match "LocalMachine") {
    
            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }
        }

        $CertificateStore = Get-Item -Path $CertStoreLocation.Name

        $CertificateStore.Open('ReadWrite,IncludeArchived')

        $CertificateStore.Certificates | Where-Object { ($_.Thumbprint -eq $Thumbprint) } | ForEach-Object -Process {

            Write-Verbose -Message "Unarchiving Certificate with Thumbprint $Thumbprint"

            Try {
                $_.Archived = $False
            }
            Catch {
                Write-Error -Message $PSItem.Exception.Message
                return  
            }

        }

        $CertificateStore.Close()

    }

    end {}
}