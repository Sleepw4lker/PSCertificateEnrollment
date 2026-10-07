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

        # A Cert: path like "Cert:\CurrentUser\My" arrives as an X509Store named after the whole path -
        # that one is opened through the Cert: drive. A real X509Store object is used as it is.
        $IsCertPath = $CertStoreLocation.Name -match '^Cert:\\'

        If ($IsCertPath) {
            $IsMachineStore = $CertStoreLocation.Name -match "LocalMachine"
        }
        Else {
            $IsMachineStore = $CertStoreLocation.Location -eq [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        }

        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($IsMachineStore) {
    
            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }
        }

        If ($IsCertPath) {
            $CertificateStore = Get-Item -Path $CertStoreLocation.Name
        }
        Else {
            $CertificateStore = $CertStoreLocation
        }

        $CertificateStore.Open('ReadWrite,IncludeArchived')

        Try {

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
        }
        Finally {
            $CertificateStore.Close()
        }

    }

    end {}
}