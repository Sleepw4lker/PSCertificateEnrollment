<#
    .SYNOPSIS
    Enumerates all Cryptographic Service Providers (CSP) and Key Storage Providers (KSP) installed on the local machine.

    .OUTPUTS
    A list of the Cryptographic Service Providers (CSP) and Key Storage Providers (KSP) installed on the local machine.
#>
Function Get-KeyStorageProvider {

    [cmdletbinding()]
    param ()

    begin {
        $KspList = New-Object -ComObject X509Enrollment.CCspInformations
    }

    process {
        # Populate the List
        $KspList.AddAvailableCsps()

        # Return the List
        $KspList
    }

    end {
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($KspList))
    }
    
}