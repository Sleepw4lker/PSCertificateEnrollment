function Unregister-ComObject {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [System.__ComObject]
        $ComObject
    )

    process {

        try {
            if ($null -ne $ComObject) {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject) | Out-Null
            }
        }
        catch {
            Write-Error "Failed to release COM object: $_"
        }
        finally {
            $ComObject = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
        }
    }
}