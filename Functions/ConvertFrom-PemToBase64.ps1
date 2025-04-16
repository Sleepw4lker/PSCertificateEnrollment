function ConvertFrom-PemToBase64 {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$String
    )

    return $String -replace "-----.*-----", "" -replace "\r", "" -replace "\n", ""
}