function ConvertFrom-PemToBase64 {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$String
    )

    # Each armor line on its own, so the Base64 between them survives even when everything is on one line
    return $String -replace "-----(BEGIN|END) [^-]+-----", "" -replace "\s", ""
}