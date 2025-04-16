function ConvertFrom-Base64ToPem {
        
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$String
    )

    return "-----BEGIN CERTIFICATE-----`n$(($String -split "(.{64})" | Where-Object {$_ -match '\S'}) -join "`n")`n-----END CERTIFICATE-----"
}