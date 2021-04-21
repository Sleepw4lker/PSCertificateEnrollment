<#
    .SYNOPSIS
    Converts a DER String to a BASE64-encoded Byte Array
#>
Function Convert-DERToBASE64 {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $String
    )

    process {

        # Convert to Byte Array
        $ByteArray = $(

            For ($i = 0; $i -lt $String.length; $i += 2) {

                [byte]"0x$($String.SubString($i,2))"

            }

        )

        # Convert Byte Array to BASE64
        [Convert]::ToBase64String($ByteArray)

    }

}