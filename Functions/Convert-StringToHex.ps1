Function Convert-StringToHex {

    # Converts each Character of a String to a Hexadecimal Representation of it's ASCII value
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            # Only ASCII (code points 0-255) can be represented as fixed-width 2-digit hex
            foreach ($Char in $_.ToCharArray()) {
                if ([int]$Char -gt 255) {
                    throw "String contains non-ASCII character '$Char' (code point $([int]$Char)), which cannot be represented as a fixed-width 2-digit hex value."
                }
            }
            $True
        })]
        [string]
        $String
    )

    process {

        $HexString = (

            $String.ToCharArray() | Foreach-Object -Process {

                [String]::Format("{0:X2}", [int]$_)

            }

        ) -join ''

        $HexString

    }

}