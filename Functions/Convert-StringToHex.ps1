Function Convert-StringToHex {

    # Converts each Character of a String to a Hexadecimal Representation of it's ASCII value
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
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