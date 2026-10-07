<#
    .SYNOPSIS
    Returns ASN.1 Length Octets for the Content Octets of a given Hex String Length
    See http://luca.ntop.org/Teaching/Appunti/asn1.html

    .PARAMETER HexStringLength
    The length, in characters, of the hex string representing the content octets (2 hex
    characters per byte). This is twice the actual object/byte length, and must be even.
#>
Function Get-Asn1LengthOctets {

    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNull()] # ValidateRange, what's the Maximum? Is int even sufficient?
        [ValidateScript({
            if ($_ % 2) {
                throw "HexStringLength must be even, as it represents a hex string (2 characters per byte). Got $_."
            }
            $True
        })]
        [int]
        $HexStringLength
    )

    <#
    Sample Output (Object/Byte Length -> Hex):
    127 -> 7F
    128 -> 8180 (First Number to use Long form)
    255 -> 81FF
    256 -> 820100 (First Number to spawn 2nd Octet)
    65535 -> 82FFFF
    65536 -> 83010000 (First Number to spawn 3rd Octet)
    Note: HexStringLength is twice the Object/Byte Length shown above (2 hex characters per byte).
    #>

    $ObjectLength = $HexStringLength / 2

    $NumBits = ([Convert]::ToString($ObjectLength,2)).Length
    $NumOctets = [int]([Math]::Ceiling($NumBits / 8))

    # 0...127 = one Octet
    If ($NumBits -le 7) {

        # - Short form (for lengths between 0 and 127). One octet.
        # Bit 8 has value "0" and bits 7-1 give the length.
        $HexObject = [String]::Format("{0:X2}", $ObjectLength)

    }
    Else {

        # - Long form. Two to 127 octets.

        # Second and following octets give the length, base 256, most significant digit first.
        $HexObject = [String]::Format("{0:X$($NumOctets * 2)}", $ObjectLength)

        # Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets.
        $HexObject = [String]::Format("{0:X2}", 128 + $NumOctets) + $HexObject
    }

    $HexObject
}