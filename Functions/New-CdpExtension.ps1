<#
    .SYNOPSIS
    Returns BASE64 Encoded DER Object for the CDP Extension
#>
Function New-CdpExtension {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Url
    )

    process {

        $Output = ''

        # Building the Nodes
        
        ForEach ($Entry in $Url) {

            # uniformResourceIdentifier
            $Output += Convert-StringToDER `
                -IdentifierOctets "86" `
                -ContentOctets $(Convert-StringtoHex -String $Entry)

        }

        # Encapsulating our Nodes

        # fullName 
        $Output = Convert-StringToDER `
            -IdentifierOctets "A0" `
            -ContentOctets $Output
        
        # distributionPoint
        $Output = Convert-StringToDER `
            -IdentifierOctets "A0" `
            -ContentOctets $Output
        
        # Inner Sequence
        $Output = Convert-StringToDER `
            -IdentifierOctets "30" `
            -ContentOctets $Output
        
        # Outer Sequence
        $Output = Convert-StringToDER `
            -IdentifierOctets "30" `
            -ContentOctets $Output

        Convert-DERToBASE64 -String $Output

    }

}