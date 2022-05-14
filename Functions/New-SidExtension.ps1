<#
    .SYNOPSIS
    Returns BASE64 Encoded DER Object for the CDP Extension
#>
Function New-SidExtension {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Sid
    )

    process {

        $Output = ''

        # Object Identifier 1.3.6.1.4.1.311.25.2.1
        $Output += "060A2B060104018237190201"

        # OCTET_STRING
        $Entry = Convert-StringToDER `
            -IdentifierOctets "04" `
            -ContentOctets $(Convert-StringtoHex -String $Sid)

        # Building the Nodes

        $Output += Convert-StringToDER `
            -IdentifierOctets "A0" `
            -ContentOctets $Entry

        $Output = Convert-StringToDER `
            -IdentifierOctets "A0" `
            -ContentOctets $Output
        
        $Output = Convert-StringToDER `
            -IdentifierOctets "30" `
            -ContentOctets $Output

        Convert-DERToBASE64 -String $Output

    }

}