<#
    .SYNOPSIS
    Returns BASE64 Encoded DER Object for the AIA Extension
#>
Function New-AiaExtension {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Url
    )

    process {

        $Output = ''
        
        # Building the Nodes
        
        ForEach ($Entry in $Url) {

            $AiaNode = ''

            # see https://www.sysadmins.lv/blog-en/how-to-encode-object-identifier-to-an-asn1-der-encoded-string.aspx
            # OIDs have special Encoding, but as it's always the same data in this case,
            # thus we wont write some fancy encoding routine for now

            # This is kind of a dirty Hack but Microsoft OCSP will always have this in the Url
            If ($Entry -match "/ocsp") {

                # On-line Certificate Status Protocol, OID 1.3.6.1.5.5.7.48.1, Code 06, Length 08
                $AiaNode += "06082B06010505073001"

            }
            Else {

                # Certification Authority Issuer, OID 1.3.6.1.5.5.7.48.2, Code 06, Length 08
                $AiaNode += "06082B06010505073002"

            }

            # uniformResourceIdentifier
            $AiaNode += Convert-StringToDER `
                -IdentifierOctets "86" `
                -ContentOctets $(Convert-StringtoHex -String $Entry)

            # Inner Sequence
            $AiaNode = Convert-StringToDER `
                -IdentifierOctets "30" `
                -ContentOctets $AiaNode

            $Output += $AiaNode

        }

        # Outer Sequence
        $Output = Convert-StringToDER `
            -IdentifierOctets "30" `
            -ContentOctets $Output

        Convert-DERToBASE64 -String $Output
    }

}