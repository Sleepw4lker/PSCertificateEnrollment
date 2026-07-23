function New-AkiExtension {

    param(
        [Parameter(Mandatory = $true)]
        [String]
        $Aki
    )

    process {

        $AkiExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAuthorityKeyIdentifier 

        try {

            $AkiExtension.InitializeEncode($EncodingType.XCN_CRYPT_STRING_BASE64, $(Convert-DERToBASE64 -String $Aki))

            return $AkiExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
        }
        finally {
            # Release the COM object to prevent memory leaks
            $AkiExtension | Unregister-ComObject
        }
    }
}