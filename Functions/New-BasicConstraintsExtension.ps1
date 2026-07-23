function New-BasicConstraintsExtension {
    param(
        [Switch]
        $IsCA = $false,

        [Parameter(Mandatory = $false)]
        [Int]
        $PathLength = -1
    )

    $BasicConstraintsExtension = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

    try {

        $BasicConstraintsExtension.InitializeEncode($IsCA, $PathLength)
        $BasicConstraintsExtension.Critical = $True
        
        return $BasicConstraintsExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    }
    finally {
        $BasicConstraintsExtension | Unregister-ComObject
    }
}