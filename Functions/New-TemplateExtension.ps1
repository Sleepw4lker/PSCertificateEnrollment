function New-TemplateExtension {

    param(
        [Parameter(Mandatory = $true)]
        [String]
        $ObjectIdentifier,

        [Parameter(Mandatory = $false)]
        [Int]
        $MajorVersion = 100,

        [Parameter(Mandatory = $false)]
        [Int]
        $MinorVersion = 1
    )

    $TemplateExtension = New-Object -ComObject X509Enrollment.CX509ExtensionTemplate
    $TemplateOid = New-Object -ComObject X509Enrollment.CObjectId

    try {
        $TemplateOid.InitializeFromValue($ObjectIdentifier)
        $TemplateExtension.InitializeEncode($TemplateOid, $MajorVersion, $MinorVersion)

        return $TemplateExtension.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    }
    finally {
        $TemplateExtension | Unregister-ComObject
        $TemplateOid | Unregister-ComObject
    }
}