Function Convert-StringToCertificateSerialNumber {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{1,100}$")] # Why 100?
        [String]
        $SerialNumber
    )

    process {

        # Building the Serialnumber of the Certificate
        # Kudos to https://www.sysadmins.lv/blog-en/self-signed-certificate-creation-with-powershell.aspx
        If ($SerialNumber.Length % 2) {
            $SerialNumber = "0" + $SerialNumber
        }

        $Bytes = $SerialNumber -split "(.{2})" | 
            Where-Object { $_ } | 
                ForEach-Object -Process {
                    
            [Convert]::ToByte($_,16)
        }

        $ByteString = [Convert]::ToBase64String($Bytes)

        return $ByteString
    }
    
}