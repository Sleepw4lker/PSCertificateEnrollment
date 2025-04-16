function Grant-PrivateKeyPermission {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_.HasPrivateKey) -and ($null -ne $_.PSParentPath)})]
        [Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[ \-_a-zA-Z0-9]{1,15}\\[ \-_a-zA-Z0-9]{1,15}\$?$')]
        [String]
        $Identity = "NT AUTHORITY\NETWORK SERVICE"
    )

    $Sid = (New-Object -TypeName Security.Principal.NTAccount($Identity)).Translate([System.Security.Principal.SecurityIdentifier]).Value

    if ($null -ne $Certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity) {

        # A CSP Key

        $CertificateStoreLocation = $Certificate.PSParentPath.Split("::")[1].Split("\")[0]
        $CertificateStoreName = $Certificate.PSParentPath.Split("::")[1].Split("\")[1]

        $CertificateStore = New-Object -TypeName Security.Cryptography.X509Certificates.X509Store($CertificateStoreName, $CertificateStoreLocation)

        $CertificateStore.Open("ReadWrite")

        $Certificate = $CertificateStore.Certificates | Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint }

        $NewParameters = New-Object -TypeName Security.Cryptography.CspParameters(
            $Certificate.PrivateKey.CspKeyContainerInfo.ProviderType, 
            $Certificate.PrivateKey.CspKeyContainerInfo.ProviderName, 
            $Certificate.PrivateKey.CspKeyContainerInfo.KeyContainerName)

        if ($CertificateStoreLocation.Equals("LocalMachine")) {
            $NewParameters.Flags = "UseExistingKey","UseMachineKeyStore"
        }
        else {
            $NewParameters.Flags = "UseExistingKey"
        }

        $NewParameters.CryptoKeySecurity = $Certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
        $NewParameters.KeyNumber = $Certificate.PrivateKey.CspKeyContainerInfo.KeyNumber

        $AccessRule = New-Object -TypeName Security.AccessControl.CryptoKeyAccessRule(
            $Sid,
            [System.Security.AccessControl.CryptoKeyRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow)

        $NewParameters.CryptoKeySecurity.AddAccessRule($AccessRule)

        [void](New-Object -TypeName Security.Cryptography.RSACryptoServiceProvider($NewParameters))

        $CertificateStore.Close()

    }
    else {

        # A KSP Key

        # Requires .NET 4.6 and works only on CNG Certificates
        # https://stackoverflow.com/questions/51018834/cngkey-assign-permission-to-machine-key
        $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)

        $NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr"
        $DACL_SECURITY_INFORMATION = 4

        $CngProperty = $PrivateKeyObject.Key.GetProperty($NCRYPT_SECURITY_DESCR_PROPERTY, $DACL_SECURITY_INFORMATION)

        $Security = New-Object -TypeName Security.AccessControl.CryptoKeySecurity
        $Security.SetSecurityDescriptorBinaryForm($CngProperty.GetValue())

        $AccessRule = New-Object -TypeName Security.AccessControl.CryptoKeyAccessRule(
            $Sid,
            [System.Security.AccessControl.CryptoKeyRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow)

        $Security.AddAccessRule($AccessRule)

        $NewCngProperty = New-Object -TypeName Security.Cryptography.CngProperty(
            $CngProperty.Name,
            $Security.GetSecurityDescriptorBinaryForm(),
            ([System.Security.Cryptography.CngPropertyOptions]::Persist -bor $DACL_SECURITY_INFORMATION))

        $PrivateKeyObject.Key.SetProperty($NewCngProperty)
    }
}