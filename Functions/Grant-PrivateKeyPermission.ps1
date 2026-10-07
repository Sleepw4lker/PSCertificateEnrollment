function Grant-PrivateKeyPermission {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({($_.HasPrivateKey) -and ($null -ne $_.PSParentPath)})]
        [Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[ \-_a-zA-Z0-9]{1,15}\\[ \-_a-zA-Z0-9]{1,15}\$?$')]
        [String]
        $Identity = "NT AUTHORITY\NETWORK SERVICE"
    )

    begin {

        $Sid = (New-Object -TypeName Security.Principal.NTAccount($Identity)).Translate([System.Security.Principal.SecurityIdentifier])

        # The legacy CSPs installed on this machine. .NET opens their keys through CNG as well, so
        # the provider name is what tells them apart from keys in a key storage provider.
        $CspNames = @(Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider" | ForEach-Object PSChildName)
    }

    process {

        if ($Certificate.PublicKey.Oid.Value.Equals("1.2.840.113549.1.1.1")) {
            $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        }
        else {
            $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
        }

        # Keys in a legacy CSP are out of reach: CNG cannot read their security descriptor, and the
        # CAPI route through CspKeyContainerInfo.CryptoKeySecurity asks for the SACL as well, which
        # needs SeSecurityPrivilege (and does not exist in .NET at all)
        if ($PrivateKeyObject.Key.Provider.Provider -in $CspNames) {
            Write-Error -Message "The private key of $($Certificate.Thumbprint) resides in the legacy CSP `"$($PrivateKeyObject.Key.Provider.Provider)`". Changing its permissions is not supported - use a key storage provider such as the Microsoft Software Key Storage Provider."
            return
        }

        $NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr"
        $DACL_SECURITY_INFORMATION = 4

        $GENERIC_READ = 0x80000000

        $CngProperty = $PrivateKeyObject.Key.GetProperty($NCRYPT_SECURITY_DESCR_PROPERTY, $DACL_SECURITY_INFORMATION)

        # CommonSecurityDescriptor rather than CryptoKeySecurity: the latter does not exist in .NET
        $Security = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor($false, $false, [byte[]]$CngProperty.GetValue(), 0)

        # Merges with an existing entry for the same identity, like AddAccessRule did
        $Security.DiscretionaryAcl.AddAccess(
            [System.Security.AccessControl.AccessControlType]::Allow,
            $Sid,
            $GENERIC_READ,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None)

        $SecurityDescriptor = New-Object -TypeName Byte[] -ArgumentList $Security.BinaryLength
        $Security.GetBinaryForm($SecurityDescriptor, 0)

        $NewCngProperty = New-Object -TypeName Security.Cryptography.CngProperty(
            $CngProperty.Name,
            $SecurityDescriptor,
            ([System.Security.Cryptography.CngPropertyOptions]::Persist -bor $DACL_SECURITY_INFORMATION))

        $PrivateKeyObject.Key.SetProperty($NewCngProperty)

        $Certificate
    }
}