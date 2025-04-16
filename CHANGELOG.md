# Changelog for the PSCertificateEnrollment PowerShell Module

## 1.0.11 (tbd)

- New `Get-PGWYCertificate` Commandlet allows requesting certificates from [Nexus SmartID Certificate Manager](https://doc.nexusgroup.com/pub/certificate-manager-overview) and [Nexus Go](https://www.nexusgroup.com/solutions/online-services/) instances via the [Certificate Manager (CM) REST API](https://doc.nexusgroup.com/pub/certificate-manager-cm-rest-api).
- New `New-EnrollmentPolicy`, `Get-EnrollmentPolicy` and `Remove-EnrollmentPolicy` Commandlets allow managing Enrollment Policies on Windows Clients to be used with MS-XCEP and MS-WSTEP.
- New `Grant-PrivateKeyPermission` Commandlet allows setting private Key permissions. 
- `Clear-XCEPEnrollmentPolicyCache` has been renamed to `Clear-EnrollmentPolicyCache`, but an Alias has been kept.
- `New-CertificateRequest` now supports a `-CertificateTemplate` argument which allows sppecifying the Object Identifier of a certificate template and build the V2 Certificate Template extension out of it and add it to the Certificate Request. This allows specifying the certificate template when requesting for certificates over MS-WCCE or MS-WSTEP.
- `Get-CertificateHash` has been renamed to `Get-Hash`.
- `Get-ESTCertificate` now uses a PSCredential instead of a plaintext password.
- Code base has been fixed to properly work with PowerShell Core.

## 1.0.10 (Feb 11, 2025)

- `Get-NDESCertificate` is renamed to `Get-SCEPCertificate` (as it works perfectly well with other SCEP server implementations). `Get-NDESCertificate` is kept as an Alias for backwards compatibility.
- `Invoke-AutoEnrollmentTask` now has a `-Wait` argument to pause further script execution unti the Task has finished.
- New `Get-ESTCAcertificates` Commandlet allows retrieval of CA certificates against an RFC 7030 compliant EST-server.
- New `Get-ESTCertificate` Commandlet allows requesting certificates against an RFC 7030 compliant EST-server, currently limited to the `simpleenroll` and `simplereenroll` operations and only using HTTP Basic Authentication.
- New `Get-XCEPEnrollmentPolicy` Commandlet allows to dump the protocol response from a MS-XCEP server (aka Microsoft CEP) for further analysis and troubleshooting.
- New `Get-WSTEPResponse` Commandlet allows to dump the protocol response from a MS-WSTEP server (aka Microsoft CES) for further analysis and troubleshooting
- New `Clear-XCEPEnrollmentPolicyCache` Commandlet allows to clear User and Machine policy cache for MS-XCEP (aka Microsoft CEP).

## 1.0.9 (May 30, 2023)

- `Get-IssuedCertificate` now supports the UniformResourceIdentifier SAN type.
- `Get-IssuedCertificate` now supports the id-pkix-ocsp-nocheck Extension with the OcspNoRevocationCheck parameter.

## 1.0.8 (Dec 19, 2022)

- `Get-IssuedCertificate` now supports requesting certificates using the machine's identity.

## 1.0.7 (Dec 13, 2022)

- `Get-IssuedCertificate` now supports request attributes.
- Add StatusCodeInt property to `Get-IssuedCertificate` containing the HResult returned from the certificate authority as integer.
- Add alias "Config" für ConfigurationString Argument to `Get-IssuedCertificate`.
- `New-CertificateRequest` now supports the newly introduced Security Identifier certificate extension.
- `Get-NDESCertificate` now supports ECC keys.
- `Get-NDESCertificate` now supports HTTP basic authentication.

## 1.0.6 (Feb 14, 2022)

- Fixed an error in the NuGet Package for PowerShell Gallery.

## 1.0.5 (Feb 14, 2022)

- Ported documentation from Markdown to ASCIIDoc.
- Include changelog with project.
- `Invoke-AutoEnrollmentTask` allows to trigger the scheduled tasks for certificate autoenrollment (both user and machine task).
- `New-CertificateRequest` 
  - now uses 3072 bit key length by default.
  - correctly specifies the KeySpec for use with legacy Cryptographic Service Providers (CSP).
- `Get-NDESCertificate` now uses 3072 bit key length by default.
- `New-SignedCertificateRequest` allows specifying the hash algorithm to use for the CMS message.
- `Install-IssuedCertificate`
  - added a "-Machine" alias for the "-MachineContext" parameter.
  - now features a "-Force" parameter.
- Ensure correct execution if PowerShell Core is installed (loading the module on pwsh is getting prevented).
- Fixed some typos in synopsis of some commands.
- `New-CertificateRequest` allows for empty subject distringusied names.
- `Get-NDESCertificate` allows for empty subject distringusied names.

## 1.0.4 (May 06, 2021)

- All included script files are now digitally signed. Using the module with restrictive PowerShell execution policy (e.g. AllSigned) is possible (if the signer certificate is trusted).
- `Get-RemoteDesktopCertificate` can be used to identify the active remote desktop certificate on a system.
- `Set-RemoteDesktopCertificate` can be used to specify the active remote desktop certificate on a system.
- `New-CertificateRequest` dows not contain the lifetime signing extended key usage.
- `Get-IssuedCertificate` refactored for proper error handling of the WSTEP protocol.

## 1.0.3 (Apr 21, 2021)

- Fixed an issue with the digital signature of the package that was published to PowerShell gallery.
- Unified all file's encodings (UTF-8 with byte order mark).
- `Get-CertificateHash` sometimes (when the calculated hash contained zeroes) returned an incorrect result, therefore `Get-NDESCertificate` could not be used in sime environments, because the root certification authoritie's MD5 hash was wrong.

## 1.0.2 (Apr 09, 2021)

- Removed compatibility requirements from module definition and reduced minimum PowerShell version to 4.0 to make it compatible with Windows 8.1 and Windows 2012 without further updates.
- New Commands
  - `Get-KeyStorageProvider` lists Cryptographic Service Providers (CSP) and Key Storage Provider (KSP) installed on the system.
  - `Get-IssuedCertificate` can be used to submit certificate requests to online certification authorities, and to retrieve pending certificate requests by specifying the Request ID.
  - `Install-IssuedCertificate` can be used to install a previously requested certificate after it has been issued by and retrieved from the certification authority.
  - `Undo-CertificateArchival` can be used to un-archive a certificate that has the archive bit set.
  - `New-SignedCertificateRequest` signs a PKCS#10 certificate request with a given (usually enrollment agent) certificate, and returns a PKCS#7 message.
- Improvements for `New-CertificateRequest`
  - The command can now also generate keys using elliptic curves (ECDH/ECDSA)
  - Add the "Document Encryption" enhanced key usage
  - Verification if a given Key Storage Provider exists is now handled by `Get-KeyStorageProvider`
- Improvements for `Get-NDESCertificate`
  - Verification if a given Key Storage Provider exists is now handled by `Get-KeyStorageProvider`

## 1.0.1 (Mar 21, 2021)

- Improvements for `New-CertificateRequest`
  - Enabled to specify 512 bit in KeyLength parameter.
  - Enabled to specify the pre-selected 2048 bit in KeyLength parameter..
  - Signing certificates do not raise an error any more.
  - Enhanced the verification routine if the specified Key Storage Provider actually exists.
- Improvements for `Get-NDESCertificate`
  - Enabled to specify 512 bit in KeyLength parameter.
  - Enabled to specify the pre-selected 2048 bit in KeyLength parameter..
  - Signing certificates do not raise an error any more.
  - Enhanced the verification routine if the specified Key Storage Provider actually exists.
  - Added the alias "Exportable" for the "PrivateKeyExportable" argument.
  - Moved calculation of the MD5 hash for the root certification authority certificate from .NET method X509Certificate2.GetCertHash to own function `Get-Hash` to ensure compatbility with .NET versions below 4.7.