# PSCertificateEnrollment

PowerShell Module for various PKI-related tasks like:
* Creating Certificate Signing requests
* Creating Self-Signed Certificates or Certificates signed with a given Key
* Signing a Certificate Request with an Enrollment Agent Certificate prior to Submission to a Certification Authority
* Submitting Certificate Requests to a Certification Aurhority and retrieving the response
* Installing issued Certificates
* Requesting or Renewing User or Machine Certificates via the [Simple Certificate Enrollment Protocol (SCEP)](https://tools.ietf.org/html/draft-nourse-scep-23)

The module can be obtained via the [PowerShell Gallery](https://www.powershellgallery.com/packages/PSCertificateEnrollment).

It is built out of pure PowerShell Script Code (using .NET and Win32 API). No wrapping of any "certutil" or "openssl" command. No additional binary Code necessary to deploy.

Supported Operating Systems

* Windows 8.1
* Windows 10
* Windows Server 2012 R2
* Windows Server 2016
* Windows Server 2019

Earlier Windows Version since Windows Vista/Server 2008 may work, but are not supported.

`Get-NDESCertificate` will definitely not work on Windows Operating Systems below 8.1/Server 2012 R2.

PowerShell Core and therefore Linux are also not supported, as the Win32 API is not available on these.

## Supported Commands

The following Commands are available:
* `Get-NDESOTP`
* `Get-NDESCertificate`
* `Get-IssuedCertificate`
* `New-CertificateRequest`
* `New-SignedCertificateRequest`
* `Install-IssuedCertificate`
* `Get-KeyStorageProvider`
* `Undo-CertificateArchival`

### Get-NDESOTP

`Get-NDESOTP` retrieves an One-Time-Password (OTP) from the NDES Server.

Uses SSL by default. SSL can be disabled if required, but this is not recommended.

Uses your Windows Identity by default but can also be passed a PSCredential Object (Get-Credential).

The -PasswordLength Parameter must be adjusted if you do not use the default 8-Character Passwords on the NDES (as it's only RegEx grabbing the HTML Output).

Example: Retrieving a NDES One-Time Password

```powershell
Get-NDESOTP `
-ComputerName 'ndes01.intra.adcslabor.de' `
-Credential $(Get-Credential)
```

### Get-NDESCertificate

`Get-NDESCertificate` creates and submits an NDES Certificate Request using the IX509SCEPEnrollment Interface available in Windows 8.1 and higher, and retrieves the issued Certificate. The issued Certificate directly gets installed into the respective Certificate store.

It supports Renewal Mode by passing an X509Certificate Object either via the Pipeline or the -SigningCertificate Argument. The Certificate must have a private Key, and be issued from the same CA as the new one.

It supports SSL, but doesnt use it by default (not necessary as sensitive Data is protected anyway).

It supports the following Server-side Implementations of the SCEP protocol:

* Microsoft Network Device Enrollment Service (NDES)

Other SCEP Implementations should be easy to implement but I currently have none to test against.

Example: Performing a SCEP Certificate Request using a previously-obtained Challenge Request

```powershell
Get-NDESCertificate `
-ComputerName "ndes01.intra.adcslabor.de" `
-Subject "CN=Test" `
-ChallengePassword "BDE00774A789610F"
```

Example: Performing a SCEP Renewal Request (renewing an existing Certificate via SCEP)

```powershell
Get-ChildItem -Path Cert:\CurrentUser\My\85CF977C7E32CE808E9D92C61FDB9A43437DC4A2 | 
Get-NDESCertificate -ComputerName "ndes01.intra.adcslabor.de"
```

### New-CertificateRequest

`New-CertificateRequest` builds a Certificate Request based on the given Arguments. Can also create self-signed Certificates as well as directly sign the request with a different Key.

You can specify the following Enhanced Key Usages (EKUs) by their friendly name:
  * `EnrollmentAgent`
  * `ClientAuthentication`
  * `CodeSigning`
  * `DocumentSigning`
  * `DocumentEncryption`
  * `EncryptingFileSystem`
  * `FileRecovery`
  * `IPSecEndSystem`
  * `IPSecIKEIntermediate`
  * `IPSecTunnelEndpoint`
  * `IPSecUser`
  * `KeyRecovery`
  * `KDCAuthentication`
  * `SecureEmail`
  * `ServerAuthentication`
  * `SmartCardLogon`
  * `TimeStamping`
  * `OCSPSigning`
  * `RemoteDesktopAuthentication`
  * `PrivateKeyArchival`

Example: Creating a PKI Hierarchy in a 3-Liner

```powershell
$a = New-CertificateRequest -CA -Subject "CN=Root CA" -SelfSign
$b = New-CertificateRequest -CA -Subject "CN=Sub CA" -SigningCert $a -PathLength 0
$c = New-CertificateRequest -Eku "ServerAuthentication" -Subject "CN=www.demo.org" -Dns "www.demo.org" -SigningCert $b
$a,$b,$c
```

Example: Demonstrating a Path length Constraint violation

```powershell
$a = New-CertificateRequest -CA -Subject "CN=Root CA" -SelfSign
$b = New-CertificateRequest -CA -Subject "CN=Sub CA" -SigningCert $a -PathLength 0
$c = New-CertificateRequest -CA -Subject "CN=Invalid Path Length CA" -SigningCert $b
$d = New-CertificateRequest -Eku "ServerAuthentication" -Subject "CN=Invalid Path Length Certificate" -Dns "www.demo.org" -SigningCert $c
$a,$b,$c,$d
```

Example: Demonstrating an EKU Constraint violation

```powershell
$a = New-CertificateRequest -CA -Subject "CN=Root CA" -SelfSign
$b = New-CertificateRequest -CA -Eku "ClientAuthentication" -Subject "CN=Sub CA 1" -SigningCert $a
$c = New-CertificateRequest -Eku "ServerAuthentication" -Subject "CN=Invalid EKU Certificate" -Dns "www.demo.org" -SigningCert $b
$a,$b,$c
```

Example: Creating a Certificate Signing Request (CSR) for a Web Server Certificate, using an ECDSA Key, containing multiple SANs of Type DnsName and IPAdress (and an empty Subject String)

```powershell
New-CertificateRequest `
-Eku ServerAuth `
-Dns "web1.fabrikam.com","web2.fabrikam.com","web3.fabrikam.com" `
-IP "192.168.0.1" `
-KeyAlgorithm ECDSA_P256 |
Out-File CertificateRequestFile.csr -Encoding ascii
```

Example: Creating a manual OCSP Request specifying AKI and a Hardware Security Module (HSM) Key Storage Provider (KSP)

```powershell
New-CertificateRequest `
-Subject "CN=My-Responder" `
-Ksp "nCipher Security World Key Storage Provider" `
-Eku "OCSPSigning" `
-Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF" `
-KeyLength 4096 |
Out-File CertificateRequestFile.csr -Encoding ascii
```

### New-SignedCertificateRequest

`New-SignedCertificateRequest` appends a Signature to a PKCS#10 Certificate Request. Can also append the RequesterName Attribute for Enroll on Behalf of (EOBO) processes.

Example: Signing a previously created Certificate Signing Request

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$eacert = Get-ChildItem -Path Cert:\CurrentUser\My\85CF977C7E32CE808E9D92C61FDB9A43437DC4A2
$csr | New-SignedCertificateRequest -SigningCert $eacert
```

### Get-IssuedCertificate

`Get-IssuedCertificate` allows for Submission of a Certificate Request to a Certification Authority. It also allows for retrieval of a previously issued Certificate from a Certification Authority.

Example: Creating a Certificate Request and submitting it to a Certification Authority

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$csr | Get-IssuedCertificate `
-ConfigString "ca02.intra.adcslabor.de\ADCS Labor Issuing CA 1"
-CertificateTemplate "ADCSLaborUser"
```

Example: Retrieving an issued Certificate for a previously submitted Certificate request

```powershell
Get-IssuedCertificate `
-ConfigString "ca02.intra.adcslabor.de\ADCS Labor Issuing CA 1"
-RequestId 12345
```

### Install-IssuedCertificate

`Install-IssuedCertificate` allows for installing a Certificate onto the local Machine after the correspoiding certificate Request was approved by a Certification Authority.

Example: Creating a Certificate Request, submitting it to a Certification Authority and installing the response

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$response = $csr | Get-IssuedCertificate `
-ConfigString "ca02.intra.adcslabor.de\ADCS Labor Issuing CA 1"
-CertificateTemplate "ADCSLaborUser"
$response.Certificate | Install-IssuedCertificate
```

### Get-KeyStorageProvider

`Get-KeyStorageProvider` enumerates all Cryptographic Service Providers (CSP) and Key Storage Providers (KSP) installed on the local machine.

Example: List all CSPs and KSPs available on the machine

```powershell
Get-KeyStorageProvider | Select-Object -Property Name
```

### Undo-CertificateArchival

`Undo-CertificateArchival` allows for un-archiving a previously archived Certificate.

Example: Unarchive an archived Certificate, identified by it's SHA-1 Thumbprint

```powershell
Undo-CertificateArchival `
-Thumbprint 85CF977C7E32CE808E9D92C61FDB9A43437DC4A2 `
-CertStoreLocation Cert:\CurrentUser\My\
```
