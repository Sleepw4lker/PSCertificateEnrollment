# PSCertificateEnrollment

PowerShell Module for various PKI-related tasks like:

- Creating Certificate Signing requests
- Creating Self-Signed Certificates or Certificates signed with a given Key
- Requesting or Renewing User or Machine Certificates via one of the following protocols:
    - [Windows Client Certificate Enrollment Protocol (MS-WCCE)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce)
    - [WS-Trust X.509v3 Token Enrollment Extensions (MS-WSTEP)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep)
    - [Simple Certificate Enrollment Protocol (SCEP)](https://datatracker.ietf.org/doc/html/rfc8894)
    - [Enrollment over Secure Transport (EST)](https://datatracker.ietf.org/doc/html/rfc7030)
- Signing a Certificate Request with an Enrollment Agent Certificate prior to Submission to a Certification Authority
- Installing issued Certificates after the Certificate Request has been approved by a Certification Authority
- Identifying and configuring the Remote Desktop Session Host Certificate of a machine

It is (mainly) intended for Client-Side Tasks inside the Microsoft PKI Ecosystem and is built out of pure PowerShell Script Code (using .NET and Win32 API). No wrapping of any `certutil` or `openssl` commands. No additional binary Code (e.g. a DLL etc.) necessary to deploy. I mainly use the module for testing PKI protocol implementations as well as certificate authority deployments.

> PSCertificateenrollment can also be used as a Penetration testing tool, e.g. for deployments using [Microsoft Network Device Enrollment Service (NDES)](https://www.gradenegger.eu/en/from-zero-to-enterprise-administrator-through-the-network-device-registration-service-ndes/) or to [directly sign certificates bypassing the certification authority service](https://www.gradenegger.eu/en/signing-certificates-bypassing-the-certification-authority/).

> For securing a Microsoft Certification Authority, take a look at the [Tame My Certs policy module for Active Directory Certificate Services](https://github.com/Sleepw4lker/TameMyCerts).

> For managing a Microsoft Certification Authority, take a look at the awesome [PSPKI Module](https://github.com/PKISolutions/PSPKI).

## Installing

The module can easily be installed via the [PowerShell Gallery](https://www.powershellgallery.com/packages/PSCertificateEnrollment).

```powershell
Install-Module -Name PSCertificateEnrollment
```

> The Module and it's files are digitally signed when obtaining it from the PowerShell Gallery.

## Supported Operating Systems

- Windows 11 / Windows Server 2022,2025
- Windows 10 / Windows Server 2016,2019
- Windows 8.1 / Windows Server 2012 R2 [Windows PowerShell 5.1](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/setup/install-configure?view=powershell-5.1) must be installed)

Earlier Windows Version since Windows Vista/Server 2008 may work, but are not supported. `Get-SCEPCertificate` will definitely **not** work on Windows Operating Systems below 8.1/Server 2012 R2.

PowerShell Core and therefore Linux are also not supported, as the Win32 API is not available on these.

## Supported Commands

The following Commands are available: 

- `Get-NDESOTP`
- `Get-SCEPCertificate`
- `Get-KeyStorageProvider`
- `Get-IssuedCertificate`
- `New-CertificateRequest`
- `New-SignedCertificateRequest`
- `Install-IssuedCertificate`
- `Undo-CertificateArchival`
- `Get-RemoteDesktopCertificate`
- `Set-RemoteDesktopCertificate`
- `Invoke-AutoEnrollmentTask`
- `Get-ESTCertificate`
- `Get-ESTCACertificates`

### New-CertificateRequest

`New-CertificateRequest` builds a Certificate Signing Request (CSR) based on the given Arguments. Can also create self-signed Certificates as well as directly sign the request with a Certificate (to be precise, it’s private Key). For example, you could specify a Certification Authority Certificate as the Signer.

You can specify the following Enhanced Key Usages (EKUs) by their friendly name:

- `EnrollmentAgent` 
- `ClientAuthentication` 
- `CodeSigning` 
- `LifeTimeSigning` 
- `DocumentSigning` 
- `DocumentEncryption` 
- `EncryptingFileSystem` 
- `FileRecovery` 
- `IPSecEndSystem` 
- `IPSecIKEIntermediate` 
- `IPSecTunnelEndpoint` 
- `IPSecUser` 
- `KeyRecovery` 
- `KDCAuthentication` 
- `SecureEmail` 
- `ServerAuthentication` 
- `SmartCardLogon` 
- `TimeStamping` 
- `OCSPSigning` 
- `RemoteDesktopAuthentication` 
- `PrivateKeyArchival`

> Note that usually, it is not necessary to specify an EKU in a CSR, as this will be overwritten by the Microsoft Certification Authority due to Certificate Template Settings).

#### Example: Creating a PKI Hierarchy in a 3-Liner

```powershell
$a = New-CertificateRequest -CA -Subject "CN=Root CA" -SelfSign
$b = New-CertificateRequest -CA -Subject "CN=Sub CA" -SigningCert $a -PathLength 0
$c = New-CertificateRequest -Eku "ServerAuthentication" -Subject "CN=www.demo.org" -Dns "www.demo.org" -SigningCert $b
$a,$b,$c
```

#### Example: Demonstrating a Path length Constraint violation

```powershell
$a = New-CertificateRequest -CA -Subject "CN=Root CA" -SelfSign
$b = New-CertificateRequest -CA -Subject "CN=Sub CA" -SigningCert $a -PathLength 0
$c = New-CertificateRequest -CA -Subject "CN=Invalid Path Length CA" -SigningCert $b
$d = New-CertificateRequest -Eku "ServerAuthentication" -Subject "CN=Invalid Path Length Certificate" -Dns "www.demo.org" -SigningCert $c
$a,$b,$c,$d
```

#### Example: Demonstrating an EKU Constraint violation

```powershell
$a = New-CertificateRequest -CA -Subject "CN=Root CA" -SelfSign
$b = New-CertificateRequest -CA -Eku "ClientAuthentication" -Subject "CN=Sub CA 1" -SigningCert $a
$c = New-CertificateRequest -Eku "ServerAuthentication" -Subject "CN=Invalid EKU Certificate" -Dns "www.demo.org" -SigningCert $b
$a,$b,$c
```

#### Example: Creating a Certificate Signing Request (CSR) for a Domain Controller Certificate using a 3072 Bit RSA Key

```powershell
New-CertificateRequest -MachineContext -LeyLength 3072 -Subject "CN=dc01.mydomain.local" -Dns "dc01.mydomain.local","mydomain.local", "MYDOMAIN" -Eku KDCAuthentication,ServerAuthentication,ClientAuthentication,SmartcardLogon
```

#### Example: Creating a Certificate Signing Request (CSR) for a Web Server Certificate, using an ECDSA Key, containing multiple SANs of Type DnsName and IPAdress (and an empty Subject String)

```powershell
New-CertificateRequest -Eku ServerAuth -Dns "web1.mydomain.local","web2.mydomain.local","web3.mydomain.local" -IP "192.168.0.1" -KeyAlgorithm ECDSA_P256 | Out-File -Path CertificateRequestFile.csr -Encoding ascii
```

#### Example: Creating a Certificate Signing Request (CSR) for an OCSP Responder, specifying the signing CA Certificate to be used via Authority Key Identifier (AKI) and a Hardware Security Module (HSM) Key Storage Provider (KSP)

```powershell
New-CertificateRequest -Subject "CN=My-Responder" -Ksp "nCipher Security World Key Storage Provider" -Eku "OCSPSigning" -Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF" -KeyLength 4096 | Out-File CertificateRequestFile.csr -Encoding ascii
```

### New-SignedCertificateRequest

`New-SignedCertificateRequest` appends a Signature to a PKCS#10 Certificate Request. Can also append the RequesterName Attribute for Enroll on Behalf of (EOBO) processes.

#### Example: Signing a previously created Certificate Signing Request

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$eacert = Get-ChildItem -Path Cert:\CurrentUser\My\85CF977C7E32CE808E9D92C61FDB9A43437DC4A2
$csr | New-SignedCertificateRequest -SigningCert $eacert
```

### Get-IssuedCertificate

`Get-IssuedCertificate` allows for Submission of a Certificate Request to a Certification Authority. It also allows for retrieval of a previously issued Certificate from a Certification Authority.

#### Example: Creating a Certificate Request and submitting it to a Certification Authority via MS-WCCE

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$csr | Get-IssuedCertificate -ConfigString "ca01.mydomain.local\My Enterprise CA" -CertificateTemplate "UserTemplate"
```

#### Example: Creating a Certificate Request and submitting it to a Certification Authority via MS-WSTEP using Kerberos Authentication

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$csr | Get-IssuedCertificate -ConfigString "https://wstep1ca01.wstep1.local/My%20Enterprise%20CA%201_CES_Kerberos/service.svc/CES" -CertificateTemplate "UserTemplate"
```

#### Example: Creating a Certificate Request and submitting it to a Certification Authority via WSTEP using Username and Password Authentication

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$csr | Get-IssuedCertificate -ConfigString "https://ces01.mydomain.local/My%20Enterprise%20CA%201_CES_UsernamePassword/service.svc/CES" -CertificateTemplate "UserTemplate" -Credential (Get-Credential)
```

#### Example: Retrieving an issued Certificate for a previously submitted Certificate request

```powershell
Get-IssuedCertificate -ConfigString "ca01.mydomain.local\My Enterprise CA" -RequestId 12345
```

### Install-IssuedCertificate

`Install-IssuedCertificate` allows for installing a Certificate onto the local Machine after the correspoiding certificate Request was approved by a Certification Authority.

#### Example: Creating a Certificate Request, submitting it to a Certification Authority and installing the response

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$response = $csr | Get-IssuedCertificate -ConfigString "ca01.mydomain.local\" -CertificateTemplate "UserTemplate"
$response.Certificate | Install-IssuedCertificate
```

### Get-SCEPCertificate

`Get-SCEPCertificate` creates and submits an NDES Certificate Request using the _IX509SCEPEnrollment_ Interface available in Windows 8.1 and higher, and retrieves the issued Certificate. The issued Certificate directly gets installed into the respective Certificate store.

It supports Renewal Mode by passing an X509Certificate Object either via the Pipeline or the `-SigningCertificate` Argument. The Certificate must have a private Key, and be issued from the same CA as the new one.

It supports SSL, but doesnt use it by default (not necessary as sensitive data is protected on protocol-level).

It should work with any server-side SCEP implementation, but was explicitly tested with:

- [Microsoft Network Device Enrollment Service (NDES)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview)
- [m2trust](https://m2trust.de/en/)

#### Example: Performing a SCEP Certificate Request using a previously-obtained Challenge Request

```powershell
Get-SCEPCertificate -ComputerName "ndes01.mydomain.local" -Subject "CN=Test" -ChallengePassword "BDE00774A789610F"
```

#### Example: Performing a SCEP Renewal Request (renewing an existing Certificate via SCEP)

```powershell
Get-ChildItem -Path Cert:\CurrentUser\My\85CF977C7E32CE808E9D92C61FDB9A43437DC4A2 | 
Get-SCEPCertificate -ComputerName "ndes01.mydomain.local"
```

### Get-NDESOTP

`Get-NDESOTP` retrieves an One-Time-Password (OTP) from the NDES Server.

Uses SSL by default. SSL can be disabled if required, but this is not recommended.

Uses your Windows Identity by default but can also be passed a PSCredential Object (Get-Credential).

The `-PasswordLength` Parameter must be adjusted if you do not use the default 8-Character Passwords on the NDES server (as it’s only RegEx grabbing the HTML Output).

#### Example: Retrieving a NDES One-Time Password

```powershell
Get-NDESOTP -ComputerName "ndes01.mydomain.local" -Credential $(Get-Credential)
```

### Get-ESTCACertificates

#### Example: Retrieving CA certificates from testrfc7030.com

> Note that for this service, it is necessary to establish trust relationship to the Root CA as [described on their landing page](http://testrfc7030.com/). Use at your won risk.

```powershell
Get-ESTCACertificates -ComputerName "testrfc7030.com" -Port 8443
```

### Get-ESTCertificate

#### Example: Requesting a certificate from testrfc7030.com

> Note that for this service, it is necessary to establish trust relationship to the Root CA as [described on their landing page](http://testrfc7030.com/). Use at your won risk.

```powershell
$csr = New-CertificateRequest -Subject "CN=Test"
$cert = $csr | Get-ESTCertificate -ComputerName "testrfc7030.com" -Port 8443 -Username "estuser" -Password "estpwd"
$cert | Install-IssuedCertificate
```

### Get-KeyStorageProvider

`Get-KeyStorageProvider` enumerates all [Cryptographic Service Providers (CSP) and Key Storage Providers (KSP)](https://www.gradenegger.eu/en/basics-cryptographic-service-provider-csp-and-key-storage-provider-ksp/) installed on the local machine.

#### Example: List all CSPs and KSPs available on the machine

```powershell
Get-KeyStorageProvider | Select-Object -Property Name
```

### Undo-CertificateArchival

`Undo-CertificateArchival` allows for un-archiving a previously archived Certificate.

#### Example: Unarchive an archived Certificate, identified by it’s SHA-1 Thumbprint

```powershell
Undo-CertificateArchival -Thumbprint 85CF977C7E32CE808E9D92C61FDB9A43437DC4A2 -CertStoreLocation Cert:\CurrentUser\My\
```

### Get-RemoteDesktopCertificate

`Get-RemoteDesktopCertificate` gets the currently configured Certificate for the Remote Desktop Session Host on the local System.

#### Example: Retrieving the currently configured Remote Desktop Certificate

```powershell
Get-RemoteDesktopCertificate
```

### Set-RemoteDesktopCertificate

`Set-RemoteDesktopCertificate` sets the Certificate for the Remote Desktop Session Host on the local System. Can be combined with `Get-SCEPCertificate`, `Get-ESTCertificate` or `Install-IssuedCertificate`.

#### Example: Choosing and setting a Remote Desktop Certificate

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My\85CF977C7E32CE808E9D92C61FDB9A43437DC4A2 | 
Set-RemoteDesktopCertificate
```