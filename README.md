# PSCertificateEnrollment

PowerShell Module to create Certificate Signing requests, Self-Signed Certificates or Certificates signed with a given Key, and to request or renew a User or Machine Certificates via the [Simple Certificate Enrollment Protocol (SCEP)](https://tools.ietf.org/html/draft-nourse-scep-23).

Supported Operating Systems:

* Windows 8.1
* Windows 10
* Windows Server 2012 R2
* Windows Server 2016
* Windows Server 2019

Earlier Operating Systems, PowerShell Core and Linux are not supported, as native OS Interfaces are used that are not present in these.

Supported SCEP Implementations:

* Microsoft Network Device Enrollment Service (NDES)

Other SCEP Implementations should be easy to implement but I currently have none to test against.

The following functions get exported:
* [Get-NDESOTP](docs/Get-NDESOTP.md)
* [Get-NDESCertificate](docs/Get-NDESCertificate.md)
* [New-CertificateRequest](docs/New-CertificateRequest.md)

## Get-NDESOTP
Retrieves an One-Time-Password (OTP) from the NDES Server.

Uses SSL by default. SSL can be disabled if required, but this is not recommended.

Uses your Windows Identity by default but can also be passed a PSCredential Object (Get-Credential).

The -PasswordLength Parameter must be adjusted if you do not use the default 8-Character Passwords on the NDES (as it's only RegEx grabbing the HTML Output).

## Get-NDESCertificate
Creates, Submits and Retrieves an NDES Certificate Request using the IX509SCEPEnrollment Interface available in Windows 8.1 and higher.

Supports Renewal Mode by passing an X509Certificate Object either via the Pipeline or the -SigningCertificate Argument. The Certificate must have a private Key, and be issued from the same CA as the new one.

Supports SSL, but doesnt use it by default (not necessary as sensitive Data is protected anyway).

## New-CertificateRequest

* `New-CertificateRequest` crafts a Certificate based on the given Arguments. Can create self-signed Certificates as well as sign with a different Key, or output a Certificate Request for submission to a Certification Authority. You can specify the following Enhanced Key Usages (EKUs):
  * `EnrollmentAgent`
  * `ClientAuthentication`
  * `CodeSigning`
  * `DocumentSigning`
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

### Sample: Creating a Certificate Hierarchy in a 3-Liner

```powershell
$a = New-CertificateRequest -CA -CommonName "Root CA" -SelfSign
$b = New-CertificateRequest -CA -CommonName "Sub CA" -SigningCert $a -PathLength 0
$c = New-CertificateRequest -Eku "ServerAuth" -CommonName "www.demo.org" -DnsName "www.demo.org" -SigningCert $b
$a,$b,$c
```

### Sample: Demonstrating a Path length Constraint violation

```powershell
$a = New-CertificateRequest -CA -CommonName "Root CA" -SelfSign
$b = New-CertificateRequest -CA -CommonName "Sub CA" -SigningCert $a -PathLength 0
$c = New-CertificateRequest -CA -CommonName "Invalid Path Length CA" -SigningCert $b
$d = New-CertificateRequest -Eku "ServerAuth" -CommonName "Invalid Path Length Certificate" -DnsName "www.demo.org" -SigningCert $c
$a,$b,$c,$d
```

### Sample: Demonstrating an EKU Constraint violation

```powershell
$a = New-CertificateRequest -CA -CommonName "Root CA" -SelfSign
$b = New-CertificateRequest -CA -Eku "ClientAuth" -CommonName "Sub CA 1" -SigningCert $a
$c = New-CertificateRequest -Eku "ServerAuth" -CommonName "Invalid EKU Certificate" -DnsName "www.demo.org" -SigningCert $b
$a,$b,$c
```

### Sample: Creating a Certificate Signing Request (CSR) for a Web Server Certificate containing multiple SANs of Type DNSName

```powershell
New-CertificateRequest ´
    -Eku ServerAuth ´
    -DnsName "web1.fabrikam.com","web2.fabrikam.com","web3.fabrikam.com" ´
    -IP "192.168.0.1" ´
    -KeyLength 4096 ´ |
    Out-File CertificateRequestFile.csr -Encoding ascii
```

### Sample: Creating a manual OCSP Request specifying AKI and a HSM

```powershell
New-CertificateRequest ´
    -CommonName "My-Responder" ´
    -Ksp "nCipher Security World Key Storage Provider" ´
    -Eku "OCSPSigning" ´
    -Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF" ´
    -KeyLength 4096 |
    Out-File CertificateRequestFile.csr -Encoding ascii
```