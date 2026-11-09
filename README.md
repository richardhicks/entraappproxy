# Update-EntraAppProxyCertificate

[![PowerShell Gallery](https://img.shields.io/badge/PowerShell%20Gallery-Update--EntraAppProxyCertificate-blue)](https://www.powershellgallery.com/packages/Update-EntraAppProxyCertificate) [![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/richardhicks/entraappproxy/blob/main/LICENSE) [![Version](https://img.shields.io/badge/Version-1.6.2-brightgreen)](https://github.com/richardhicks/entraappproxy)

PowerShell script for updating the TLS certificate assigned to Microsoft Entra application proxy applications published on a custom domain.

## Description

Microsoft Entra application proxy applications published using a custom domain require a TLS certificate to be uploaded to the service. Update-EntraAppProxyCertificate.ps1 replaces that certificate using the Microsoft Graph API, either for a single application by name or for every application in the tenant whose external URL matches a name in the supplied certificate.

The script validates the certificate before making any changes. It confirms that the PFX file includes the private key, that the certificate is currently valid, and that its subject or a subject alternative name matches the host name in the application's external URL. After each update, it reads the certificate back from the service and compares the thumbprint to confirm the change.

When the `-UpdateAll` switch is used, wildcard certificates, multi-SAN certificates, or a combination of both are supported. The following applications are skipped automatically:

- Applications published using the default `msappproxy.net` domain.
- Applications published using Global Secure Access (Microsoft Entra Private Access).
- Applications whose external URL does not match a name in the certificate.

Applications are discovered using the Microsoft Entra on-premises application template. Applications created programmatically without this template are not discovered and must be updated individually using the `-Name` parameter.

## Installation

### PowerShell Gallery

```
Install-Script -Name Update-EntraAppProxyCertificate -Scope CurrentUser
```

The required Microsoft.Graph.Authentication module is installed automatically if it is not already present.

### Manual Installation

1. Install the Microsoft Graph Authentication module, if it is not already installed:

```
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
```

2. Download `Update-EntraAppProxyCertificate.ps1` from the [GitHub repository](https://github.com/richardhicks/entraappproxy).
3. If the file was downloaded from the internet, unblock it:

```
Unblock-File -Path .\Update-EntraAppProxyCertificate.ps1
```

## Parameters

| Parameter             | Description                                                                                                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `-Name`               | The display name of the application proxy application. Required when updating a single application.                                             |
| `-UpdateAll`          | Updates all application proxy applications in the tenant whose external URL matches a name in the supplied certificate.                         |
| `-PfxFile`            | The path to the PFX file containing the new TLS certificate and its private key.                                                                |
| `-Password`           | The password protecting the PFX file, supplied as a secure string.                                                                              |
| `-TenantId`           | The Microsoft Entra tenant ID or domain name. Optional. Required only when the signed in account has access to more than one tenant.            |
| `-SkipNameValidation` | Suppresses validation of the certificate names against the application's external URL. Valid only when updating a single application by name. |

The script also supports the common `-WhatIf` and `-Confirm` parameters.

## Usage

Update the TLS certificate for a single application:

```
$Password = Read-Host -Prompt 'Enter PFX password' -AsSecureString
.\Update-EntraAppProxyCertificate.ps1 -Name 'hrwebapp' -PfxFile 'C:\Certs\hrwebapp.pfx' -Password $Password
```

Update a single application in a specific tenant:

```
.\Update-EntraAppProxyCertificate.ps1 -Name 'hrwebapp' -PfxFile 'C:\Certs\hrwebapp.pfx' -Password $Password -TenantId 'contoso.com'
```

Update all applications whose external URL matches a name in the certificate:

```
.\Update-EntraAppProxyCertificate.ps1 -UpdateAll -PfxFile 'C:\Certs\wildcard.pfx' -Password $Password
```

List the applications that would be updated without making any changes:

```
.\Update-EntraAppProxyCertificate.ps1 -UpdateAll -PfxFile 'C:\Certs\wildcard.pfx' -Password $Password -WhatIf
```

## Output

The script emits one object to the pipeline for each application processed, with the following properties:

| Property     | Description                                                                                                       |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| `Name`       | The display name of the application.                                                                              |
| `Status`     | `Updated`, `Unconfirmed`, `Skipped`, or `Failed`.                                                                 |
| `Thumbprint` | The thumbprint of the certificate reported by the service after the update. Null for skipped and failed applications. |
| `Expires`    | The expiration date of the certificate reported by the service after the update. Null for skipped and failed applications. |
| `Reason`     | The reason the application was skipped, failed, or could not be confirmed. Null for successful updates.           |

No objects are emitted when `-WhatIf` is specified or when the script terminates with an error before processing begins.

### Exit Codes

The script sets an exit code for callers that cannot consume pipeline output, such as Task Scheduler or CI/CD pipelines.

| Exit Code | Description                                                         |
| --------- | ------------------------------------------------------------------- |
| `0`       | All updates completed and were confirmed.                           |
| `1`       | The script terminated with an error before processing completed. Returned when the script is run with `powershell.exe` or `pwsh`. When the script is called from within PowerShell, a terminating error is thrown instead. |
| `2`       | One or more updates failed.                                         |
| `3`       | One or more updates completed but could not be confirmed.           |

### Logging

Each run is recorded in a transcript written to `$env:ProgramData\RMHCI\PowerShell` with a date and time stamped file name.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 and later.
- Microsoft.Graph.Authentication module version 2.0.0 or later.
- The Cloud Application Administrator role (or higher) in Microsoft Entra ID.
- The `Application.ReadWrite.All` and `Directory.ReadWrite.All` delegated Microsoft Graph permissions.
- A PFX file containing the TLS certificate and its private key.

> **Note:** Application proxy configuration is exposed only in the Microsoft Graph beta endpoint.

## Additional Information

- [onPremisesPublishing resource type (Microsoft Graph beta)](https://learn.microsoft.com/en-us/graph/api/resources/onpremisespublishing?view=graph-rest-beta)
- [Configure custom domains with Microsoft Entra application proxy](https://learn.microsoft.com/en-us/entra/identity/app-proxy/how-to-configure-custom-domain)

## Author

**Richard Hicks** - [Richard M. Hicks Consulting, Inc.](https://www.richardhicks.com/)

- Website: <https://www.richardhicks.com/>
- GitHub: <https://github.com/richardhicks/entraappproxy>
- X: [@richardhicks](https://x.com/richardhicks)

## License

This project is licensed under the [MIT License](https://github.com/richardhicks/entraappproxy/blob/main/LICENSE).

## Copyright

© 2026 Richard M. Hicks Consulting, Inc.
