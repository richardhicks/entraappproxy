<#PSScriptInfo

.VERSION 1.6.2

.GUID 2bd6a2ed-2b0f-47f1-b7c1-9deb614c1554

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/entraappproxy/blob/main/LICENSE

.PROJECTURI https://github.com/richardhicks/entraappproxy

.TAGS Entra, EntraID, AppProxy, ApplicationProxy, Certificate, TLS, SSL, MicrosoftGraph, Graph, Azure, AzureAD

#>

<#

.SYNOPSIS
    Updates the TLS certificate assigned to one or all Microsoft Entra application proxy applications published on a custom domain.

.DESCRIPTION
    Microsoft Entra application proxy applications published using a custom domain require a TLS certificate to be uploaded to the service. This script replaces that certificate using the Microsoft Graph API.

    The certificate must be supplied as a PFX file including the private key. When updating a single application by name, the subject or a subject alternative name must match the host name in the application's external URL.

    When the -UpdateAll switch is used, the script enumerates all application proxy applications in the tenant and updates every application whose external URL host matches a name in the supplied certificate. A wildcard certificate, a multi-SAN certificate, or a combination of both is supported. Applications are discovered using the Microsoft Entra on-premises application template. Applications created programmatically without this template are not discovered and must be updated individually using the -Name parameter.

    The signed in account requires the Cloud Application Administrator role (or higher) and the Directory.ReadWrite.All and Application.ReadWrite.All delegated Microsoft Graph permissions.

    Application proxy configuration is exposed only in the Microsoft Graph beta endpoint.

    Each run is recorded in a transcript written to $env:ProgramData\RMHCI\PowerShell with a date and time stamped file name.

    The script emits one result object per application to the pipeline and sets an exit code for callers that cannot consume pipeline output, such as Task Scheduler or CI/CD pipelines. Exit code 0 indicates all updates completed and were confirmed, 1 indicates the script terminated with an error before processing completed (returned when the script is run with powershell.exe or pwsh; when the script is called from within PowerShell, a terminating error is thrown instead), 2 indicates one or more updates failed, and 3 indicates one or more updates completed but could not be confirmed.

.PARAMETER Name
    The display name of the Microsoft Entra application proxy application. Required when updating a single application.

.PARAMETER UpdateAll
    Updates all application proxy applications in the tenant whose external URL matches a name in the supplied certificate. Wildcard and multi-SAN certificates are both supported. Applications published using the default msappproxy.net domain, applications published using Global Secure Access (Entra Private Access), and applications whose external URL does not match a name in the certificate are skipped.

.PARAMETER PfxFile
    The path to the PFX file containing the new TLS certificate and its private key.

.PARAMETER Password
    The password protecting the PFX file.

.PARAMETER TenantId
    The Microsoft Entra tenant ID or domain name. Optional. Required only when the signed in account has access to more than one tenant.

.PARAMETER SkipNameValidation
    Suppresses validation of the certificate subject and subject alternative names against the application's external URL. Valid only when updating a single application by name.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    PSCustomObject. One object is emitted to the pipeline for each application processed, with the following properties:

    Name       - The display name of the application.
    Status     - 'Updated', 'Unconfirmed', 'Skipped', or 'Failed'.
    Thumbprint - The thumbprint of the certificate reported by the service after the update. Null for skipped and failed applications.
    Expires    - The expiration date of the certificate reported by the service after the update. Null for skipped and failed applications.
    Reason     - The reason the application was skipped, failed, or could not be confirmed. Null for successful updates.

    No objects are emitted when -WhatIf is specified or when the script terminates with an error before processing begins.

.EXAMPLE
    $Password = Read-Host -Prompt 'Enter PFX password' -AsSecureString
    .\Update-EntraAppProxyCertificate.ps1 -Name 'hrwebapp' -PfxFile 'C:\Certs\hrwebapp.pfx' -Password $Password

    Updates the TLS certificate for the application proxy application named 'hrwebapp'.

.EXAMPLE
    .\Update-EntraAppProxyCertificate.ps1 -Name 'hrwebapp' -PfxFile 'C:\Certs\hrwebapp.pfx' -Password $Password -TenantId 'contoso.com' -Verbose

    Updates the TLS certificate for the application proxy application named 'hrwebapp' in the contoso.com tenant with verbose output.

.EXAMPLE
    .\Update-EntraAppProxyCertificate.ps1 -Name 'hrwebapp' -PfxFile 'C:\Certs\hrwebapp.pfx' -Password $Password -WhatIf

    Performs all validation and reports the change that would be made without updating the application.

.EXAMPLE
    .\Update-EntraAppProxyCertificate.ps1 -UpdateAll -PfxFile 'C:\Certs\wildcard.pfx' -Password $Password

    Updates the TLS certificate for all application proxy applications published on a custom domain whose external URL matches a name in the certificate.

.EXAMPLE
    .\Update-EntraAppProxyCertificate.ps1 -UpdateAll -PfxFile 'C:\Certs\wildcard.pfx' -Password $Password -WhatIf

    Lists the application proxy applications that would be updated without making any changes.

.LINK
    https://github.com/richardhicks/entraappproxy

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/onpremisespublishing?view=graph-rest-beta

.LINK
    https://learn.microsoft.com/en-us/entra/identity/app-proxy/how-to-configure-custom-domain

.NOTES
    Version:        1.6.2
    Creation Date:  August 6, 2026
    Last Updated:   November 9, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByName')]
[OutputType([PSCustomObject])]

Param (

    [Parameter(Mandatory, ParameterSetName = 'ByName', HelpMessage = 'Enter the display name of the Entra application proxy application.')]
    [ValidateNotNullOrEmpty()]
    [string]$Name,

    [Parameter(Mandatory, ParameterSetName = 'UpdateAll', HelpMessage = 'Update all Entra application proxy applications matching the certificate.')]
    [switch]$UpdateAll,

    [Parameter(Mandatory, HelpMessage = 'Enter the path to the PFX file containing the new TLS certificate.')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$PfxFile,

    [Parameter(Mandatory, HelpMessage = 'Enter the password for the PFX file.')]
    [ValidateNotNull()]
    [securestring]$Password,

    [Parameter(HelpMessage = 'Enter the Entra tenant ID or domain name.')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'ByName', HelpMessage = 'Skip validation of the certificate name against the application external URL.')]
    [switch]$SkipNameValidation

)

# Ensure verbose output is always displayed and captured in the transcript
$VerbosePreference = 'Continue'

# Create log directory if it doesn't exist
Write-Verbose 'Starting transcript...'
$LogPath = "$env:ProgramData\RMHCI\PowerShell"

If (-not (Test-Path -Path $LogPath)) {

    # Logging is exempt from -WhatIf so the transcript can always be created
    [void](New-Item -Path $LogPath -ItemType Directory -Force -WhatIf:$False)

}

# Start transcript. Exempt from -WhatIf so -WhatIf runs are always logged and Stop-Transcript in the Finally block always succeeds
Start-Transcript -Path "$LogPath\Update-EntraAppProxyCertificate_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -WhatIf:$False

# Record the invocation and bound parameters in the transcript for troubleshooting
Write-Verbose "Invocation: $($MyInvocation.Line.Trim())"
Write-Verbose 'Bound parameters:'
ForEach ($Parameter in $PSBoundParameters.GetEnumerator()) {

    Write-Verbose "  -$($Parameter.Key): $($Parameter.Value)"

}

$ErrorActionPreference = 'Stop'
$GraphUri = 'https://graph.microsoft.com/beta/applications'
$AppProxyTemplateId = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'
$PlainTextPassword = $null

# Result collections populated during processing and reported in the summary displayed after the transcript stops
$Updated = [System.Collections.Generic.List[object]]::New()
$Skipped = [System.Collections.Generic.List[object]]::New()
$Failed = [System.Collections.Generic.List[object]]::New()

Function Invoke-GraphRequestWithRetry {

    [CmdletBinding()]

    Param (

        [hashtable]$RequestParams

    )

    $MaxAttempts = 4
    $Attempt = 0

    While ($True) {

        $Attempt++

        Try {

            Return Invoke-MgGraphRequest @RequestParams

        }

        Catch {

            $StatusCode = 0
            $Response = $_.Exception.Response

            If ($null -ne $Response) {

                $StatusCode = [int]$Response.StatusCode

            }

            If ($StatusCode -eq 429 -and $Attempt -lt $MaxAttempts) {

                $Delay = 10
                $RetryAfter = $Response.Headers.RetryAfter

                If ($null -ne $RetryAfter -and $null -ne $RetryAfter.Delta) {

                    $Delay = [int]$RetryAfter.Delta.TotalSeconds

                }

                Write-Warning "Request throttled by Microsoft Graph. Waiting $Delay seconds before retrying..."
                Start-Sleep -Seconds $Delay

            }

            Else {

                Throw

            }

        }

    }

}

Function Get-CertificateDnsName {

    [CmdletBinding()]
    [OutputType([string[]])]

    Param (

        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate

    )

    $DnsNames = [System.Collections.Generic.List[string]]::New()
    $SanExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }

    If ($null -ne $SanExtension) {

        ForEach ($Line in ($SanExtension.Format($True) -split "`r`n|`n")) {

            ForEach ($Entry in ($Line -split ',')) {

                If ($Entry.Trim() -match '^DNS Name=(.+)$') {

                    $DnsNames.Add($Matches[1].Trim())

                }

            }

        }

    }

    If ($Certificate.Subject -match 'CN=([^,]+)') {

        $DnsNames.Add($Matches[1].Trim())

    }

    Return $DnsNames.ToArray()

}

Function Test-CertificateNameMatch {

    [CmdletBinding()]
    [OutputType([bool])]

    Param (

        [string]$HostName,
        [string[]]$DnsName

    )

    ForEach ($CandidateName in $DnsName) {

        If ($HostName -eq $CandidateName) {

            Return $True

        }

        # Wildcard names match a single label only, consistent with TLS certificate validation rules
        If ($CandidateName.StartsWith('*.')) {

            $Separator = $HostName.IndexOf('.')

            If ($Separator -gt 0 -and $HostName.Substring($Separator + 1) -eq $CandidateName.Substring(2)) {

                Return $True

            }

        }

    }

    Return $False

}

Function Set-AppProxyCertificate {

    # ShouldProcess is handled by the calling script before this function is invoked
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]

    Param (

        [string]$ApplicationId

    )

    $RequestParams = @{

        Method      = 'PATCH'
        Uri         = '{0}/{1}' -f $GraphUri, $ApplicationId
        Body        = $RequestBody
        ContentType = 'application/json'
        ErrorAction = 'Stop'

    }

    [void](Invoke-GraphRequestWithRetry -RequestParams $RequestParams)

    # Allow the service time to process the change before confirming
    Start-Sleep -Seconds 5

    $ConfirmParams = @{

        Method      = 'GET'
        Uri         = '{0}/{1}?$select=onPremisesPublishing' -f $GraphUri, $ApplicationId
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'

    }

    Return (Invoke-GraphRequestWithRetry -RequestParams $ConfirmParams).onPremisesPublishing.verifiedCustomDomainCertificatesMetadata

}

Try {

    # Validate the file extension
    If ([System.IO.Path]::GetExtension($PfxFile) -notin '.pfx', '.p12') {

        Throw "The file '$PfxFile' does not appear to be a PFX file. A PFX file including the private key is required."

    }

    $PfxFile = (Resolve-Path -Path $PfxFile).ProviderPath

    # Convert the PFX password to plain text for certificate validation and the Graph request body
    $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)

    Try {

        $PlainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)

    }

    Finally {

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)

    }

    # Load the certificate and confirm the password and private key
    Write-Verbose "Reading certificate from $PfxFile..."

    Try {

        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $PfxFile, $Password, ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)

    }

    Catch {

        Write-Verbose 'Ephemeral key import failed. Falling back to the default key storage flags...'
        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $PfxFile, $Password

    }

    If (-Not $Certificate.HasPrivateKey) {

        Throw 'The supplied PFX file does not contain a private key. Export the certificate again and include the private key.'

    }

    If ($Certificate.NotAfter -lt (Get-Date)) {

        Throw "The certificate expired on $($Certificate.NotAfter). Supply a valid certificate."

    }

    If ($Certificate.NotBefore -gt (Get-Date)) {

        Throw "The certificate is not valid until $($Certificate.NotBefore). Supply a currently valid certificate."

    }

    Write-Verbose "Certificate subject: $($Certificate.Subject)"
    Write-Verbose "Certificate thumbprint: $($Certificate.Thumbprint)"
    Write-Verbose "Certificate expires: $($Certificate.NotAfter)"

    $CertificateDnsNames = @(Get-CertificateDnsName -Certificate $Certificate)
    Write-Verbose "Certificate DNS names: $($CertificateDnsNames -join ', ')"

    # Connect to Microsoft Graph
    $Context = Get-MgContext

    If ($null -eq $Context) {

        Write-Verbose 'Connecting to Microsoft Graph...'

        $ConnectParams = @{

            Scopes      = 'Application.ReadWrite.All', 'Directory.ReadWrite.All'
            NoWelcome   = $True
            ErrorAction = 'Stop'

        }

        If ($PSBoundParameters.ContainsKey('TenantId')) {

            $ConnectParams.Add('TenantId', $TenantId)

        }

        Connect-MgGraph @ConnectParams
        $Context = Get-MgContext

    }

    Else {

        Write-Verbose "Using the existing Microsoft Graph connection for $($Context.Account)."

    }

    If ('Directory.ReadWrite.All' -notin $Context.Scopes) {

        Write-Warning 'The current Microsoft Graph session does not include the Directory.ReadWrite.All scope. The update may fail. Run Disconnect-MgGraph and try again if an authorization error occurs.'

    }

    # Build the request body once. The same certificate payload is used for every application.
    $Base64Certificate = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($PfxFile))

    $Body = @{

        onPremisesPublishing = @{

            verifiedCustomDomainKeyCredential      = @{

                type  = 'X509CertAndPassword'
                value = $Base64Certificate

            }

            verifiedCustomDomainPasswordCredential = @{

                value = $PlainTextPassword

            }

        }

    }

    $RequestBody = $Body | ConvertTo-Json -Depth 5 -Compress

    If ($UpdateAll) {

        # Enumerate application proxy applications using the on-premises application template
        Write-Verbose 'Enumerating application proxy applications...'

        $Filter = "applicationTemplateId eq '{0}'" -f $AppProxyTemplateId
        $Uri = '{0}?$filter={1}&$select=id,displayName&$count=true&$top=999' -f $GraphUri, [System.Uri]::EscapeDataString($Filter)
        $Applications = [System.Collections.Generic.List[object]]::New()

        While (-Not [string]::IsNullOrEmpty($Uri)) {

            $ListParams = @{

                Method      = 'GET'
                Uri         = $Uri
                Headers     = @{ ConsistencyLevel = 'eventual' }
                OutputType  = 'PSObject'
                ErrorAction = 'Stop'

            }

            $Result = Invoke-GraphRequestWithRetry -RequestParams $ListParams

            ForEach ($Application in $Result.value) {

                $Applications.Add($Application)

            }

            $Uri = $Result.'@odata.nextLink'

        }

        If ($Applications.Count -eq 0) {

            Throw "No application proxy applications were found in tenant $($Context.TenantId). Applications created without the Entra on-premises application template are not discovered and must be updated individually by name."

        }

        Write-Verbose "Found $($Applications.Count) application proxy application(s)."

        # Select applications with an external URL matching a name in the certificate
        $Targets = [System.Collections.Generic.List[object]]::New()

        ForEach ($Application in $Applications) {

            $GetParams = @{

                Method      = 'GET'
                Uri         = '{0}/{1}?$select=onPremisesPublishing' -f $GraphUri, $Application.id
                OutputType  = 'PSObject'
                ErrorAction = 'Stop'

            }

            $Publishing = (Invoke-GraphRequestWithRetry -RequestParams $GetParams).onPremisesPublishing

            If ($null -eq $Publishing -or [string]::IsNullOrEmpty($Publishing.externalUrl)) {

                Write-Verbose "Skipping '$($Application.displayName)'. The application is not configured for application proxy."
                $Skipped.Add([PSCustomObject]@{ Name = $Application.displayName; Status = 'Skipped'; Thumbprint = $null; Expires = $null; Reason = 'The application is not configured for application proxy' })
                Continue

            }

            # Global Secure Access (Entra Private Access) applications share the application proxy template but do not use TLS certificates
            If ($Publishing.isAccessibleViaZTNAClient -eq $True) {

                Write-Verbose "Skipping '$($Application.displayName)'. The application is published using Global Secure Access, not application proxy."
                $Skipped.Add([PSCustomObject]@{ Name = $Application.displayName; Status = 'Skipped'; Thumbprint = $null; Expires = $null; Reason = 'The application is published using Global Secure Access, not application proxy' })
                Continue

            }

            $ExternalHost = ([System.Uri]$Publishing.externalUrl).Host

            If ($ExternalHost -like '*.msappproxy.net') {

                Write-Verbose "Skipping '$($Application.displayName)'. The application is published using the default msappproxy.net domain."
                $Skipped.Add([PSCustomObject]@{ Name = $Application.displayName; Status = 'Skipped'; Thumbprint = $null; Expires = $null; Reason = 'The application is published using the default msappproxy.net domain' })
                Continue

            }

            If (-Not (Test-CertificateNameMatch -HostName $ExternalHost -DnsName $CertificateDnsNames)) {

                Write-Verbose "Skipping '$($Application.displayName)'. The certificate does not include a name matching '$ExternalHost'."
                $Skipped.Add([PSCustomObject]@{ Name = $Application.displayName; Status = 'Skipped'; Thumbprint = $null; Expires = $null; Reason = "The certificate does not include a name matching '$ExternalHost'" })
                Continue

            }

            $Targets.Add([PSCustomObject]@{ Id = $Application.id; Name = $Application.displayName; ExternalHost = $ExternalHost })

        }

        If ($Targets.Count -eq 0) {

            Throw "The certificate does not include a name matching the external URL of any application proxy application. Names found: $($CertificateDnsNames -join ', ')."

        }

        Write-Verbose "$($Targets.Count) application(s) selected for update."

        # Update each matching application. A failure on one application does not stop the batch.
        ForEach ($Target in $Targets) {

            If ($PSCmdlet.ShouldProcess($Target.Name, "Assign TLS certificate $($Certificate.Thumbprint) expiring $($Certificate.NotAfter)")) {

                Try {

                    Write-Verbose "Uploading certificate to application '$($Target.Name)'..."
                    $Metadata = Set-AppProxyCertificate -ApplicationId $Target.Id
                    $Confirmed = ($null -ne $Metadata -and $Metadata.thumbprint -eq $Certificate.Thumbprint)

                    If ($Confirmed) {

                        Write-Verbose "The TLS certificate for '$($Target.Name)' was updated successfully."
                        $Updated.Add([PSCustomObject]@{ Name = $Target.Name; Status = 'Updated'; Thumbprint = $Metadata.thumbprint; Expires = $Metadata.expiryDate; Reason = $null })

                    }

                    Else {

                        Write-Warning "The update request for '$($Target.Name)' completed but the assigned certificate could not be confirmed. Verify the assignment in the Microsoft Entra admin center."
                        $Updated.Add([PSCustomObject]@{ Name = $Target.Name; Status = 'Unconfirmed'; Thumbprint = $Metadata.thumbprint; Expires = $Metadata.expiryDate; Reason = 'The update request completed but the assigned certificate could not be confirmed' })

                    }

                }

                Catch {

                    Write-Warning "Failed to update the certificate for '$($Target.Name)'. $($_.Exception.Message)"
                    $Failed.Add([PSCustomObject]@{ Name = $Target.Name; Status = 'Failed'; Thumbprint = $null; Expires = $null; Reason = $_.Exception.Message })

                }

            }

        }

    }

    Else {

        # Locate the application object
        Write-Verbose "Searching for application '$Name'..."

        $Filter = "displayName eq '{0}'" -f $Name.Replace("'", "''")
        $Uri = '{0}?$filter={1}&$select=id,displayName' -f $GraphUri, [System.Uri]::EscapeDataString($Filter)
        $Result = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject

        If ($Result.value.Count -eq 0) {

            Throw "No application with the display name '$Name' was found in tenant $($Context.TenantId)."

        }

        If ($Result.value.Count -gt 1) {

            Throw "More than one application with the display name '$Name' was found. Resolve the ambiguity before continuing."

        }

        $ApplicationId = $Result.value[0].id
        Write-Verbose "Found application '$Name' with object ID $ApplicationId."

        # Retrieve the current application proxy configuration
        $Uri = '{0}/{1}?$select=onPremisesPublishing' -f $GraphUri, $ApplicationId
        $Publishing = (Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject).onPremisesPublishing

        If ($null -eq $Publishing -or [string]::IsNullOrEmpty($Publishing.externalUrl)) {

            Throw "The application '$Name' is not configured for Microsoft Entra application proxy."

        }

        # Global Secure Access (Entra Private Access) applications share the application proxy template but do not use TLS certificates
        If ($Publishing.isAccessibleViaZTNAClient -eq $True) {

            Throw "The application '$Name' is published using Global Secure Access, not application proxy. A TLS certificate cannot be assigned to this application."

        }

        $ExternalUrl = $Publishing.externalUrl
        $ExternalHost = ([System.Uri]$ExternalUrl).Host
        Write-Verbose "Application external URL: $ExternalUrl"

        If ($ExternalHost -like '*.msappproxy.net') {

            Throw "The application '$Name' is published using the default msappproxy.net domain. A TLS certificate can only be assigned to an application published using a custom domain."

        }

        If ($null -ne $Publishing.verifiedCustomDomainCertificatesMetadata) {

            Write-Verbose "Current certificate thumbprint: $($Publishing.verifiedCustomDomainCertificatesMetadata.thumbprint)"
            Write-Verbose "Current certificate expires: $($Publishing.verifiedCustomDomainCertificatesMetadata.expiryDate)"

        }

        # Validate the certificate name against the external URL
        If (-Not $SkipNameValidation) {

            If (-Not (Test-CertificateNameMatch -HostName $ExternalHost -DnsName $CertificateDnsNames)) {

                Throw "The certificate does not include a name matching the external URL host '$ExternalHost'. Names found: $($CertificateDnsNames -join ', '). Use -SkipNameValidation to override this check."

            }

            Write-Verbose "Certificate name validated against '$ExternalHost'."

        }

        # Update the certificate
        If ($PSCmdlet.ShouldProcess($Name, "Assign TLS certificate $($Certificate.Thumbprint) expiring $($Certificate.NotAfter)")) {

            Write-Verbose "Uploading certificate to application '$Name'..."
            $Metadata = Set-AppProxyCertificate -ApplicationId $ApplicationId
            $Confirmed = ($null -ne $Metadata -and $Metadata.thumbprint -eq $Certificate.Thumbprint)

            If ($Confirmed) {

                Write-Verbose "The TLS certificate for '$Name' was updated successfully."
                $Updated.Add([PSCustomObject]@{ Name = $Name; Status = 'Updated'; Thumbprint = $Metadata.thumbprint; Expires = $Metadata.expiryDate; Reason = $null })

            }

            Else {

                Write-Warning "The update request completed but the assigned certificate could not be confirmed. Expected thumbprint $($Certificate.Thumbprint) but the service reported '$($Metadata.thumbprint)'. Verify the assignment in the Microsoft Entra admin center."
                $Updated.Add([PSCustomObject]@{ Name = $Name; Status = 'Unconfirmed'; Thumbprint = $Metadata.thumbprint; Expires = $Metadata.expiryDate; Reason = 'The update request completed but the assigned certificate could not be confirmed' })

            }

        }

    }

}

Finally {

    If ($null -ne $PlainTextPassword) {

        $PlainTextPassword = $null

    }

    If ($null -ne $Certificate) {

        $Certificate.Dispose()

    }

    Remove-Variable -Name Body, RequestBody, Base64Certificate, PlainTextPassword -ErrorAction SilentlyContinue
    [System.GC]::Collect()

    # Stop transcript
    Write-Verbose 'Stopping transcript...'
    Stop-Transcript

}

# Display the results summary and emit result objects (skipped if the script exited early or -WhatIf was specified)
If (-Not $WhatIfPreference -and ($Updated.Count -gt 0 -or $Skipped.Count -gt 0 -or $Failed.Count -gt 0)) {

    # Human-readable summary written to the information stream so it does not mix with the object output. Per-application details are available in the result objects.
    Write-Information '' -InformationAction Continue
    Write-Information "Certificate update complete. Updated: $($Updated.Count). Skipped: $($Skipped.Count). Failed: $($Failed.Count)." -InformationAction Continue

    # Emit one result object per application for consuming automation
    Write-Output $Updated
    Write-Output $Skipped
    Write-Output $Failed

    # Set an exit code for schedulers and other callers that cannot consume the object output. Success falls through with exit code 0.
    If ($Failed.Count -gt 0) {

        Exit 2

    }

    If (@($Updated | Where-Object { $_.Status -eq 'Unconfirmed' }).Count -gt 0) {

        Exit 3

    }

}
