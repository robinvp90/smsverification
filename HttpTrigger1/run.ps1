using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

# Input bindings must be placed at the beginning of the script
param(
    [Parameter(Mandatory = $true)]
    [object] $Request,

    [Parameter(Mandatory = $false)]
    [object] $TriggerMetadata
)
Import-Module Az.Accounts
Import-Module Az.automation
Import-Module Az.KeyVault
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Users.Actions
# Ensure the preference variables are set appropriately
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# Enable TLS 1.2 for security
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Function to create standardized error responses
function Write-ErrorResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,
        [Parameter(Mandatory = $false)]
        [System.Net.HttpStatusCode] $StatusCode = [HttpStatusCode]::InternalServerError
    )

    Push-OutputBinding -Name Response -Value ([HttpResponseContext] @{
        StatusCode = $StatusCode
        Body       = @{
            error     = $Message
            timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json
    })
}

# Function to get certificate from Key Vault
function Get-KeyVaultCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string] $VaultName,
        [Parameter(Mandatory = $true)]
        [string] $CertificateName
    )
    
    try {
        Write-Information "Retrieving certificate '$CertificateName' from Key Vault '$VaultName'"
        # Retrieve the certificate bundle from Key Vault
        $certBundle = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
        if (-not $certBundle) {
            throw "Certificate '$CertificateName' not found in Key Vault '$VaultName'"
        }
        Write-Information "Certificate retrieved: $($certBundle.Name) with thumbprint $($certBundle.Thumbprint)"
        
        # The certificate's PFX (including the private key) is stored as a base64-encoded secret.
        $CertBase64 = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertificateName -AsPlainText
        Write-Information "Certificate Secret retrieved: $($CertBase64)"
        $CertBytes = [System.Convert]::FromBase64String($CertBase64)
        if ([string]::IsNullOrWhiteSpace($CertBytes)) {
            throw "The certificate secret is empty."
        }
        
        # Create an X509Certificate2 object from the byte array.
        # The Exportable flag ensures that the private key is accessible.
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Information "Returning the following certificate for authentication: $($Cert)"
        return $cert
    }
    catch {
        throw "Failed to retrieve certificate from Key Vault: $($_.Exception.Message)"
    }
}

try {
    # Parse the request body
    $WebHookData = $Request.Body
    
    Write-Information "Received request body: $($WebHookData | Out-String)"
    
    # Parse the JSON data
    try {
        if ($WebHookData -is [System.Collections.Hashtable] -or $WebHookData -is [PSCustomObject]) {
            $Data = $WebHookData
        } else {
            $Data = $WebHookData | ConvertFrom-Json -ErrorAction Stop
        }
    }
    catch {
        Write-ErrorResponse -Message "Invalid JSON in request body: $_" -StatusCode ([HttpStatusCode]::BadRequest)
        return
    }

    # Validate required fields
    if (-not $Data.content) {
        Write-ErrorResponse -Message "Missing 'content' field in request data" -StatusCode ([HttpStatusCode]::BadRequest)
        return
    }
    if (-not $Data.content.HaloUser) {
        Write-ErrorResponse -Message "Missing 'HaloUser' field in request content" -StatusCode ([HttpStatusCode]::BadRequest)
        return
    }
    if (-not $Data.content.TicketID) {
        Write-ErrorResponse -Message "Missing 'TicketID' field in request content" -StatusCode ([HttpStatusCode]::BadRequest)
        return
    }

    $HaloUser = $Data.content.HaloUser
    $TicketID = $Data.content.TicketID
    $RequestID = $Data.id
    $Timestamp = $Data.timestamp
    $RefCharacter = $HaloUser.IndexOf("@")
    $TenantID = $HaloUser.Substring($RefCharacter + 1)

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = @{
            status = "success"
            message = "Processing request for user: $HaloUser"
            ticketId = $TicketID
            requestId = $RequestID
        } | ConvertTo-Json
    })

    Write-Information "Processing request for user: $HaloUser"

    # Connect to Azure using managed identity
    $azContext = Connect-AzAccount -Identity

    if (-not $azContext) {
        throw "Failed to obtain Azure context"
    }

    # Retrieve KeyVault secrets and set variables
    $random = Get-Random -Minimum 100000 -Maximum 999999
    $VaultName = $env:KEY_VAULT_NAME
    $sid = Get-AzKeyVaultSecret -VaultName $VaultName -Name $env:TWILIO_SID_SECRET_NAME -AsPlainText
    $token = Get-AzKeyVaultSecret -VaultName $VaultName -Name $env:TWILIO_TOKEN_SECRET_NAME -AsPlainText
    $WebhookUrl = $env:HALO_WEBHOOK_URL
    $number = $env:TWILIO_PHONE_NUMBER

    # Connect to Microsoft Graph
    $AppId = $env:GRAPH_APP_ID
    $CertificateName = $env:CERTIFICATE_NAME

    if ([string]::IsNullOrWhiteSpace($TenantID)) {
        throw "TenantID cannot be empty"
    }

    # Get the certificate from Key Vault
    $Certificate = Get-KeyVaultCertificate -VaultName $VaultName -CertificateName $CertificateName

    # Connect using the certificate
    Connect-MgGraph -ClientId $AppId -TenantId $TenantID -Certificate $Certificate

    if (-not (Get-MgContext)) {
        throw "Failed to obtain Graph context"
    }

    # Get MFA methods
    $MFAPhone = $null
    [array]$MFAData = Get-MgUserAuthenticationMethod -UserId $HaloUser
    $AuthenticationMethod = @()
    $AdditionalDetails = @()
    
    foreach ($MFA in $MFAData)
    {
        Switch ($MFA.AdditionalProperties["@odata.type"])
        {
            "#microsoft.graph.passwordAuthenticationMethod"
            {
                $AuthMethod = 'PasswordAuthentication'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"
            {
                # Microsoft Authenticator App
                $AuthMethod = 'AuthenticatorApp'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
                $MicrosoftAuthenticatorDevice = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.phoneAuthenticationMethod"
            {
                # Phone authentication
                $AuthMethod = 'PhoneAuthentication'
                $AuthMethodDetails = $MFA.AdditionalProperties["phoneType", "phoneNumber"] -join ' '
                $MFAPhone = $MFA.AdditionalProperties["phoneNumber"]
            }
            "#microsoft.graph.fido2AuthenticationMethod"
            {
                # FIDO2 key
                $AuthMethod = 'Fido2'
                $AuthMethodDetails = $MFA.AdditionalProperties["model"]
            }
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"
            {
                # Windows Hello
                $AuthMethod = 'WindowsHelloForBusiness'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.emailAuthenticationMethod"
            {
                # Email Authentication
                $AuthMethod = 'EmailAuthentication'
                $AuthMethodDetails = $MFA.AdditionalProperties["emailAddress"]
            }
            "microsoft.graph.temporaryAccessPassAuthenticationMethod"
            {
                # Temporary Access pass
                $AuthMethod = 'TemporaryAccessPass'
                $AuthMethodDetails = 'Access pass lifetime (minutes): ' + $MFA.AdditionalProperties["lifetimeInMinutes"]
            }
            "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod"
            {
                # Passwordless
                $AuthMethod = 'PasswordlessMSAuthenticator'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.softwareOathAuthenticationMethod"
            {
                $AuthMethod = 'SoftwareOath'
                $Is3rdPartyAuthenticatorUsed = "True"
            }
            
        }
        $AuthenticationMethod += $AuthMethod
        if ($AuthMethodDetails -ne $null)
        {
            $AdditionalDetails += "$AuthMethod : $AuthMethodDetails"
        }
    }
    #To remove duplicate authentication methods
    $AuthenticationMethod = $AuthenticationMethod | Sort-Object | Get-Unique
    $AuthenticationMethods = $AuthenticationMethod -join ","
    $AdditionalDetail = $AdditionalDetails -join ", "

    # Check if MFAPhone is available
    if (-not $MFAPhone) {
        throw "User does not have a registered phone for MFA"
    }

    # Generate HTML response
    $Note = @"
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border-radius: 10px;
            background: linear-gradient(145deg, #ffffff, #f0f0f0);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

    <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #2c3e50; margin: 0; padding: 10px; font-size: 24px; border-bottom: 2px solid #3498db;">
            Identity Verification Details
        </h1>
    </div>
    
    <div style="background: #3498db; color: white; padding: 20px; border-radius: 8px; text-align: center; margin: 15px 0;">
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 3px;">$Random</div>
        <div style="font-size: 14px; margin-top: 5px;">Verification Code</div>
    </div>

    <!-- Request Information -->
    <div style="background: #fff; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #2ecc71;">
        <div style="font-size: 14px; color: #7f8c8d; margin-bottom: 5px;">Request Information</div>
        <div style="color: #2c3e50; margin-bottom: 3px;">
            <strong>Request ID:</strong> $RequestID
        </div>
        <div style="color: #2c3e50; margin-bottom: 3px;">
            <strong>Timestamp:</strong> $Timestamp
        </div>
        <div style="color: #2c3e50;">
            <strong>Target Number:</strong> $MFAPhone
        </div>
    </div>

    <!-- User Details -->
    <div style="background: #fff; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #e74c3c;">
        <div style="font-size: 14px; color: #7f8c8d; margin-bottom: 5px;">User Details</div>
        <div style="color: #2c3e50; margin-bottom: 3px;
                    white-space: normal;
                    word-break: break-word;
                    overflow-wrap: break-word;">
            <strong>User:</strong> $HaloUser
        </div>
        <div style="color: #2c3e50; margin-bottom: 3px;">
            <strong>Tenant:</strong> $TenantID
        </div>
    </div>

    <!-- Authentication Methods -->
    <div style="background: #fff; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #f1c40f;">
        <div style="font-size: 14px; color: #7f8c8d; margin-bottom: 5px;">Authentication Methods</div>
        <div style="color: #2c3e50; margin-bottom: 3px;
                    white-space: normal;
                    word-break: break-word;
                    overflow-wrap: break-word;">
            <strong>Methods:</strong> $AuthenticationMethods
        </div>
        <div style="color: #2c3e50;
                    white-space: normal;
                    word-break: break-word;
                    overflow-wrap: break-word;">
            <strong>Details:</strong> $AdditionalDetail
        </div>
    </div>

    <!-- Twilio Response -->
    <div style="background: #27ae60; color: white; padding: 10px; border-radius: 5px; text-align: center; margin-top: 20px;">
        <span style="font-size: 16px;">Microsoft Authenticator Response: Success</span>
    </div>
</div>
"@

    # Send response to Halo webhook
    $headers = @{
        'Content-Type' = 'application/json'
    }

    $HaloResponsePayload = @{
        "TicketID" = $TicketID
        "VerificationResponse" = $Note
    }

    $JsonPayload = $HaloResponsePayload | ConvertTo-Json
    $Response = Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $JsonPayload -Headers $headers -ErrorAction Stop
    
}
catch {
    Write-ErrorResponse -Message "An error occurred: $($_.Exception.Message)"
}
