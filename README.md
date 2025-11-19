# Microsoft Authenticator Identity Verification Function App

This Azure Function App provides identity verification using Microsoft Authenticator for HaloPSA. It integrates with Microsoft Graph API for user authentication method retrieval.

## Prerequisites

1. An Azure subscription
2. A Microsoft Graph API application registration with:
   - Application (client) ID
   - A certificate for authentication (to be uploaded to Key Vault after deployment)
3. A HaloPSA webhook URL

## Deployment Option 1: Deploy directly to Azure using ARM Template

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcscaminaci%2FSMS-Identity-Verification-for-HaloPSA%2Frefs%2Fheads%2Fmain%2Fazuredeploy.json)

## Deployment Option 2: Deploy Manually with ARM Template

### 1. Fill in the Parameters

Copy `azuredeploy.parameters.json` to `azuredeploy.parameters.local.json` and fill in the values:

```json
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "functionAppName": {
            "value": "your-function-app-name"
        },
        "keyVaultName": {
            "value": "your-keyvault-name"
        },
        "haloWebhookUrl": {
            "value": "your-halo-webhook-url"
        },
        "graphAppId": {
            "value": "your-graph-app-id"
        },
        "certificateName": {
            "value": "your-certificate-name"
        }
    }
}
```

### 2. Deploy the ARM Template

You can deploy the template using Azure CLI or PowerShell:

#### Using Azure CLI

```bash
az group create --name your-resource-group-name --location "East US 2"
az deployment group create --resource-group your-resource-group-name --template-file azuredeploy.json --parameters @azuredeploy.parameters.local.json
```

#### Using PowerShell

```powershell
New-AzResourceGroup -Name your-resource-group-name -Location "East US 2"
New-AzResourceGroupDeployment -ResourceGroupName your-resource-group-name -TemplateFile azuredeploy.json -TemplateParameterFile azuredeploy.parameters.local.json
```

### 3. Upload Graph API Certificate

After deployment, you need to upload your Graph API authentication certificate to the Key Vault with the name specified in the `certificateName` parameter (default: "GraphApiCert").

You can do this through the Azure Portal or using Azure PowerShell:

```powershell
$certPath = "path-to-your-certificate.pfx"
$certPassword = "your-certificate-password"
$keyVaultName = "your-keyvault-name"
$certName = "GraphApiCert"

Import-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certName -FilePath $certPath -Password (ConvertTo-SecureString -String $certPassword -AsPlainText -Force)
```

## Required PowerShell Modules

The function app requires the following PowerShell modules, which are automatically installed based on the requirements.psd1 file:

- Az.Accounts (4.*)
- Az.KeyVault (6.*)
- Az.Automation (1.*)
- Microsoft.Graph.Authentication (2.*)
- Microsoft.Graph.Users (2.*)
- Microsoft.Graph.Groups (2.*)
- Microsoft.Graph.Identity.DirectoryManagement (2.*)
- Microsoft.Graph.Identity.SignIns (2.*)
- Microsoft.Graph.Users.Actions (2.*)

## Function App Configuration

The deployment will automatically configure the following settings in your Function App:

- PowerShell version: 7.4
- .NET Framework version: 8.0
- All necessary environment variables for Twilio, Graph API, and HaloPSA integration

## Security

The deployment includes:
- A system-assigned managed identity for the Function App
- Key Vault access policies for the Function App to access secrets and certificates
- HTTPS-only access
- TLS 1.2 enforcement

## Support

For issues or questions, please open an issue in the GitHub repository.