# This file enables modules to be automatically managed by the Functions service.
# See https://aka.ms/functionsmanageddependency for additional information.
#
@{
    # Core Azure modules
    'Az.Accounts' = '4.*'
    'Az.KeyVault' = '6.*'
    'Az.Automation' = '1.*'
    # Microsoft Graph modules
    'Microsoft.Graph.Authentication' = '2.*'
    'Microsoft.Graph.Users' = '2.*'
    'Microsoft.Graph.Groups' = '2.*'
    'Microsoft.Graph.Identity.DirectoryManagement' = '2.*'
    'Microsoft.Graph.Identity.SignIns' = '2.*'
    'Microsoft.Graph.Users.Actions' = '2.*'
}
