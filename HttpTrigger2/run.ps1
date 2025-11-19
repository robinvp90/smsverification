using namespace System.Net

param(
    [Parameter(Mandatory = $true)]
    [object] $Request,
    [Parameter(Mandatory = $false)]
    [object] $TriggerMetadata
)

# Simple response for demonstration
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = @{ message = "Hello from HttpTrigger2!" } | ConvertTo-Json
})
