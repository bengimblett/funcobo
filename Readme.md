# Functions with MSAL example

## context

JS SPA Client (MSAL.JS) => Calls Function A => Calls Function B (on behalf of) => Calls Function C (this call from B to C is using a token derived from the MSI)

For details on a number of steps see https://docs.microsoft.com/en-us/azure/api-management/howto-protect-backend-frontend-azure-ad-b2c 

## prerequisites

Create an AAD app for the Client SPA as per the APIM instructions linked above

### Function Apps

Deploy 3 consumption function Apps , one for each function

Each function App requires EasyAuth for AAD Provider to be turned on

Add a delegated permission to functionA AAD app and consume the permission in the client AAD app.
Do the same between function App A and function App B AAD Apps, also as per instructions for the APIM walkthrough

Function App B needs system managed MSI assigned. Note: This wil create a SP with the same name as the easy auth AAD app SP.
Two SPs, same name, different type.
In AAD go to "enterprise apps", filter by type "managed identity etc"

A app role permission needs adding on Function App C - this can be consumed with the PS1 below

Powershell is required to add the app role permission exposed from Function C so that function B AAD app can consume it. 
This is not currently possible via the UI

```Powershell
# Install the module. (You need admin on the machine.)
# Install-Module AzureAD

# Your tenant ID (in the Azure portal, under Azure Active Directory > Overview).
$tenantID = '355fffe7-b699-45c3-965a-8e6bd45406c1'

# The name of your web app, which has a managed identity that should be assigned to the server app's app role.
$webAppName = 'FunctionAppB'
$resourceGroupName = 'func-to-func-aad'

# The name of the server app that exposes the app role.
$serverApplicationName = 'FunctionAppC' # For example, MyApi

# The name of the app role that the managed identity should be assigned to.
$appRoleName = 'helloyetagain' # role value

# Look up the web app's managed identity's object ID.
$managedIdentityObjectId ='b5c56b49-8f44-4d80-97e7-38e94a6ed25a' # assigned direct, filter "Enterprise apps by 'managed identity'... 
# when you create a managed identity you get a service principal of the same name as the app, in the case of funcs + easyauth that means 2 SPs of the same name, but different type!
#(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $webAppName).identity.principalid

Connect-AzureAD -TenantId $tenantID

# Look up the details about the server app's service principal and app role.
$serverServicePrincipal = (Get-AzureADServicePrincipal -Filter "DisplayName eq '$serverApplicationName'")
$serverServicePrincipalObjectId = $serverServicePrincipal.ObjectId
$appRoleId = ($serverServicePrincipal.AppRoles | Where-Object {$_.Value -eq $appRoleName }).Id

# Assign the managed identity access to the app role.
New-AzureADServiceAppRoleAssignment `
    -ObjectId $managedIdentityObjectId `
    -Id $appRoleId `
    -PrincipalId $managedIdentityObjectId `
    -ResourceId $serverServicePrincipalObjectId

#Example output
#    ObjectId                                    ResourceDisplayName PrincipalDisplayName
#--------                                    ------------------- --------------------
#SWvFtUSPgE2X5zjpSm7SWp6C-1Obr7xMsYExOApurJA functionAppC        FunctionAppB   
```

### Alter index.html MSAL JS config

This will need to be hosted in a storage web$ static hosting container

Deploy to the storage account and check the user can be logged in (OIDC)

```Javascript
     		var config = {
     			msal: {
     				auth: {
     					clientId: "{client id, front end app}", // This is the client ID of your FRONTEND application that you registered with the SPA type in AAD B2C
     					authority:  "https://login.microsoftonline.com/{AAD Tenant ID here}", // 
     					redirectUri: "{storage static hosting url}" // hosting url e.g. https://begimhosting.z16.web.core.windows.net/
     				},
     				cache: {
     					cacheLocation: "sessionStorage",
     					storeAuthStateInCookie: false 
     				}
     			},
     			api: {
     				scopes: ["api://{downstream app client id}/{permission}"], // The scope that we request for the API from B2C, this should be the backend API scope, with the full URI.
     				backend: "{downstream FunctionA URL}" // The location that we will call for the backend api, this should be hosted in API Management, suffixed with the name of the API operation (in the sample this is '/hello').
     			}
     		}
```

### Special note

At the time of writing - AAD EasyAuth v2 is slightly confusing in how it validates the audience.
This is being addressed
In the interim alter each function manifest and set the access token to be v2 through the APP Manifest "accessTokenAcceptedVersion" property 
This forces the token Aud claim to be a guid (rather than a uri)

It should be noted MSAL will allow you to provide a downstream scope as "{clientid}/{permission}" rather than "{uri}/{permission}"


## WIP NOTES

Front end SPA setup
AAD app setup
Exposed permissions
Consuming – and consent
MSAL 
Token caching extension to MSAL to prevent repeated calls to login/token endpoint
Bootstrapcontext missing in the function
If you set MSI + EasyAuth , you’ll get an AAD app + SP from EasyAuth AND an SP (of the same name!) from the MSI
Use the senders access token for OBO as an assertion, use client credentials flow with azure-default-credentials for a non OBO flow (app to app via MSI
OBO Token version issue when using Easy Auth
Why not x-ms-token-aad-access-token?
