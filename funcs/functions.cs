using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Linq;
using Microsoft.Extensions.Primitives;
using Azure.Identity;
using Microsoft.Identity.Client;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Company.Function
{
    // Function A , B and C should each be deployed to their own consumption function App
    // All require easyauth, the default AAD App created by easyauth is fine and can be modified where required
    // Function B also requires a system assigned MSI as it's call to function C is App to App
    // The client is the JS Spa modified from Wills APIM OBO example to use AAD (instead of B2C)
    // 
    // See GIT readme for more details


    public static class weather
    {
        // manage http client statically for connection pooling/reuse
        private static readonly HttpClient client = new HttpClient();

        [FunctionName("functionA")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,ClaimsPrincipal principal,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            // get the access token used to call this function from the request context
            var userAssertion = GetUserAssertion(log, principal, req );

            // use that to obtain a new access token for the downstream service - the new token still carries the user context from the original
            var accessToken = await GetDownStreamAccessTokenAsync(log, userAssertion);

            log.LogInformation($"The call to functionB has an access token derived from the user-assertion, the token this function received - that token is {accessToken}");

            string url = Environment.GetEnvironmentVariable("DownStreamApiUrl");
 
            var responseBody =await CallDownstreamApi(log,url, accessToken);

            log.LogInformation($"response from {url} - {responseBody}");
        
            return new OkObjectResult("All good here, function 1 ran to completion.");
        }


        // api 2 for the client (api 1)
        [FunctionName("functionB")]
        public static async Task<IActionResult> Run2(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,ClaimsPrincipal principal,
            ILogger log )
        {
            log.LogInformation("C# HTTP trigger function 2 processed a request.");
        
            string url = Environment.GetEnvironmentVariable("DownStreamApiUrl");
        
            // resource here is the token audience we are requesting , the token will be derived from the managed identity and the role included
            // because the managed identity has the role permission from the downstream AAD app representing the downstream API
            var accessToken = await GetManagedIdentityAccessTokenAsync(resource:"f7a808fd-3b94-4ca6-9e62-52fc8e50fa22");
            log.LogInformation($"The token to call functionC has an access token obtained from the MSI for function B- that token is {accessToken}");
            
            var responseBody =await CallDownstreamApi(log,url, accessToken);
            log.LogInformation($"response from {url} - {responseBody}");

            return new OkObjectResult("All good here, function 2 ran to completion.");
        }

        // api 3 for the client (api 2)
        [FunctionName("functionC")]
        public static async Task<IActionResult> Run3(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,ClaimsPrincipal principal,
            ILogger log)
        {
            // easy auth provides the token checking as per other functions
            log.LogInformation("C# HTTP trigger function 3 processed a request. This function does nothing except get called.");

            return new OkObjectResult("All good here, function 3 ran to completion.");
        }

        private static UserAssertion GetUserAssertion(ILogger log, ClaimsPrincipal principal, HttpRequest req){
            
            if ( null == principal ){
                throw new Exception("Claims Principal was null");
            }

            var scopeClaim = principal.FindFirst("http://schemas.microsoft.com/identity/claims/scope");
            if (scopeClaim == null || (!scopeClaim.Value.Contains("hello")))
            {
                throw new Exception($"expected 'hello' scope, got '{scopeClaim.Value}' instead"); // 
            }
            
            string bootstrapContext =null;
            StringValues values;
            // could probably do this better....
            if ( req.Headers.TryGetValue("Authorization", out values) && values.Count> 0 && values[0].Contains("Bearer ")){
                bootstrapContext = values[0].Split(' ')[1];
            }

            if ( null == bootstrapContext){
                throw new Exception("Couldnt read an access token from the request");
            }

            log.LogInformation($"boostrapcontext {bootstrapContext}");

            return new UserAssertion(bootstrapContext, "urn:ietf:params:oauth:grant-type:jwt-bearer");
        }

        private static async Task<string> GetDownStreamAccessTokenAsync(ILogger log, UserAssertion userAssertion){
                        // easy auth keys
            var appKey = Environment.GetEnvironmentVariable("MICROSOFT_PROVIDER_AUTHENTICATION_SECRET");
            var clientId = Environment.GetEnvironmentVariable("WEBSITE_AUTH_CLIENT_ID");
            var openidIssuer = Environment.GetEnvironmentVariable("APPSETTING_WEBSITE_AUTH_OPENID_ISSUER");

            // in most identity samples the authority is concat from the login url (for AAD) and the tenant id
            // as it happens functions does contain a setting but probably wrong to take a hard dependency on this
            // better to add login + tenant as per msal / identity samples
            var authority = openidIssuer.Replace("sts.windows.net","login.microsoftonline.com").Replace("/v2.0", "");

            // use MSAL to obtain the token
            // there is a missing piece - no caching!
            // MSAL Microsoft.Identity.Web contains some out of the box implementations which can be wired in
            // we think functions would probably need a distributed cache (e.g. not in memory)
            // but, it depends on the context and scale characteristics of the real function
            var app = ConfidentialClientApplicationBuilder.Create(clientId)
                   .WithAuthority(authority)
                   .WithClientSecret(appKey)
                   .Build();

            // scope for the downstream API - e.g. the downstream API AAD app client ID - which is part of the URI and the permission we're requesting as part of the onward request OBO this user
            string[] scopes = { "api://8285da4c-7e80-4f32-9465-18bad92fdf30/helloagain" };

            // Acquiring an AuthenticationResult for the scope representing the downstream api and delegated permission, 
            // impersonating the user represented by userAssertion, using the OBO flow
            AuthenticationResult result = await app.AcquireTokenOnBehalfOf(scopes, userAssertion)
                    .ExecuteAsync();

            string accessToken = result.AccessToken;
            if (accessToken == null)
            {
                throw new Exception("Access Token could not be acquired.");
            }

            return accessToken;
        }

        private static async Task<string> GetManagedIdentityAccessTokenAsync(string resource)
        {
            // obsolete now
            //var tokenProvider = new AzureServiceTokenProvider("RunAs=App;");
            //return await tokenProvider.GetAccessTokenAsync("f7a808fd-3b94-4ca6-9e62-52fc8e50fa22");
 
            // new way
            var credential = new ManagedIdentityCredential();
            var token = await credential.GetTokenAsync(
                new Azure.Core.TokenRequestContext(
                    new[] { resource }));

            return token.Token;

        }

        private static async Task<string> CallDownstreamApi(ILogger log, string url, string accessToken){
            
            var responseBody = "";
            // Call asynchronous network methods in a try/catch block to handle exceptions.
            try	
            {
                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer",accessToken);
                responseBody = await client.GetStringAsync(url);
            
            }
            catch(HttpRequestException e)
            {
                log.LogInformation("\nException Caught!");	
                log.LogInformation("Message :{0} ",e.Message);
            }

            return responseBody;
        }
    }
}

