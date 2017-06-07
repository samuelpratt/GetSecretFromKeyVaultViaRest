using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using Jose;
using Newtonsoft.Json.Linq;

namespace GetSecretFromKeyVaultViaRest
{
    class Program
    {
        private static readonly Config Config = new Config();

        public static void Main(string[] argv)
        {
            var authToken = GetAzureBearerJwtToken();
            string keyValue = GetSecret(authToken, Config.SecretName);

            Console.WriteLine($"The value of secret '{Config.SecretName}' is : -");
            Console.WriteLine(keyValue);
        }

        private static string GetSecret(string authToken, string secretName)
        {
            //Build Request
            var httpClient = new HttpClient();
            var requestMessage = new HttpRequestMessage(HttpMethod.Get,
                $"https://{Config.KeyVaultName}.vault.azure.net/secrets/{secretName}/?api-version=2016-10-01");
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authToken);
            var responseTask = httpClient.SendAsync(requestMessage);

            //Send Request
            responseTask.Wait();
            var response = responseTask.Result;
            var responseBodyTask = response.Content.ReadAsStringAsync();
            responseBodyTask.Wait();

            //Extract the Key from the response
            dynamic d = JObject.Parse(responseBodyTask.Result);
            string keyValue = d.value;
            return keyValue;
        }

        private static string GetAzureBearerJwtToken()
        {

            //Build the request
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("resource", "https://vault.azure.net"), //Note the lack of trailing '/'
                new KeyValuePair<string, string>("client_id", Config.AppClientId),
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_assertion", BuildClientAuthJwtToken())
            });

            //Send the request
            var httpClient = new HttpClient();
            var authRequest = httpClient.PostAsync($"https://login.windows.net/{Config.TenantId}/oauth2/token", content);
            authRequest.Wait();
            var result = authRequest.Result;
            result.EnsureSuccessStatusCode();
            var responseBodyTask = result.Content.ReadAsStringAsync();
            responseBodyTask.Wait();

            //Extract the Bearer JWT Token
            dynamic d = JObject.Parse(responseBodyTask.Result);
            string authToken = d.access_token;
            return authToken;
        }

        public static string BuildClientAuthJwtToken()
        {
            var certificate = new X509Certificate2(Config.CertFile, Config.CertPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
            var privateKey = certificate.GetRSAPrivateKey();

            var payload = new Dictionary<string, object>()
            {
                { "aud", $"https://login.windows.net/{Config.TenantId}/oauth2/token"}, //Audience https://tools.ietf.org/html/rfc7519#section-4.1.3
                { "iss", Config.AppClientId }, //Issuer: https://tools.ietf.org/html/rfc7519#section-4.1.1
                { "sub", Config.AppClientId }, //Subject: https://tools.ietf.org/html/rfc7519#section-4.1.2
                { "exp", GetTokenExpiryTime() }, //Expiry https://tools.ietf.org/html/rfc7519#section-4.1.4

            };

            var extraHeaders = new Dictionary<string, object>()
            {
                { "x5t",  Convert.ToBase64String(certificate.GetCertHash()) } //x5t Header: http://self-issued.info/docs/draft-jones-json-web-token-01.html#ReservedHeaderParameterName
            };

            return JWT.Encode(payload, privateKey, JwsAlgorithm.RS256, extraHeaders);
        }

        private static int GetTokenExpiryTime()
        {
            return ToUnixTime(DateTime.UtcNow.AddMinutes(10));
        }

        private static int ToUnixTime(DateTime date)
        {
            return (int)date.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
        }
    }
}
