using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace TokenAuthenticationNetCore.Extensions
{
    public static class UtilityExtensions
    {
        /// <summary>
        /// Returns an instance of HTTPResponseMessage
        /// </summary>
        /// <param name="ResponseBody">JObject to returned as the response body</param>
        /// <param name="ResponseStatusCode">HTTP Status code to be returned</param>
        /// <returns></returns>
        public static ContentResult ReturnResponse(JObject ResponseBody, HttpStatusCode ResponseStatusCode)
        {
            try
            {
                if (ResponseBody == null)
                    throw new ArgumentNullException(nameof(ResponseBody), "Response body to send cannot be null!!");

                string serializedModelResponseBody = JsonConvert.SerializeObject(ResponseBody, new JsonSerializerSettings
                {
                    ContractResolver = new DefaultContractResolver(),
                    Formatting = Formatting.Indented
                });
                
                return new ContentResult
                {
                    Content = serializedModelResponseBody,
                    ContentType = "application/json",
                    StatusCode = (int)ResponseStatusCode
                };
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <returns>Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        public static long ToUnixEpochDate(DateTime date) => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
