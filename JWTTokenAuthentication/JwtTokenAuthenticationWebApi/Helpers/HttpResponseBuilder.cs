using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Web;

namespace JwtTokenAuthenticationWebApi.Helpers
{
    public class HttpResponseBuilder
    {
        public static HttpResponseMessage CreateUnauthorizedResponse(HttpRequestMessage request)
        {
            return request.CreateResponse(HttpStatusCode.Unauthorized, "Unauthorized request.", new JsonMediaTypeFormatter());
        }

        public static HttpResponseMessage CreateOKResponse(HttpRequestMessage request, String body)
        {
            return request.CreateResponse(HttpStatusCode.OK, body, new JsonMediaTypeFormatter());
        }
    }
}