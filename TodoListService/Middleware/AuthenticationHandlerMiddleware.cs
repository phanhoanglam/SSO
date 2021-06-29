using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace TodoListService.Middleware
{
    public class AuthenticationHandlerMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthenticationHandlerMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await VerifyToken(context);
            }
            catch (Exception exception)
            {
                switch (exception)
                {
                    case SecurityTokenExpiredException e:
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        break;
                    case SecurityTokenException e:
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        break;
                    default:
                        // unhandled error
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        break;
                }
                //var result = JsonSerializer.Serialize(new { message = exception?.Message });
                await context.Response.WriteAsync(exception?.Message);
                return;
            }

            await _next(context);
        }

        public async Task VerifyToken(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (String.IsNullOrEmpty(token))
            {
                throw new SecurityTokenException();
            }
            var configuration = Startup.Configuration.GetSection("AzureAd");

            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(configuration["OpenIDDocument"], new OpenIdConnectConfigurationRetriever());
            var config = await configManager.GetConfigurationAsync();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidAudience = configuration["ClientId"],
                ValidIssuer = configuration["Issuer"],
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = false,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["ClientSecret"]))
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var validatedToken = (SecurityToken)new JwtSecurityToken();
            tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            if (validatedToken == null)
            {
                throw new SecurityTokenException();
            }
            if (DateTime.Compare(validatedToken.ValidTo, DateTime.UtcNow) <= 0)
            {
                throw new SecurityTokenExpiredException("The incoming token has expired. Get a new access token from the Authorization Server.");
            }
        }
    }
}
