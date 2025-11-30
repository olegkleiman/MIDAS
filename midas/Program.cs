
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using midas.Models;
using midas.Services.Cache;
using midas.Services.Db;
using midas.Services.JWT;
using midas.Services.Membership;
using midas.Services.Oid;
using midas.Services.OTP;
using midas.Services.SMS;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using static System.Net.Mime.MediaTypeNames;

namespace midas
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Bind config sections to the related services before building the app
            builder.Services.Configure<SMSSendOptions>(builder.Configuration.GetSection("SmsServiceOptions"));
            builder.Services.Configure<TokenOptions>(builder.Configuration.GetSection("TokenOptions"));
            builder.Services.Configure<OidcOptions>(builder.Configuration.GetSection("OidcOptions"));

            builder.Services.AddDbContext<HRDbContext>(options =>
                options.UseSqlServer(
                     builder.Configuration.GetConnectionString("HRData")
            ));
            builder.Services.AddDbContext<OTPDbContext>(options =>
                options.UseSqlServer(
                    builder.Configuration.GetConnectionString("SSO_DB")
            ));

            builder.Services.AddHttpClient<ISMSService, SMSService>((sp, client) =>
            {
                var options = sp.GetRequiredService<IOptions<SMSSendOptions>>().Value;
                client.BaseAddress = new Uri(options.EndpointUrl);
            });

            builder.Services.AddScoped<IDatabase>(cfg =>
            {
                string? redisConnectionString = builder.Configuration.GetConnectionString("Redis_Cache");
                ConnectionMultiplexer multiplexer = ConnectionMultiplexer.Connect(redisConnectionString);
                return multiplexer.GetDatabase();
            });

            // Scoped services live per HTTP request.
            builder.Services.AddScoped<IMembershipService, MembershipService>();
            builder.Services.AddScoped<IOTPService, OTPService>();
            builder.Services.AddScoped<ICacheService, CacheService>();
            builder.Services.AddScoped<ITokenService, TokenService>();

            // Singletons live for the entire application lifetime.
            builder.Services.AddSingleton<IOidService, OidService>();

            builder.Services.AddAuthorization();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            IdentityModelEventSource.ShowPII = true;

            app.UseAuthorization();

            app.MapGet("/api/otp", async (
                [FromQuery(Name = "id")] string userId,
                [FromQuery(Name = "phoneNum")] string phoneNum,
                HttpContext httpContext,
                IOTPService otpService,
                ISMSService smsService,
                IMembershipService membershipService,
                ILogger<Program> logger) =>
            {
                try
                {
                    if (!membershipService.IsMember(userId, phoneNum))
                        return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.no_customer, errorId: 14));

                    logger.LogInformation($"Membership validated for phone number: '{phoneNum}'");

                    string otp = otpService.Generate();
                    if (otpService.Save(userId, phoneNum, otp))
                        await smsService.Send(phoneNum, otp);

                    return Results.Ok();
                }
                catch (ApplicationException ex)
                {
                    logger.LogError(ex.Message);
                    return Results.Ok(new TLVOAuthErrorResponse()
                    {
                        ErrorDesc = ex.Message,
                        IsError = true,
                        ErrorId = 12
                    });
                }

            })
            .WithName("RequestOTP")
            .WithOpenApi();

            app.MapPost("/api/token", async ([FromBody] OTPDto request,
                                            IOTPService otpService,
                                            ITokenService jwtIssuer,
                                            IOidService oidService) =>
            {
                try
                {
                    string? userId = otpService.RetrieveUserId(request.code);
                    if( string.IsNullOrEmpty(userId) )
                        return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.unknown_otp, errorId: 10));

                    var tokens = await jwtIssuer.IssueJWEForSubject(userId);
                    return Results.Ok(tokens);
                }
                catch (Exception ex)
                {
                    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: ex.Message, errorId: 11));
                }

            })
            .WithName("Login")
            .WithOpenApi();

            ///<summary>
            /// Decode and validate the passed token (JWE assumed)
            ///</summary>
            ///<returns>
            /// The list of verified claims 
            ///</returns>
            app.MapPost("/api/tokeninfo", async ([FromBody] VerifyFormData formData,
                                            [FromServices] ITokenService tokenService,
                                            [FromServices] ICacheService cache
                                           ) =>
            {
                try
                {
                    var token = formData.token;
                    var jweHeader = TokenService.JweHeader(token);
                    if (jweHeader == null)
                        return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.invalid_token, errorId: 20));
                    var jti = jweHeader["jti"];
                    if ( jti is null)
                        return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.invalid_token, errorId: 19));
                    if (cache.FindToken(jti.ToString()))
                    {
                        return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.error_revoked_token, errorId: 18));
                    }

                    var claims = await tokenService.ValidateJweToken(token);

                    return Results.Ok(claims);
                }
                catch (Exception ex)
                {
                    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: ex.Message, errorId: 21));
                }
            })
            .WithName("UserDetails")
            .WithOpenApi();

            /// <summary>
            /// Revokes the passed token (refresh token or JWE)
            /// </summary>
            app.MapPost("/api/revoke", async ([FromBody] VerifyFormData formData,
                                          [FromServices] IOTPService otpService,
                                          [FromServices] ICacheService cache) =>
            {
                // Determine which token is revoked - refresh token or JWE
                string token = formData.token;
                string[] parts = token.Split('.');
                
                if ( parts.Length == 5 )
                {
                    cache.AddToken(token);
                    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: string.Empty, isError: false));
                }

                if ( !otpService.IsRefreshTokenValid(token) )
                    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.invalid_token, errorId: 20));
                otpService.DeleteRefreshToken(token);

                return Results.Ok(new TLVOAuthErrorResponse(errorDesc: string.Empty, isError: false));
            });

            /// <summary>
            /// This method receives the refresh token and, if verified, issues the set of new tokens
            /// </summary>
            /// Because refresh token was previosuly encrypted with AES, it may contain '+' (plus) charachters
            /// For URL query parameters, this '+' is automatically replaced with ' ' (space) that eventually 
            /// URL encoding convention.
            /// To prevent such replacement, POST verb is used.
            app.MapPost("/api/refresh_token",
                     [AllowAnonymous] async (ILogger<Program> logger,
                                     [FromServices] ITokenService tokenService,
                                     [FromBody] RefreshTokenFormData body) =>
            {
                try
                {
                    var tokens = await tokenService.RefreshTokens(body.refresh_token);
                    return Results.Ok(tokens);
                }
                catch (Exception ex)
                {
                    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: ex.Message, errorId: 10));
                }

            })
            .WithName("RefreshTokens")
            .WithOpenApi(); ;

            app.Run();
        }
    }
}
