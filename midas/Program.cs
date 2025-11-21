
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using midas.Models;
using midas.Models.Tables;
using midas.Services.Db;
using midas.Services.JWT;
using midas.Services.Membership;
using midas.Services.Oid;
using midas.Services.OTP;
using midas.Services.SMS;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace midas
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Bind config sections to the related services before building the app
            builder.Services.Configure<SMSSendOptions>(builder.Configuration.GetSection("SmsServiceOptions"));
            builder.Services.Configure<JWTIssuerOptions>(builder.Configuration.GetSection("JWTIssuerOptions"));
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

            builder.Services.AddScoped<IMembershipService, MembershipService>();
            builder.Services.AddScoped<IOTPService, OTPService>();
            builder.Services.AddSingleton<IJWTIssuerService, JWTIssuerService>();
            builder.Services.AddSingleton<IOidService, OidService>();

            // Add services to the container.
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
                    if( !membershipService.IsMember(userId, phoneNum) )
                    {
                        return Results.Ok(new TLVOAuthErrorResponse()
                        {
                            ErrorDesc = Resources.no_customer,
                            IsError = true,
                            ErrorId = 14
                        });
  
                    }
                    logger.LogInformation($"Membership validated for phone number: '{phoneNum}'");

                    string otp = otpService.Generate();
                    if( otpService.Save(userId, phoneNum, otp) )
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
                                            IJWTIssuerService jwtIssuer,
                                            IOidService oidService) =>
            {
                try
                {
                    string? userId = otpService.RetrieveUserId(request.code);
                    if( string.IsNullOrEmpty(userId) )
                        return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.unknown_otp, errorId: 10));

                    var oid = oidService.RetrieveOID(userId);

                    var tokens = await jwtIssuer.IssueForSubject(oid);
                    return Results.Ok(tokens);
                }
                catch(Exception ex)
                {                     
                    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: ex.Message, errorId: 11));
                }   

            })
            .WithName("Login")
            .WithOpenApi();

            ///<summary>
            /// Decode and validate the passed token (JWT assumed)
            ///</summary>
            ///<returns>
            /// The list of verified claims
            ///</returns>
            app.MapPost("/api/tokeninfo", (IJWTIssuerService jwtIssuer,
                                           [FromServices] OidService oidService,
                                           [FromBody] VerifyFormData formData) =>
            {
                IEnumerable<Claim> claims = jwtIssuer.VerifyToken(formData.token);
                var oid = (from c in claims
                        where c.Value == JwtRegisteredClaimNames.Sub
                        select c).FirstOrDefault();
 
                var userId = oidService.RetrieveUserId(oid.Value);
                var claimList = claims.ToList();
                claimList.RemoveAll(c => c.Value == JwtRegisteredClaimNames.Sub);
                claimList.Add(new Claim(JwtRegisteredClaimNames.Sub, oid.ToString()));

                return Results.Ok(claims);
            });

            /// <summary>
            /// This method receives the refresh token and, if verified, issues the set of new tokens
            /// </summary>
            /// Because refresh token was previosuly encrypted with AES, it may contain '+' (plus) charachters
            /// For URL query parameters, this '+' is automatically replaced with ' ' (space) that eventually 
            /// URL encoding convention.
            /// To prevent such replacement, POST verb is used.
            app.MapPost("/refresh_token", 
                    [AllowAnonymous] (ILogger<Program> logger,
                                     [FromBody] RefreshTokenFormData body) =>
            {

            });

            app.Run();
        }
    }
}
