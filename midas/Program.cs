
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using midas.Models;
using midas.Services.Db;
using midas.Services.JWT;
using midas.Services.Membership;
using midas.Services.Oid;
using midas.Services.OTP;
using midas.Services.SMS;

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

            builder.Services.AddScoped<IMembershipService, MembershipService>();
            builder.Services.AddScoped<IOTPService, OTPService>();
            builder.Services.AddSingleton<ITokenService, TokenService>();
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
                    if (string.IsNullOrEmpty(userId))
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
                                            [FromServices] ITokenService tokenService
                                           ) =>
            {
                var claims = await tokenService.VerifyJWE(formData.token);
                return Results.Ok(claims);

                //IEnumerable<Claim> claims = await jwtIssuer.VerifyJWT(formData.token);
                //var oid = (from c in claims
                //            where c.Type == ClaimTypes.NameIdentifier
                //            select c).FirstOrDefault();
                //if( oid == null )
                //    return Results.Ok(new TLVOAuthErrorResponse(errorDesc: Resources.no_customer, errorId: 14));

                //var userId = oidService.RetrieveUserId(oid.Value);

                //var claimList = from claim in claims
                //                select new
                //                {
                //                    Type = claim.Type,
                //                    Value = claim.Type == ClaimTypes.NameIdentifier ? userId : claim.Value
                //                };  

                //return Results.Ok(claimList);
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
