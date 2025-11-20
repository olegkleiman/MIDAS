
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using midas.Models;
using midas.Services.JWT;
using midas.Services.Membership;
using midas.Services.OTP;
using midas.Services.SMS;
using Newtonsoft.Json.Linq;

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

            builder.Services.AddScoped<SqlConnection>(serviceProvider =>
            {
                var config = serviceProvider.GetRequiredService<IConfiguration>();
                var connectionString = config.GetConnectionString("HRData");
                return new SqlConnection(connectionString);
            });

            builder.Services.AddHttpClient<ISMSService, SMSService>((sp, client) =>
            {
                var options = sp.GetRequiredService<IOptions<SMSSendOptions>>().Value;
                client.BaseAddress = new Uri(options.EndpointUrl);
            });

            builder.Services.AddSingleton<IMembershipService, MembershipService>();
            builder.Services.AddSingleton<IOTPService, OTPService>();
            builder.Services.AddSingleton<IJWTIssuerService, JWTIssuerService>();

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
                    if (!await membershipService.IsMember(phoneNum))
                    {
                        return Results.Ok(Resources.no_customer);
                    }

                    string otp = otpService.Generate();
                    await otpService.Save(otp);

                    await smsService.Send(phoneNum, otp);

                    return Results.Ok();
                }
                catch (ApplicationException ex)
                {
                    logger.LogError(ex.Message);
                    return Results.Ok(new TLVOAuthErroeResponse()
                    {
                        ErrorDesc = ex.Message,
                        IsError = true
                    });
                }

            })
            .WithName("RequestOTP")
            .WithOpenApi();

            app.MapPost("/api/token", async ([FromBody] OTPDto request,
                                            IOTPService otpService,
                                            IJWTIssuerService jwtIssuer) =>
            {
                try
                {
                    string? oid = await otpService.RetrieveOID(request.code);
                    if (string.IsNullOrEmpty(oid) )
                    {
                        return Results.Ok("Unknown OTP");
                    }

                    var tokens = await jwtIssuer.IssueForSubject(oid);
                    return Results.Ok(tokens);
                }
                catch(Exception ex)
                {                     
                    return Results.Ok(new TLVOAuthErroeResponse()
                    {
                        ErrorDesc = ex.Message,
                        IsError = true
                    });
                }   

            })
            .WithName("Login")
            .WithOpenApi();


            app.Run();
        }
    }
}
