
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using midas.Models;
using midas.Services.Membership;
using midas.Services.OTP;
using midas.Services.SMS;

namespace midas
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Bind SMS section to SMSServiceOptions before building the app
            builder.Services.Configure<SMSSendOptions>(builder.Configuration.GetSection("SmsServiceOptions"));

            builder.Services.AddScoped<SqlConnection>(serviceProvider =>
            {
                var config = serviceProvider.GetRequiredService<IConfiguration>();
                var connectionString = config.GetConnectionString("UserInfo");
                return new SqlConnection(connectionString);
            });

            builder.Services.AddHttpClient<ISMSService, SMSService>((sp, client) =>
            {
                var options = sp.GetRequiredService<IOptions<SMSSendOptions>>().Value;
                client.BaseAddress = new Uri(options.EndpointUrl);
            });

            builder.Services.AddSingleton<IMembershipService, MembershipService>();
            builder.Services.AddSingleton<IOTPService, OTPService>();

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

            app.MapGet("/otp", (string id, string phoneNum, 
                                HttpContext httpContext,
                                IOTPService otpService,
                                ISMSService smsService,
                                IMembershipService benefitsService) =>
            {
                benefitsService.IsMember(phoneNum);

                string otp = otpService.Generate();
                ////otpService.Save();

                smsService.Send(phoneNum, otp);

                return Results.Ok(new { OTP = "123456" });
            })
            .WithName("RequestOTP")
            .WithOpenApi();

            app.MapPost("/api/token", async (OTPFormData request,
                                             SqlConnection conn) =>
            {
                //await conn.OpenAsync();
            });


            app.Run();
        }
    }
}
