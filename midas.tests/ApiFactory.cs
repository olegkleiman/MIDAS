
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using midas;
using midas.Services.JWT;
using midas.Services.Membership;
using midas.Services.OTP;
using midas.Services.SMS;

public class ApiFactory : WebApplicationFactory<midas.Program>
{
    public IMembershipService MembershipMock { get; private set; } = null!;
    public IOTPService OtpMock { get; private set; } = null!;
    public ISMSService SmsMock { get; private set; } = null!;
    public ITokenService JwtMock { get; private set; } = null;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Убираем реальные зависимости
            services.RemoveAll(typeof(IMembershipService));
            services.RemoveAll(typeof(IOTPService));
            services.RemoveAll(typeof(ISMSService));
            services.RemoveAll(typeof(ITokenService));

            // Создаем моки
            MembershipMock = NSubstitute.Substitute.For<IMembershipService>();
            OtpMock = NSubstitute.Substitute.For<IOTPService>();
            SmsMock = NSubstitute.Substitute.For<ISMSService>();
            JwtMock = NSubstitute.Substitute.For<ITokenService>();

            // Регистрируем замену
            services.AddSingleton(MembershipMock);
            services.AddSingleton(OtpMock);
            services.AddSingleton(SmsMock);
            services.AddSingleton(JwtMock);
        });
    }
}

