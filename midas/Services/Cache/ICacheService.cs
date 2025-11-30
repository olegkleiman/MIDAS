namespace midas.Services.Cache
{
    public interface ICacheService
    {
        bool FindToken(string token);
        bool AddToken(string token);
    }
}
