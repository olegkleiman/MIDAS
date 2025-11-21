namespace midas.Services.Oid
{
    public interface IOidService
    {
        string RetrieveOID(string userId);
        string RetrieveUserId(string oid);
    }
}
