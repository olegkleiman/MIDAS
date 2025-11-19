namespace midas.Models
{
    public class TLVOAuthErroeResponse(bool isError = false, string errorDesc = "", int errorId = -1)
    {
        public bool IsError { get; set; } = isError;
        public string ErrorDesc { get; set; } = errorDesc;
        public int ErrorId { get; set; } = errorId;
    }
}
