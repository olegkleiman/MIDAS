using Azure.Core;
using Microsoft.AspNetCore.Http;
using midas.Services.JWT;
using StackExchange.Redis;

namespace midas.Services.Cache
{
    public class CacheService(IDatabase cache,
                              ILogger<CacheService> logger) : ICacheService
    {
        private readonly IDatabase _cache = cache;
        private readonly ILogger<CacheService> _logger = logger;

        public bool FindToken(string jti)
        {
            try
            {
                RedisKey redisKey = new(jti);
                HashEntry[] entries = _cache.HashGetAll(redisKey);
                return entries.Length != 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(new Exception(), ex.Message);
                throw;
            }   
        }


        /// <summary>
        /// Add the JWE to Redis index by the key that extracted from header
        /// The value of the key is the JWE itself
        /// The TTL of the key is the expiration time of the JWE - current time (if positive)
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public bool AddToken(string token)
        {
            try
            {
                var jweHeader = TokenService.JweHeader(token);
                if (jweHeader == null) 
                    return false;

                var jtiValue = jweHeader["jti"];
                string? jti = jtiValue.ToString();
                if( jti == null )
                    return false;
                if( FindToken(jti)) // already exists  
                    return true;

                var expValue = jweHeader["exp"];
                string? exp = expValue.ToString();
                if (exp == null)
                    return false;
                long nExp = long.Parse(exp);

                var expDate = DateTimeOffset.FromUnixTimeSeconds(nExp).UtcDateTime;
                var ttl = expDate - DateTime.UtcNow; // exp - now
                if (ttl <= TimeSpan.Zero)
                    ttl = TimeSpan.Zero;

                RedisKey redisKey = new(jti);
                HashEntry[] entries = [new("jwe", token)];

                _cache.HashSet(redisKey, entries);
                _cache.KeyExpire(redisKey, ttl);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(new Exception(), message: ex.Message);
                throw;
            }
        }
    }
}
