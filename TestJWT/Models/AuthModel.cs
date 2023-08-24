using System.Text.Json.Serialization;

namespace TestJWT.Models
{
    public class AuthModel
    {
        public string Message { get; set; }
        public bool IsAuthticated { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; }
        public string Token { get; set; }
        //public DateTime ExpiesOn { get; set; }
        [JsonIgnore]
        public string? RefreshToken { get; set; }
        public  DateTime RefreshtokenExpiration { get; set; }
    }
}
