namespace AuthAPI.Dtos.Auth
{
    public class AuthenticationResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public bool Success { get; set; } = false;
    }
}
