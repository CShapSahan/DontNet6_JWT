namespace API_JWT
{
    public class User
    {
        public String UserName { get; set; } = string.Empty;
        public byte[] PaswoordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
