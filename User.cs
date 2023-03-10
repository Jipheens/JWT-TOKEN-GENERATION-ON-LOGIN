namespace JWT
{
    public class User
    {
        public string username { get; set; } = string.Empty;
        public byte[] PasswordHarsh { get; set; }
        public byte[] PasswordSalt { get; set; }

    }
}
