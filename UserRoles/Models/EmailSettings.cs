namespace UserRoles.Models
{
    public class EmailSettings
    {
        public string SmtpServer { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Sender { get; set; } = string.Empty;
        public string From { get; set; }    =   string.Empty;
    }
}
