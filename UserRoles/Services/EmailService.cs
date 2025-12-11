
using Microsoft.AspNetCore.Cors;
using System.Net;
using System.Net.Mail;

namespace UserRoles.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var from = _configuration["EmailSettings:From"];
            var smtpServer = _configuration["EmailSettings:SmtpServer"];
            var Port = int.Parse(_configuration["EmailSettings:Port"]!);
            var Username = _configuration["EmailSettings:Username"];
            var Password = _configuration["EmailSettings:Password"];

            var message = new MailMessage(from!, toEmail, subject, body);
            var isBodyHtml = true;

            using  var client = new SmtpClient(smtpServer, Port);
            {
                client.Credentials = new NetworkCredential(Username, Password);
                client.EnableSsl = true;    
                
            }
            await client.SendMailAsync(message);
        }
    }
}
