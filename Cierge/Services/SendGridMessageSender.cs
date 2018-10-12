using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Cierge.Services
{
    public class SendGridMessageSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private SendGridClient _emailClient;
        private ILogger _logger;

        public SendGridMessageSender(IConfiguration configuration, ILogger<SendGridMessage> logger)
        {
            _configuration = configuration;
            _emailClient = new SendGridClient(_configuration["SendGrid:ApiKey"]);
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var msg = MailHelper.CreateSingleEmail(new EmailAddress(_configuration["Smtp:From"]), new EmailAddress(email), subject, message, message);
            var result = await _emailClient.SendEmailAsync(msg).ConfigureAwait(false);

            _logger.LogTrace($"[sendgrid] Sent email to {email?.GetHashCode()}.  Status code: " + result.StatusCode);
        }
    }
}
