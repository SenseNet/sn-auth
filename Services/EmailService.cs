using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;
using System.Net.Mail;
using System.Net;

namespace SenseNetAuth.Services;

public class EmailService : IEmailService
{
    private readonly EmailSettings _emailSettings;

    public EmailService(IOptions<EmailSettings> emailSettings)
    {
        _emailSettings = emailSettings.Value;
    }

    public string GenerateEmailBody(string templateName, Dictionary<string, string> variables)
    {
        var templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "EmailTemplates", templateName);

        if (!File.Exists(templatePath))
            throw new FileNotFoundException("Email template not found", templatePath);

        var emailBody = File.ReadAllText(templatePath);

        foreach (var variable in variables)
        {
            string placeholder = $"{{{{{variable.Key}}}}}";
            emailBody = emailBody.Replace(placeholder, variable.Value);
        }

        return emailBody;
    }

    public void SendEmail(string toEmail, string subject, string emailBody)
    {
        using var client = new SmtpClient(_emailSettings.Server, _emailSettings.Port);
        if (!string.IsNullOrEmpty(_emailSettings.Username) && !string.IsNullOrEmpty(_emailSettings.Password))
            client.Credentials = new NetworkCredential(_emailSettings.Username, _emailSettings.Password);
        client.EnableSsl = true;

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
            Subject = subject,
            Body = emailBody,
            IsBodyHtml = true
        };

        mailMessage.To.Add(toEmail);

        try
        {
            client.Send(mailMessage);
            Console.WriteLine("Email sent successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending email: {ex.Message}");
        }
    }
}
