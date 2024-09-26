namespace SenseNetAuth.Services;

public interface IEmailService
{
    public string GenerateEmailBody(string templateName, Dictionary<string, string> variables);
    public void SendEmail(string toEmail, string subject, string emailBody);
}
