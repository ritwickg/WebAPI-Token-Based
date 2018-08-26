using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace TokenAuthenticationNetCore.Services
{
    public class EmailHandling
    {
        public async Task<bool> SendVerificationEmail(string email, string jwtToken)
        {
            using (MailMessage mailMessage = new MailMessage("carapplication2017@gmail.com", email)
            {

                IsBodyHtml = true,
                //Body = "<a href=localhost:4200/verify/"+jwtToken+"></a>",
                Body = $"<html><body><a href='http://localhost:4200/verify/{jwtToken}'>Verify Email</a><body><html>",
                BodyEncoding = Encoding.UTF8,
                Subject = "Verify your Email"
            })
            {
                using (SmtpClient smtp = new SmtpClient
                {
                    Port = 25,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    Host = "smtp.gmail.com",
                    UseDefaultCredentials = false,
                    EnableSsl = true,
                    Timeout = 200000,
                    Credentials = new System.Net.NetworkCredential("carapplication2017@gmail.com", "#CarApplication2017"),
                })
                {
                    try
                    {
                        await smtp.SendMailAsync(mailMessage);
                        return true;
                    }
                    catch (Exception ex)
                    {

                        Console.WriteLine(ex);
                        return false;
                    }
                }
            }
        }

        public async Task SendEmail(string Email)
        {


            using (MailMessage mailMessage = new MailMessage("carapplication2017@gmail.com", Email)
            {
                IsBodyHtml = true,
                Body = "This is demo",
                BodyEncoding = Encoding.UTF8,
                Subject = "Demo",

            })
            {
                using (SmtpClient smtpClient = new SmtpClient
                {
                    Port = 25,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    Host = "smtp.gmail.com",
                    UseDefaultCredentials = false,
                    EnableSsl = true,
                    Timeout = 200000,
                    Credentials = new System.Net.NetworkCredential("carapplication2017@gmail.com", "#Carapplication2017"),
                })
                    try
                    {
                        await smtpClient.SendMailAsync(mailMessage);

                        // smtpClient.SendCompleted += new SendCompletedEventHandler(MailSendingComplete);
                    }
                    catch (SmtpFailedRecipientException ex)
                    {
                        Console.WriteLine(ex);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
            }

        }
    }
}
