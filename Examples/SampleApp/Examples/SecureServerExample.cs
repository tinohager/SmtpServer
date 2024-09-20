using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using SmtpServer;
using SmtpServer.ComponentModel;
using SmtpServer.Tracing;

namespace SampleApp.Examples
{
    public static class SecureServerExample
    {
        public static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            var validityPeriodInYears = 1;

            using RSA rsa = RSA.Create(2048);  // 2048-Bit Key

            var certificateRequest = new CertificateRequest(
                $"CN={subjectName}",  // Common Name (CN)
                rsa,
                HashAlgorithmName.SHA256,  // Hash-Algorithmus
                RSASignaturePadding.Pkcs1  // Padding Schema
            );

            certificateRequest.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false)
            );

            certificateRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true)
            );

            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddYears(validityPeriodInYears);

            X509Certificate2 certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);

            return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
        }

        public static void Run()
        {

            var x = CreateSelfSignedCertificate("localhost");

            // this is important when dealing with a certificate that isnt valid
            ServicePointManager.ServerCertificateValidationCallback = IgnoreCertificateValidationFailureForTestingOnly;

            var cancellationTokenSource = new CancellationTokenSource();

            var options = new SmtpServerOptionsBuilder()
                .ServerName("SmtpServer SampleApp")
                .Endpoint(builder =>
                    builder
                        .Port(9025, true)
                        .SessionTimeout(TimeSpan.FromSeconds(5))
                        .AllowUnsecureAuthentication(false)
                        .Certificate(x))
                .Build();

            var serviceProvider = new ServiceProvider();
            serviceProvider.Add(new SampleUserAuthenticator());

            var server = new SmtpServer.SmtpServer(options, serviceProvider);
            server.SessionCreated += OnSessionCreated;
            
            var serverTask = server.StartAsync(cancellationTokenSource.Token);

            Console.ReadLine();

            SampleMailClient.Send(user: "user", password: "password", useSsl: true);

            cancellationTokenSource.Cancel();
            serverTask.WaitWithoutException();
        }

        static void OnSessionCreated(object sender, SessionEventArgs e)
        {
            Console.WriteLine("Session Created.");

            e.Context.CommandExecuting += OnCommandExecuting;
        }

        static void OnCommandExecuting(object sender, SmtpCommandEventArgs e)
        {
            Console.WriteLine("Command Executing.");

            new TracingSmtpCommandVisitor(Console.Out).Visit(e.Command);
        }

        static bool IgnoreCertificateValidationFailureForTestingOnly(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        static X509Certificate2 CreateCertificate()
        {
            // to create an X509Certificate for testing you need to run MAKECERT.EXE and then PVK2PFX.EXE
            // http://www.digitallycreated.net/Blog/38/using-makecert-to-create-certificates-for-development

            var certificate = File.ReadAllBytes(@"C:\Users\caino\Dropbox\Documents\Cain\Programming\SmtpServer\SmtpServer.pfx");
            var password = File.ReadAllText(@"C:\Users\caino\Dropbox\Documents\Cain\Programming\SmtpServer\SmtpServerPassword.txt");

            return new X509Certificate2(certificate, password);
        }
    }
}