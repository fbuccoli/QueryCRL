using System;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertificateRevocationCheck
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length == 0 || !Uri.IsWellFormedUriString(args[0], UriKind.Absolute))
            {
                Console.WriteLine("Please provide a valid URL as an argument.");
                return;
            }

            string url = args[0]; // Get URL from command-line argument
            X509Certificate2 cert = null;

            try
            {
                var handler = new HttpClientHandler();
                handler.ServerCertificateCustomValidationCallback = (httpRequestMessage, certificate, cetChain, policyErrors) =>
                {
                    if (certificate != null && policyErrors == SslPolicyErrors.None)
                    {
                        cert = new X509Certificate2(certificate.Export(X509ContentType.Cert));
                        return true; // If there's no error, proceed with the request.
                    }

                    Console.WriteLine("Certificate error: " + policyErrors);
                    return false; // If there are errors, do not proceed with the request.
                };

                using (var client = new HttpClient(handler))
                {
                    // Making a request to fetch the certificate
                    HttpResponseMessage response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();
                }

                // Check if certificate was retrieved
                if (cert != null)
                {
                    CheckCertificateRevocation(cert, url);
                }
                else
                {
                    Console.WriteLine("No certificate was retrieved from the server.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }

            
        }

        private static void CheckCertificateRevocation(X509Certificate2 cert, string url)
        {
            Console.WriteLine("Checking certificate for: " + cert.Subject);
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            bool isChainValid = chain.Build(cert);
            bool isRevoked = chain.ChainStatus.Any(status => status.Status == X509ChainStatusFlags.Revoked);

            if (!isRevoked)
            {
                string crlDistributionPoint = FindCRLDistributionPoint(cert);
                Console.WriteLine($"The certificate for {url} is valid.\nIssued by {cert.Issuer}\nCRL: {crlDistributionPoint}");
            }
            else
            {
                foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                {
                    Console.WriteLine("Chain status: " + chainStatus.StatusInformation);
                }
            }
        }

        private static string FindCRLDistributionPoint(X509Certificate2 cert)
        {
            X509Extension crlExtension = cert.Extensions["2.5.29.31"]; // OID for CRL Distribution Points
            if (crlExtension != null)
            {
                AsnEncodedData asnData = new AsnEncodedData(crlExtension.Oid, crlExtension.RawData);
                return asnData.Format(true);
            }
            return "Not Available";
        }
    }
}
