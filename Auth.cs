using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

using RGiesecke.DllExport;

namespace CertificateGen
{
    public static class Auth
    {
        [ComVisible(true)]
        [DllExport]
        public static AsymmetricCipherKeyPair GetKeyPair(X509Certificate2 cert)
        {
            return DotNetUtilities.GetKeyPair(cert.PrivateKey);
        }

        [ComVisible(true)]
        [DllExport]
        public static string ConvertKeyToPem(AsymmetricCipherKeyPair key)
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(key.Private);
            pemWriter.Writer.Flush();

            return textWriter.ToString();
        }

        [ComVisible(true)]
        [DllExport]
        public static string ConvertCertToPem(X509Certificate2 cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        /// <summary>
        /// Creates a self-signed certificate and adds to third-party certificate authorities. Valid for one year. Renews if expired. Use overload to set expiration date manually."/>
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="store"></param>
        /// <param name="subjectAlternativeNames"></param>
        /// <param name="usages"></param>
        /// <returns></returns>
        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 GetOrCreateCertificate(string subjectName, X509Store store, string[] subjectAlternativeNames = null, KeyPurposeID[] usages = null)
        {
            return GetOrCreateCertificate(subjectName, DateTime.Now.AddYears(1), true, store, subjectAlternativeNames, usages);
        }

        /// <summary>
        /// Creates a self-signed certificate and adds to third-party certificate authorities. 
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="expirationDate"></param>
        /// <param name="renew"></param>
        /// <param name="store"></param>
        /// <param name="subjectAlternativeNames"></param>
        /// <param name="usages"></param>
        /// <returns></returns>
        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 GetOrCreateCertificate(string subjectName, DateTime expirationDate, bool renew, X509Store store, string[] subjectAlternativeNames = null, KeyPurposeID[] usages = null)
        {
            if (GetCertificate(store, subjectName) is X509Certificate2 foundCert)
            {
                if (IsExpired(foundCert) && renew)
                {
                    CertStore.DeleteCertificateFromStore(store, foundCert);
                }
                else
                {
                    return foundCert;
                }
            }

            return CreateCertificate(subjectName, expirationDate, store, subjectAlternativeNames, usages);
        }

        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 CreateCertificate(string subjectName, DateTime expirationDate, X509Store store,
            string[] subjectAlternativeNames, KeyPurposeID[] usages)
        {
            if (expirationDate < DateTime.Now)
            {
                throw new ArgumentOutOfRangeException(nameof(expirationDate), "Expiration date must be after current time.");
            }

            subjectAlternativeNames ??= Array.Empty<string>();

            usages ??= new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth, };

            string serverCertName = $"CN={subjectName}";
            X509Certificate2 caCert =
                Certification.CreateCertificateAuthorityCertificate(serverCertName, expirationDate, subjectAlternativeNames,
                    usages);
            caCert.FriendlyName = subjectName;

            CertStore.AddCertificateToStore(store, caCert);

            return caCert;
        }

        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 GetCertificate(X509Store store, string subjectName)
        {
            string serverCertName = $"CN={subjectName}";

            if (CertStore.GetCertificateFromStore(store, serverCertName) is X509Certificate2 certificate)
            {
                return certificate;
            }

            return null;
        }

        private static bool IsExpired(X509Certificate2 cert)
        {
            return cert.NotAfter < DateTime.Now.ToUniversalTime();
        }
    }
}
