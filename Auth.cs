﻿using System;
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
        /// Creates a self-signed certificate and adds to third-party certificate authorities. 
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="subjectAlternativeNames"></param>
        /// <param name="usages"></param>
        /// <returns></returns>
        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 GetOrCreateCertificate(string subjectName, string[] subjectAlternativeNames = null, KeyPurposeID[] usages = null)
        {
            if (GetCertificate(subjectName) is X509Certificate2 validCert)
            {
                return validCert;
            }

            if (subjectAlternativeNames == null)
            {
                subjectAlternativeNames = Array.Empty<string>();
            }

            if (usages == null)
            {
                usages = new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth, };
            }

            string serverCertName = $"CN={subjectName}";
            X509Certificate2 caCert = Certification.CreateCertificateAuthorityCertificate(serverCertName, subjectAlternativeNames,
               usages);
            caCert.FriendlyName = subjectName;

            X509Store store = new X509Store(StoreName.AuthRoot);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(caCert);
            }
            finally
            {
                store.Close();
            }

            return caCert;
        }

        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 GetCertificate(string subjectName)
        {
            string serverCertName = $"CN={subjectName}";

            X509Store store = new X509Store(StoreName.AuthRoot);
            if (GetCertificateFromStore(store, serverCertName) is X509Certificate2 validCert)
            {
                return validCert;
            }

            return null;
        }

        private static X509Certificate2 GetCertificateFromStore(X509Store store, string certName)
        {
            try
            {
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection signingCert = GetCurrentCertificatesByName(store, certName);
                if (signingCert.Count == 0)
                {
                    return null;
                }

                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }

        private static X509Certificate2Collection GetCurrentCertificatesByName(X509Store store, string certName)
        {
            // Place all certificates in an X509Certificate2Collection object.
            X509Certificate2Collection certCollection = store.Certificates;
            // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
            // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
            X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            return currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
        }
    }
}
