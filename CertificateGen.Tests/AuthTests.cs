using System;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1.X509;

using Xunit;

namespace CertificateGen.Tests
{
    public class AuthTests
    {
        [Fact]
        public void Auth_GetOrCreateCertificate()
        {
            string subjectName = "test-cert";
            X509Certificate2 cert = Auth.GetOrCreateCertificate(subjectName, DateTime.Now.AddMinutes(1), true, new X509Store(StoreName.AuthRoot), new[] { "127.0.0.1", "localhost", subjectName }, new[] { KeyPurposeID.IdKPClientAuth, KeyPurposeID.IdKPServerAuth, });

            Assert.NotNull(cert);
        }
    }
}