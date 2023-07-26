using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using RGiesecke.DllExport;

namespace CertificateGen
{
    public static class CertStore
    {
        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2 GetCertificateFromStore(X509Store store, string certName)
        {
            try
            {
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection signingCert = GetCertificatesByName(store, certName);
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

        [ComVisible(true)]
        [DllExport]
        public static X509Certificate2Collection GetCertificatesByName(X509Store store, string certName)
        {
            X509Certificate2Collection certCollection = store.Certificates;
            // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
            // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
            //X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now.ToUniversalTime(), false);

            return certCollection.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
        }

        [ComVisible(true)]
        [DllExport]
        public static bool AddCertificateToStore(X509Store store, X509Certificate2 cert)
        {
            bool result = false;
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                result = true;
            }
            catch
            {
                // ignored
            }
            finally
            {
                store.Close();
            }

            return result;
        }

        [ComVisible(true)]
        [DllExport]
        public static bool DeleteCertificateFromStore(X509Store store, X509Certificate2 cert)
        {
            bool result = false;
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Remove(cert);
                result = true;
            }
            catch
            {
                // ignored
            }
            finally
            {
                store.Close();
            }

            return result;
        }
    }
}
