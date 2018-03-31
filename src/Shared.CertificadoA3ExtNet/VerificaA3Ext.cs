using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificadoA3ExtNet
{
    public static class VerificaA3Ext
    {
        public static bool IsA3(this X509Certificate2 x509Certificate2)
        {
            if (x509Certificate2 == null)
                return false;

            bool result = false;

            try
            {
                RSACryptoServiceProvider service = x509Certificate2.PrivateKey as RSACryptoServiceProvider;

                if (service != null)
                {
                    if (service.CspKeyContainerInfo.Removable &&
                        service.CspKeyContainerInfo.HardwareDevice)
                        result = true;
                }
            }
            catch
            {
                //assume que é false
                result = false;
            }

            return result;
        }

        public static bool IsNotA3(this X509Certificate2 x509Certificate2)
        {
            return !IsA3(x509Certificate2);
        }

    }
}
