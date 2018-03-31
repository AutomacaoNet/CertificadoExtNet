using System;
using System.Security.Cryptography.X509Certificates;

namespace CertificadoA3ExtNet
{
    public static class ValidadeExt
    {
        public static bool IsVencido(this X509Certificate2 x509Certificate2)
        {
            return x509Certificate2.NotAfter <= DateTime.Now;
        }

        public static bool IsNotVencido(this X509Certificate2 x509Certificate2)
        {
            return IsVencido(x509Certificate2);
        }
    }
}
