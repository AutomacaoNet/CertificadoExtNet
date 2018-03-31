using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificadoA3ExtNet
{
    public static class SetSenhaA3Ext
    {
        /// <summary>
        /// Seta a senha do certificado digital A3
        /// Observação: Obter o certificado digital do repositorio com "OpenFlags.ReadOnly"
        /// </summary>
        /// <param name="x509Certificate2"></param>
        /// <param name="senha"></param>
        public static void SetSenhaA3(this X509Certificate2 x509Certificate2, string senha)
        {
            if (x509Certificate2 == null) throw new ArgumentNullException(nameof(x509Certificate2));
            var key = (RSACryptoServiceProvider)x509Certificate2.PrivateKey;

            var providerHandle = IntPtr.Zero;
            var pinBuffer = Encoding.ASCII.GetBytes(senha);

            MetodosNativos.Executar(() => MetodosNativos.CryptAcquireContext(ref providerHandle,
                key.CspKeyContainerInfo.KeyContainerName,
                key.CspKeyContainerInfo.ProviderName,
                key.CspKeyContainerInfo.ProviderType,
                MetodosNativos.CryptContextFlags.Silent));
            MetodosNativos.Executar(() => MetodosNativos.CryptSetProvParam(providerHandle,
                MetodosNativos.CryptParameter.KeyExchangePin,
                pinBuffer, 0));
            MetodosNativos.Executar(() => MetodosNativos.CertSetCertificateContextProperty(
                x509Certificate2.Handle,
                MetodosNativos.CertificateProperty.CryptoProviderHandle,
                0, providerHandle));
        }

        internal static class MetodosNativos
        {
            internal enum CryptContextFlags
            {
                None = 0,
                Silent = 0x40
            }

            internal enum CertificateProperty
            {
                None = 0,
                CryptoProviderHandle = 0x1
            }

            internal enum CryptParameter
            {
                None = 0,
                KeyExchangePin = 0x20
            }

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptAcquireContext(
                ref IntPtr hProv,
                string containerName,
                string providerName,
                int providerType,
                CryptContextFlags flags
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CryptSetProvParam(
                IntPtr hProv,
                CryptParameter dwParam,
                [In] byte[] pbData,
                uint dwFlags);

            [DllImport("CRYPT32.DLL", SetLastError = true)]
            internal static extern bool CertSetCertificateContextProperty(
                IntPtr pCertContext,
                CertificateProperty propertyId,
                uint dwFlags,
                IntPtr pvData
            );

            public static void Executar(Func<bool> action)
            {
                if (!action())
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
            }
        }
    }
}
