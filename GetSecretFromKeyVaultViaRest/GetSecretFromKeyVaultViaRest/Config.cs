using System.Configuration;

namespace GetSecretFromKeyVaultViaRest
{
    public class Config
    {
        public string CertFile = ConfigurationManager.AppSettings["CertFile"];
        public string CertPassword = ConfigurationManager.AppSettings["CertPassword"];
        public string KeyVaultName = ConfigurationManager.AppSettings["KeyVaultName"];
        public string SecretName = ConfigurationManager.AppSettings["SecretName"];
        public string AppClientId => ConfigurationManager.AppSettings["AppClientId"];
        public string TenantId => ConfigurationManager.AppSettings["TenantId"];
    }
}