namespace SAML_Test_Application_AzureAD_B2C.Models
{
    public class SamlSettings
    {
        public string Issuer { get; set; }
        public string AssertionConsumerServiceUrl { get; set; }
        public string CertificateValidationMode { get; set; }

    }

    public class AzureAdB2CSettings
    {
        public string Tenant { get; set; }
        public string Policy { get; set; }
        public string MetadataUri { get; set; }
    }
}
