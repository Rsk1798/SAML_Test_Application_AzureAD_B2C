using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System.Xml.Serialization;
using SAML_Test_Application_AzureAD_B2C.Models;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Diagnostics;


var builder = WebApplication.CreateBuilder(args);

// Ensure your app listens on the Railway-provided port
builder.WebHost.ConfigureKestrel(options =>
    options.ListenAnyIP(int.Parse(Environment.GetEnvironmentVariable("PORT") ?? "8080")));

// Register HttpClientFactory (usually already registered by default)
builder.Services.AddHttpClient();

// Bind settings from appsettings.json
builder.Services.Configure<SamlSettings>(builder.Configuration.GetSection("Saml"));
builder.Services.Configure<AzureAdB2CSettings>(builder.Configuration.GetSection("AzureAdB2C"));

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddHealthChecks();

var metadataUri = builder.Configuration["AzureAdB2C:MetadataUri"];

builder.Services.AddSaml2();
builder.Services.AddScoped<Saml2Configuration>(serviceProvider =>
{
    var config = new Saml2Configuration
    {
        Issuer = "https://samltestapplicationazureadb2-production.up.railway.app", // Your app's Entity ID
        SingleSignOnDestination = new Uri("https://hcliamtrainingb2c.b2clogin.com/hcliamtrainingb2c.onmicrosoft.com/B2C_1A_RAJA_SAML_SIGNUP_SIGNIN/samlp/sso/login"),
        SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature,
        CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
        RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
    };

    // Resolve IHttpClientFactory safely
    var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
    if (httpClientFactory == null)
    {
        throw new InvalidOperationException("IHttpClientFactory is not registered.");
    }

    using var httpClient = httpClientFactory.CreateClient();

    // Load Azure AD B2C metadata
    // var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
    // using var httpClient = httpClientFactory.CreateClient();
    var metadataUri = "https://hcliamtrainingb2c.b2clogin.com/hcliamtrainingb2c.onmicrosoft.com/B2C_1A_RAJA_SAML_SIGNUP_SIGNIN/samlp/metadata";
    var metadataResponse = httpClient.GetAsync(metadataUri).GetAwaiter().GetResult();
    var metadataString = metadataResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();


    // Parse metadata XML
    //var xmlDocument = new XmlDocument();
    //xmlDocument.LoadXml(metadataString);

    // Parse metadata manually
    var xmlDocument = new XmlDocument();
    xmlDocument.LoadXml(metadataString);

    var entityId = xmlDocument.DocumentElement?.GetAttribute("entityID");
    var signingCertificates = new List<X509Certificate2>();

    var idpSsoDescriptorNode = xmlDocument.SelectSingleNode("//md:IDPSSODescriptor", GetNamespaceManager(xmlDocument));
    if (idpSsoDescriptorNode != null)
    {
        var keyDescriptorNodes = idpSsoDescriptorNode.SelectNodes(".//md:KeyDescriptor", GetNamespaceManager(xmlDocument));
        foreach (XmlNode keyDescriptorNode in keyDescriptorNodes)
        {
            var x509CertificateNode = keyDescriptorNode.SelectSingleNode(".//ds:X509Certificate", GetNamespaceManager(xmlDocument));
            if (x509CertificateNode != null)
            {
                var certificateBytes = Convert.FromBase64String(x509CertificateNode.InnerText);
                var certificate = new X509Certificate2(certificateBytes);
                signingCertificates.Add(certificate);
            }
        }
    }


    // Deserialize metadata XML into EntityDescriptor
    //var serializer = new XmlSerializer(typeof(EntityDescriptor));
    //using (var metadataReader = new StringReader(metadataString))
    //{
    //    var entityDescriptor = (EntityDescriptor)serializer.Deserialize(metadataReader);

    //    // Configure SAML settings
    //    if (entityDescriptor?.IdPSsoDescriptor != null)
    //    {
    //        config.AllowedIssuer = entityDescriptor.EntityId;
    //        config.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
    //    }
    //}

    // Configure SAML settings
    if (!string.IsNullOrEmpty(entityId) && signingCertificates.Any())
    {
        config.AllowedIssuer = entityId;
        config.SignatureValidationCertificates.AddRange(signingCertificates);
    }


    return config;
});

// Define GetNamespaceManager method
static XmlNamespaceManager GetNamespaceManager(XmlDocument xmlDocument)
{
    var namespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
    namespaceManager.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata"); // SAML metadata namespace
    namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#"); // XML signature namespace
    return namespaceManager;
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// Global error handling
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var exceptionHandler = context.Features.Get<IExceptionHandlerFeature>();
        Console.WriteLine($"Unhandled exception: {exceptionHandler?.Error}");
        await context.Response.WriteAsync("An error occurred. Check logs for details.");
    });
});


app.MapHealthChecks("/health");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
