using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System.Xml.Serialization;
using SAML_Test_Application_AzureAD_B2C.Models;


var builder = WebApplication.CreateBuilder(args);

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
        Issuer = "https://localhost:5001", // Your app's Entity ID
        SingleSignOnDestination = new Uri("https://{YourTenant}.b2clogin.com/{YourTenant}.onmicrosoft.com/{YourPolicy}/samlp/sso/login"),
        SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature,
        CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
        RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
    };

    // Load Azure AD B2C metadata
    var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
    using var httpClient = httpClientFactory.CreateClient();
    var metadataUri = "https://{YourTenant}.b2clogin.com/{YourTenant}.onmicrosoft.com/{YourPolicy}/samlp/metadata";
    var metadataResponse = httpClient.GetAsync(metadataUri).GetAwaiter().GetResult();
    var metadataString = metadataResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();

    
    // Parse metadata XML
    //var xmlDocument = new XmlDocument();
    //xmlDocument.LoadXml(metadataString);


    // Deserialize metadata XML into EntityDescriptor
    var serializer = new XmlSerializer(typeof(EntityDescriptor));
    using (var metadataReader = new StringReader(metadataString))
    {
        var entityDescriptor = (EntityDescriptor)serializer.Deserialize(metadataReader);

        // Configure SAML settings
        if (entityDescriptor?.IdPSsoDescriptor != null)
        {
            config.AllowedIssuer = entityDescriptor.EntityId;
            config.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
        }
    }


    return config;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}


app.MapHealthChecks("/health");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
