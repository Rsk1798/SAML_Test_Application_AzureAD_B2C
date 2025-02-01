using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SAML_Test_Application_AzureAD_B2C.Models;

namespace SAML_Test_Application_AzureAD_B2C.Controllers
{
    public class SamlController : Controller
    {

        private readonly Saml2Configuration config;
       // private readonly SamlSettings _samlSettings;


        //public IActionResult Index()
        //{
        //    return View();
        //}

        public SamlController(Saml2Configuration config)  //, IOptions<SamlSettings> samlSettings
        {
            this.config = config;
            // _samlSettings = samlSettings.Value;
        }


        [Route("Auth/Login")]
        [Route("saml/login")]
        public IActionResult Login()
        {
            var binding = new Saml2RedirectBinding();
            var saml2AuthnRequest = new Saml2AuthnRequest(config)
            {
                AssertionConsumerServiceUrl = new Uri("https://samltestapplicationazureadb2-production.up.railway.app/saml/acs"),
                // "https://your-app-url/Auth/ACS"
                ForceAuthn = true,
            };
            return binding.Bind(saml2AuthnRequest).ToActionResult();
        }


        [Route("Auth/ACS")]
        [Route("saml/acs")]
        public async Task<IActionResult> Acs()
        {
            try
            {


                var binding = new Saml2PostBinding();
                var saml2AuthnResponse = new Saml2AuthnResponse(config);


                // Read and validate the SAML response
                binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);


                //if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
                //{
                //    throw new Exception("SAML login failed.");
                //}
                //binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
                //var relayState = binding.RelayState;
                //await saml2AuthnResponse.CreateSession(HttpContext);

                //return Redirect(relayState ?? "/");

                await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) =>
                {
                    // Transform claims if needed
                    return claimsPrincipal;
                });

                // Redirect to a secure page after successful authentication
                return RedirectToAction("Index", "Home");

            }
            catch (Exception ex) {

                // Log the error and redirect to the error page
                return RedirectToAction("Error", "Home", new { message = ex.Message });

            }
        }



        [Authorize]
        [Route("Auth/Logout")]
        [Route("saml/logout")]
        public IActionResult Logout()
        {
            var binding = new Saml2RedirectBinding();
            var saml2LogoutRequest = new Saml2LogoutRequest(config);

            // Redirect to Azure AD B2C for logout
            return binding.Bind(saml2LogoutRequest).ToActionResult();

            // return SignOut("Cookies", "Saml2");
        }

    }
}
