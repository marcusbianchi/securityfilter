using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using securityfilter.Model;
using securityfilter.Services.Interfaces;

namespace securityfilter {
    public class SecurityFilter : ActionFilterAttribute {
        private readonly string _permission;
        public SecurityFilter (string permission) {
            _permission = permission;
        }

        public override void OnActionExecuting (ActionExecutingContext context) {
            IEncryptService _encryptService = (IEncryptService) context.HttpContext.RequestServices.GetService (typeof (IEncryptService));
            IConfiguration _configuration = (IConfiguration) context.HttpContext.RequestServices.GetService (typeof (IConfiguration));

            if (String.IsNullOrEmpty (_configuration["Disable"])) {
                if (_encryptService != null) {
                    var header = context.HttpContext.Request.Headers["security"].ToString ();
                    if (String.IsNullOrEmpty (header)) {
                        SendResponse (context, "No Security Header in the request", 401);
                    }
                    string jsonUser = _encryptService.Decrypt (header);
                    if (jsonUser != null) {
                        User user = JsonConvert.DeserializeObject<User> (jsonUser);
                        if (user != null && user.userGroup != null) {
                            List<string> permissions = new List<string> (user.userGroup.permissions);
                            if (permissions.Count != 0) {
                                if (!permissions.Contains (_permission))
                                    SendResponse (context, "This UserGroup Doesn't have permission to this endpoint", 401);
                            } else {
                                SendResponse (context, "This UserGroup Doesn't have permissions", 401);
                            }
                        } else {
                            SendResponse (context, "This User Doesn't belong to a group", 401);
                        }
                    } else {
                        SendResponse (context, " Decript Error.", 401);
                    }
                } else {
                    SendResponse (context, "No Decript configuration on API DI.", 401);
                }
            } else
                Console.WriteLine ("Security Disabled");
        }

        private void SendResponse (ActionExecutingContext context, string message, int code) {
            context.HttpContext.Response.StatusCode = code;
            context.HttpContext.Response.Headers.Clear ();
            var wrongResult = new { error = message };
            context.Result = new JsonResult (wrongResult);
        }

        // private bool ByPassSameHost (ActionExecutingContext context) {
        //     return context.HttpContext.Connection.RemoteIpAddress
        //         context.HttpContext.Connection.RemoteIpAddress;
        // }


    }
}