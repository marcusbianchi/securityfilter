using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Http;
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
            if (!IsLocal (context)) {
                if (_encryptService != null) {
                    if (String.IsNullOrEmpty (_configuration["Disable"])) {
                        var header = context.HttpContext.Request.Headers["security"].ToString ();
                        if (String.IsNullOrEmpty (header)) {
                            SendResponse (context, "No Security Header in the request", 401);
                        } else {
                            string jsonUser = _encryptService.Decrypt (header);
                            if (jsonUser != null) {
                                User user = JsonConvert.DeserializeObject<User> (jsonUser);
                                LogRequest (context, _configuration, user.username);
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
                        }
                    } else {
                        SendResponse (context, "No Decript configuration on API DI.", 401);
                    }
                } else
                    Console.WriteLine ("Security Disabled");
            } else
                Console.WriteLine ("Same Host Request");
        }

        private void SendResponse (ActionExecutingContext context, string message, int code) {
            context.HttpContext.Response.StatusCode = code;
            context.HttpContext.Response.Headers.Clear ();
            var wrongResult = new { error = message };
            context.Result = new JsonResult (wrongResult);
        }

        private void LogRequest (ActionExecutingContext context, IConfiguration _configuration, string user) {
            if (!String.IsNullOrEmpty (_configuration["SecurityLogFolder"])) {
                Directory.CreateDirectory (_configuration["SecurityLogFolder"]);
                if (context.HttpContext.Request.Method != "GET") {
                    using (StreamWriter w = File.AppendText (_configuration["SecurityLogFolder"] +
                        "//log.txt")) {
                        string method = context.HttpContext.Request.Method;
                        string body = context.HttpContext.Request.Body.ToString ();
                        var curentDate = DateTime.Now.ToString ();
                        w.WriteLine ($"{curentDate};{method};{user};{body}");
                    }
                }
            }

        }

        private static bool IsLocal (ActionExecutingContext context) {
            var connection = context.HttpContext.Connection;
            var localIp = connection.LocalIpAddress.MapToIPv4 ().ToString ();
            var remoteIp = connection.RemoteIpAddress.MapToIPv4 ().ToString ();
            if (connection.RemoteIpAddress != null) {
                if (connection.LocalIpAddress != null) {
                    if (localIp.Equals (remoteIp))
                        return true;
                    return context.HttpContext.Request.Host.Host == "localhost";

                } else {
                    return IPAddress.IsLoopback (connection.RemoteIpAddress);
                }
            }
            if (connection.RemoteIpAddress == null && connection.LocalIpAddress == null) {
                return true;
            }

            return false;
        }
    }
}