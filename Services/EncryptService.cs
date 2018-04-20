using System;
using Microsoft.AspNetCore.DataProtection;
using securityfilter.Services.Interfaces;

namespace securityfilter.Services {
    public class EncryptService : IEncryptService {
        private readonly IDataProtector _protector;

        public EncryptService (IDataProtectionProvider provider) {
            _protector = provider.CreateProtector (GetType ().FullName);
        }

        public string Decrypt (string cipherString) {
            try {
                return _protector.Unprotect (cipherString);
            } catch (Exception ex) {
                Console.WriteLine (ex.ToString ());
                return null;
            }
        }

        public string Encrypt (string toEncrypt) {
            try {
                return _protector.Protect (toEncrypt);
            } catch (Exception ex) {
                Console.WriteLine (ex.ToString ());
                return null;
            }
        }
    }
}