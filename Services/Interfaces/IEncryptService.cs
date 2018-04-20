namespace securityfilter.Services.Interfaces {
    public interface IEncryptService {
        string Decrypt (string cipherString);
        string Encrypt (string toEncrypt);
    }
}