
namespace securityfilter.Model
{
    public class User {
        public int userId { get; set; }
        public string username { get; set; }       
        public string name { get; set; }
        public string password { get; set; }       
        public string email { get; set; }
        public bool? enabled { get; set; }
        public UserGroup userGroup { get; set; }

    }
}