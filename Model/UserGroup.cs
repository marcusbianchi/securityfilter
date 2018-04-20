using System.Collections.Generic;

namespace securityfilter.Model
{
    public class UserGroup {
        public int userGroupId { get; set; }
        public string name { get; set; }
        public string description { get; set; }
        public bool? enabled { get; set; }
        private string[] _permissions;
        public string[] permissions {
            get {
                if (this._permissions == null)
                    return new string[0];
                else
                    return this._permissions;
            }
            set { this._permissions = value; }
        }
    }
}