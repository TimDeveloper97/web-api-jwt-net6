using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Models
{
    public class User
    {
        [Key]
        public string UserName { get; set; } = "";
        public string Name { get; set; } = "";
        public string Role { get; set; } = "Everyone";
        public bool IsActive { get; set; } = false;
        public string Token { get; set; } = "";        
        public string Password { get; set; } = "";

        public User(string userName, string name, string password, string role)
        {
            UserName = userName;
            Name = name;
            Password = password;
            Role = role;
        }
    }

    public class LoginUser
    {
        /// <summary>
        /// The name of the product
        /// </summary>
        /// <example>Men's basketball shoes</example>
        public string UserName { get; set; } = "";
        /// <summary>
        /// Quantity left in stock
        /// </summary>
        /// <example>10</example>
        public string Password { get; set; } = "";
    }

    public class RegisterUser
    {
        public string Name { get; set; } = "";
        public string UserName { get; set; } = "";
        public string Password { get; set; } = "";
        public string Role { get; set; } = "Everyone";
    }
}