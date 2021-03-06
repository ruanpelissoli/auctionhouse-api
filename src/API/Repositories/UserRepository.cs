using API.Models;
using System.Text;

namespace API.Repositories
{
    public class UserRepository
    {
        public static List<User> Users = new()
        {
            new() { Username = "luke_admin", EmailAddress = "luke.admin@email.com", PasswordHash = Encoding.UTF8.GetBytes("MyPass_w0rd"), GivenName = "Luke", Surname = "Rogers", Role = "Administrator" },
            new() { Username = "lydia_standard", EmailAddress = "lydia.standard@email.com", PasswordHash = Encoding.UTF8.GetBytes("MyPass_w0rd"), GivenName = "Elyse", Surname = "Burton", Role = "Standard" },
        };
    }
}
