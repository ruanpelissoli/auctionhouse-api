using API.Models;
using API.Repositories;

namespace API.Services
{
    public interface IUserService
    {
        public User Get(UserLogin userLogin);
    }

    public class UserService : IUserService
    {
        public User Get(UserLogin userLogin)
        {
            User user = UserRepository.Users.FirstOrDefault(o => o.Username.Equals(userLogin.Username, StringComparison.OrdinalIgnoreCase) && o.Password.Equals(userLogin.Password));

            return user;
        }
    }
}
