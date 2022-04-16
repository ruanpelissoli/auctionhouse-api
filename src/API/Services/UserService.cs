using API.Models;
using API.Repositories;
using System.Security.Cryptography;
using System.Text;

namespace API.Services
{
    public interface IUserService
    {
        public User? Get(UserLogin userLogin);
        void Create(User user);
    }

    public class UserService : IUserService
    {
        public User? Get(UserLogin userLogin)
        {
            User? user = UserRepository.Users.FirstOrDefault(o => o.Username.Equals(userLogin.Username));

            if (user == null) return null;

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(userLogin.Password));

            if (computedHash.SequenceEqual(user.PasswordHash))
                return user;

            return null;
        }

        public void Create(User user)
        {
            UserRepository.Users.Add(user);
        }
    }
}
