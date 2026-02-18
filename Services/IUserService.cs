using System.Security.Cryptography;
using System.Text;

namespace dotnet_auth.Services;

public interface IUserService
{
    Task<User?> GetByIdAsync(int id);
    Task<User?> GetByUsernameAsync(string username);
    Task<User?> GetByRefreshTokenAsync(string refreshToken);
    Task<bool> ExistsByUsernameAsync(string username);
    Task<bool> ExistsByEmailAsync(string email);
    Task<User> CreateAsync(string username, string email, string password);
    Task SetRefreshTokenAsync(int userId, string refreshToken);
}

public class UserService : IUserService
{
    private readonly List<User> _users = new();
    private int _nextId = 1;

    public Task<User?> GetByIdAsync(int id) =>
        Task.FromResult(_users.FirstOrDefault(u => u.Id == id));

    public Task<User?> GetByUsernameAsync(string username) =>
        Task.FromResult(_users.FirstOrDefault(u => u.Username == username));

    public Task<User?> GetByRefreshTokenAsync(string refreshToken) =>
        Task.FromResult(_users.FirstOrDefault(u => u.RefreshToken == refreshToken));

    public Task<bool> ExistsByUsernameAsync(string username) =>
        Task.FromResult(_users.Any(u => u.Username == username));

    public Task<bool> ExistsByEmailAsync(string email) =>
        Task.FromResult(_users.Any(u => u.Email == email));

    public Task<User> CreateAsync(string username, string email, string password)
    {
        var user = new User
        {
            Id = _nextId++,
            Username = username,
            Email = email,
            PasswordHash = ComputeSha256Hash(password)
        };
        _users.Add(user);
        return Task.FromResult(user);
    }

    public Task SetRefreshTokenAsync(int userId, string refreshToken)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user != null)
        {
            user.RefreshToken = refreshToken;
        }
        return Task.CompletedTask;
    }

    private static string ComputeSha256Hash(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hashBytes);
    }
}

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? RefreshToken { get; set; }
}
