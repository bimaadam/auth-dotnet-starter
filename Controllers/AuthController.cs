using System.Security.Cryptography;
using System.Text;
using dotnet_auth.Models;
using dotnet_auth.Services;
using Microsoft.AspNetCore.Mvc;

namespace dotnet_auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtTokenService _tokenService;
    private readonly IUserService _userService;

    public AuthController(IJwtTokenService tokenService, IUserService userService)
    {
        _tokenService = tokenService;
        _userService = userService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        if (await _userService.ExistsByUsernameAsync(request.Username))
        {
            return BadRequest(new { message = "Username already exists" });
        }

        if (await _userService.ExistsByEmailAsync(request.Email))
        {
            return BadRequest(new { message = "Email already exists" });
        }

        var user = await _userService.CreateAsync(request.Username, request.Email, request.Password);
        var token = _tokenService.GenerateToken(user.Id, user.Username, user.Email);
        var refreshToken = _tokenService.GenerateRefreshToken();

        await _userService.SetRefreshTokenAsync(user.Id, refreshToken);

        return Ok(new AuthResponse
        {
            Token = token,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60),
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email
            }
        });
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        var user = await _userService.GetByUsernameAsync(request.Username);
        
        if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
        {
            return Unauthorized(new { message = "Invalid username or password" });
        }

        var token = _tokenService.GenerateToken(user.Id, user.Username, user.Email);
        var refreshToken = _tokenService.GenerateRefreshToken();

        await _userService.SetRefreshTokenAsync(user.Id, refreshToken);

        return Ok(new AuthResponse
        {
            Token = token,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60),
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email
            }
        });
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<AuthResponse>> Refresh([FromBody] RefreshRequest request)
    {
        var user = await _userService.GetByRefreshTokenAsync(request.RefreshToken);
        
        if (user == null)
        {
            return Unauthorized(new { message = "Invalid refresh token" });
        }

        var token = _tokenService.GenerateToken(user.Id, user.Username, user.Email);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        await _userService.SetRefreshTokenAsync(user.Id, newRefreshToken);

        return Ok(new AuthResponse
        {
            Token = token,
            RefreshToken = newRefreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60),
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email
            }
        });
    }

    private static bool VerifyPassword(string password, string passwordHash)
    {
        var hash = ComputeSha256Hash(password);
        return hash == passwordHash;
    }

    private static string ComputeSha256Hash(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hashBytes);
    }
}

public class RefreshRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}
