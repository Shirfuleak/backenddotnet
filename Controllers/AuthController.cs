using JwtAuthDemo.Data;
using Microsoft.AspNetCore.Authorization;
using JwtAuthDemo.DTOs;
using JwtAuthDemo.Models;
using JwtAuthDemo.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;

    public AuthController(AppDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromForm] UserDto request)
    {
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return BadRequest("User already exists");

        var user = new User
        {
            Username = request.Username,
            PasswordHash = HashPassword(request.Password),
            //ImagePath = image != null ? $"images/{Guid.NewGuid()}_{image.FileName}" : null
        };

        //if (image != null)
        //{
        //    var path = Path.Combine("wwwroot", user.ImagePath);
        //    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        //    using var stream = new FileStream(path, FileMode.Create);
        //    await image.CopyToAsync(stream);
        //}

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok("User registered");
    }



    [HttpPost("login")]
    public async Task<IActionResult> Login(UserDto request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null || user.PasswordHash != HashPassword(request.Password))
            return Unauthorized("Invalid credentials");

        var token = _tokenService.CreateToken(user);
        return Ok(new { token });
    }

    private string HashPassword(string password)
    {
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var username = User.Identity?.Name;
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return Unauthorized();

        return Ok(new
        {
            message = $"Welcome {user.Username}",
            //imageUrl = user.ImagePath != null ? $"/{user.ImagePath}" : null
        });
    }

}