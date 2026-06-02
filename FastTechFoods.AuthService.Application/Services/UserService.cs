using Castle.Core.Logging;
using FastTechFoods.AuthService.Application.DTOs;
using FastTechFoods.AuthService.Application.Interfaces;
using FastTechFoods.AuthService.Domain.Entities;
using FastTechFoods.AuthService.Domain.Interfaces;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace FastTechFoods.AuthService.Application.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _repo;
        private readonly ITokenService _token;
        private readonly IValidator<RegisterRequest> _registerValidator;
        private readonly IValidator<LoginRequest> _loginValidator;
        private readonly ILogger<UserService> _logger;

        public UserService(
            IUserRepository repo,
            ITokenService token,
            IValidator<RegisterRequest> registerValidator,
            IValidator<LoginRequest> loginValidator,
            ILogger<UserService> logger)
        {
            _repo = repo;
            _token = token;
            _registerValidator = registerValidator;
            _loginValidator = loginValidator;
            _logger = logger;
        }

        public async Task<AuthResponse> AuthenticateAsync(LoginRequest request)
        {
            _logger.LogInformation("starting authentication for login {UserLogin}", request.Login);
            var validation = await _loginValidator.ValidateAsync(request);

            if (!validation.IsValid)
            {
                var msg = string.Join(" | ", validation.Errors.Select(e => e.ErrorMessage));
                _logger.LogError("validation failed for login {UserLogin}: {ValidationErrors}", request.Login, msg);
                return AuthResponse.Fail(msg);
            }

            var user = await _repo.GetByEmailOrCpfAsync(request.Login);

            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) 
            {
                _logger.LogWarning("authentication failed for login {UserLogin}: invalid credentials", request.Login);
                return AuthResponse.Fail("Credenciais inválidas");
            }
                
            _logger.LogInformation("user with login {UserLogin} successfully authenticated", request.Login);
            return AuthResponse.Success(user, _token.GenerateToken(user));
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            _logger.LogInformation("starting to add a new user for email {UserEmail}", request.Email);

            var validation = await _registerValidator.ValidateAsync(request);
            if (!validation.IsValid)
            {
                var msg = string.Join(" | ", validation.Errors.Select(e => e.ErrorMessage));
                _logger.LogError("validation failed for user registration with email {UserEmail}: {ValidationErrors}", request.Email, msg);
                return AuthResponse.Fail(msg);
            }

            if (await _repo.ExistsAsync(request.Email, request.Cpf)) 
            {
                _logger.LogWarning("user with this email {UserEmail} already exists", request.Email);
                return AuthResponse.Fail("Usuário já existe");
            }

            var user = new User
            {
                Id = Guid.NewGuid(),
                Name = request.Name,
                Email = request.Email,
                Cpf = request.Cpf,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
                Role = request.Role
            };

            await _repo.AddAsync(user);
            _logger.LogInformation("user with email {UserEmail} successfully registered", request.Email);
            return AuthResponse.Success(user, _token.GenerateToken(user));
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            var users = await _repo.GetAllAsync();
            return users.Select(u => new UserDto(u));
        }

        public async Task<IEnumerable<UserDto>> GetUsersByRoleAsync(string role)
        {
            var users = await _repo.GetByRoleAsync(role);
            return users.Select(u => new UserDto(u));
        }
    }
}