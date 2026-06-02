using FastTechFoods.AuthService.Application.DTOs;
using FastTechFoods.AuthService.Application.Interfaces;
using FastTechFoods.AuthService.Domain.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace FastTechFoods.AuthService.Api.Controllers
{
    [ApiController]
    [Route("api/user")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService authService)
        {
            _userService = authService;
        }

        /// <summary>
        /// Lista os usuários do sistema.
        /// Gerente vê todos, Atendente vê apenas clientes.
        /// </summary>
        [HttpGet]
        [Authorize]
        [ProducesResponseType(typeof(IEnumerable<UserDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> GetAll()
        {
            var role = User.FindFirst(ClaimTypes.Role)?.Value;
            IEnumerable<UserDto> users;

            if (string.IsNullOrEmpty(role)) return Forbid();
            if (role == UserRoles.Gerente) users = await _userService.GetAllUsersAsync();
            else if (role == UserRoles.Atendente) users = await _userService.GetUsersByRoleAsync(UserRoles.Cliente);
            else return Forbid();

            return Ok(users);
        }

        /// <summary>
        /// Realiza o login de um usuário com CPF ou Email e senha.
        /// </summary>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await _userService.AuthenticateAsync(request);
            return result.IsAuthenticated ? Ok(result) : Unauthorized(result);
        }

        /// <summary>
        /// Registra um novo usuário. Apenas clientes podem se registrar livremente.
        /// Para outros papéis (Atendente, Gerente), é necessário estar autenticado como Gerente.
        /// </summary>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (request.Role != UserRoles.Cliente)
            {
                if (!User.Identity?.IsAuthenticated ?? true || !User.IsInRole(UserRoles.Gerente))
                    return Forbid();
            }

            var result = await _userService.RegisterAsync(request);
            return result.IsAuthenticated
                ? Ok(result)
                : BadRequest(result.Message);
        }
    }
}
