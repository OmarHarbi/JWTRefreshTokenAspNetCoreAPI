using AuthAPI.Dtos.Auth;
using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Service
{
    public interface IAuthService
    {
        Task<AuthDto> RegisterAsync(RegisterDto model);
        Task<string> AddRoleToUserAsync(AddRoleToUserDto model);
        Task<IdentityResult> CreateRole(CreateRoleDTO model);
        Task<AuthenticationResponse> Login(LoginDTO model);

    }
}
