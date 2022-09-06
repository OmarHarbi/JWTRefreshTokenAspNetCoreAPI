using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos.Auth
{
    public class CreateRoleDTO
    {
        [Required(ErrorMessage = "ادخل الصلاحية")]
        public string RoleName { get; set; }
    }
}
