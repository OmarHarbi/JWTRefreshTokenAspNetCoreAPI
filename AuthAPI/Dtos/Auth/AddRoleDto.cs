using System.ComponentModel.DataAnnotations;
namespace AuthAPI.Dtos.Auth
{
    public class AddRoleToUserDto
    {
        [Required(ErrorMessage ="ادخل معرف المستخدم")]
        public string UserId { get; set; }

        [Required(ErrorMessage = "ادخل الصلاحية")]
        public string Role { get; set; }
    }
}
