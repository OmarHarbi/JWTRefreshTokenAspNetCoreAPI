using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos.Auth
{
    public class RegisterDto
    {
        [StringLength(100)]
        [Required(ErrorMessage ="ادخل الاسم")]
        public string Name { get; set; }

        [StringLength(128)]
        [Required(ErrorMessage = "ادخل البريد الالكتروني")]
        public string Email { get; set; }

        [StringLength(256)]
        [Required(ErrorMessage = "ادخل كلمة المرور")]
        public string Password { get; set; }
    }
}
