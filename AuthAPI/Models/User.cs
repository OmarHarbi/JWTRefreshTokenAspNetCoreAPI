using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Models;


public class User : IdentityUser
{
    [StringLength(100)]
    public string Name { get; set; }
    public string? RefreshToken { get; set; }
}

