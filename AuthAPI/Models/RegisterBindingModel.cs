using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AuthAPI.Models
{
    public class RegisterBindingModel
    {
            [Required]
            [StringLength(25, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 4)]
            public string Username { get; set; }

            [Required(ErrorMessage = "Email is a required field")]
            [EmailAddress]
            public string Email { get; set; }

            [Required(ErrorMessage = "Password is a required field")]
            [DataType(DataType.Password)]
            public string Password { get; set; }


        
    }
}
