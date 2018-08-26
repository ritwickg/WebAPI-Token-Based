using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace TokenAuthenticationNetCore.Data.Models
{
    public class VerificationEmailModel
    {
        [Key]
        public Guid RegisterId { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
    }
}
