using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace pbkdf2
{
    internal class ProgramOptions
    {
        public string HashingAlgorithm { get; set; }
        public string Salt { get; set; }
        public bool HasSalt => !String.IsNullOrEmpty(Salt);
        public string Password { get; set; }
        public bool HasPassword => !String.IsNullOrEmpty(Password);
    }
}
