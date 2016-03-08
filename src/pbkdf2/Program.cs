using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace pbkdf2
{
    public class Program
    {
        private readonly string[] _args;
        private readonly TextReader _inputReader;
        private readonly TextWriter _outputWriter;
        private readonly TextWriter _errorWriter;
        private byte[] _password;
        private byte[] _salt;
        private const int DefaultSaltSize = 12;
        private const int DefaultKeySize = 24;
        private const int DefaultIterationCount = 1000;

        public Program(string[] args, TextReader input,
            TextWriter output, TextWriter error)
        {
            _args = args;
            _inputReader = input;
            _outputWriter = output;
            _errorWriter = error;
        }

        public static void Main(string[] args)
        {
            (new Program(args, Console.In, Console.Out, Console.Error)).Run();
        }

        public void Run()
        {
            if (_args.Length < 1)
            {
                ShowHelp();
                return;
            }
            var options = new ProgramOptions();
            options.HashingAlgorithm = _args[0];
            if (_args.Length >= 2)
            {
                if (_args.Length >= 3)
                {
                    options.Salt = _args[1];
                    options.Password = _args[2];
                }
                else
                {
                    options.Password = _args[1];
                }
            }
            _password = Encoding.UTF8.GetBytes(options.HasPassword ? options.Password : RetrievePassword());
            if (options.HasSalt)
            {
                _salt = Convert.FromBase64String(options.Salt);
            }
            else
            {
                _salt = new byte[DefaultSaltSize];
                
                using (var randomNumberGenerator = RandomNumberGenerator.Create())
                {
                    randomNumberGenerator.GetBytes(_salt);
                }
            }

            var hashAlgorithm = GetHashAlgorithm(options.HashingAlgorithm);

            byte[] passwordHash = hashAlgorithm.ComputeHash(_password);

            var deriver = new Rfc2898DeriveBytes(passwordHash, _salt, DefaultIterationCount);
            var derivedPassword = deriver.GetBytes(DefaultKeySize);

            ShowResult(derivedPassword, _salt, options.HashingAlgorithm, DefaultIterationCount);
        }

        private HashAlgorithm GetHashAlgorithm(string hashingAlgorithm)
        {
           
            if (String.Equals("md5", hashingAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return MD5.Create();
            }
             if (String.Equals("sha1", hashingAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return SHA1.Create();
            }
             if (String.Equals("sha256", hashingAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return SHA256.Create();
            }
            throw new ArgumentException();
        }

        private void ShowResult(byte[] passwordHash, byte[] salt, string hashingAlgorithm, int iterationCount)
        {
            var encodedPasswordHash = Convert.ToBase64String(passwordHash);
            var ecnodedSalt = Convert.ToBase64String(salt);
            var result = 
            $"PBKDF2${hashingAlgorithm}${iterationCount}${ecnodedSalt}${encodedPasswordHash}";
            _outputWriter.WriteLine(result);
        }


        private string RetrievePassword()
        {
            _outputWriter.Write("Password:");
            return _inputReader.ReadLine();
        }

        private void ShowHelp()
        {
            _outputWriter.WriteLine("Usage: ");
            _outputWriter.WriteLine("pbkdf2 hash_type [salt] [password]");
        }
    }
}
