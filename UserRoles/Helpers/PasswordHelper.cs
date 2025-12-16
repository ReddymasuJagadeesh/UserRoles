using System;
using System.Linq;

namespace UserRoles.Helpers
{
    public static class PasswordHelper
    {
        public static string GeneratePassword(int length = 12)
        {
            const string chars =
                "ABCDEFGHJKLMNOPQRSTUVWXYZ" +
                "abcdefghijkmnopqrstuvwxyz" +
                "0123456789" +
                "!@#$%^&*";

            var random = new Random();

            return new string(Enumerable
                .Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)])
                .ToArray());
        }
    }
}
