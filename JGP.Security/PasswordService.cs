// ***********************************************************************
// Assembly         : JGP.Security
// Author           : Joshua Gwynn-Palmer
// Created          : 07-10-2022
//
// Last Modified By : Joshua Gwynn-Palmer
// Last Modified On : 07-10-2022
// ***********************************************************************
// <copyright file="PasswordService.cs" company="Joshua Gwynn-Palmer">
//     Joshua Gwynn-Palmer
// </copyright>
// <summary></summary>
// ***********************************************************************

namespace JGP.Security
{
    using System.Security.Cryptography;

    /// <summary>
    ///     Interface IPasswordService
    /// Implements the <see cref="System.IDisposable" />
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public interface IPasswordService : IDisposable
    {
        /// <summary>
        ///     Creates a hash from a password with 10000 iterations
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>System.String.</returns>
        string Hash(string password);

        /// <summary>
        ///     Verifies a password against a hash.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="hashedPassword">The hashed password.</param>
        /// <returns><c>true</c> if [Match], <c>false</c> otherwise.</returns>
        bool Verify(string password, string hashedPassword);
    }

    /// <summary>
    ///     Class PasswordService.
    /// </summary>
    public class PasswordService : IPasswordService
    {
        /// <summary>
        ///     Size of hash.
        /// </summary>
        private const int HashSize = 20;

        /// <summary>
        ///     Size of salt.
        /// </summary>
        private const int SaltSize = 16;
        /// <summary>
        ///     The generator
        /// </summary>
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        /// <summary>
        ///     Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Rng?.Dispose();
        }

        /// <summary>
        ///     Creates a hash from a password with 10000 iterations
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>System.String.</returns>
        public string Hash(string password)
        {
            return Hash(password, 10000);
        }

        /// <summary>
        ///     Verifies a password against a hash.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="hashedPassword">The hashed password.</param>
        /// <returns><c>true</c> if [Match], <c>false</c> otherwise.</returns>
        public bool Verify(string password, string hashedPassword)
        {
            var hashBytes = Convert.FromBase64String(hashedPassword);

            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
            var hash = pbkdf2.GetBytes(HashSize);

            for (var i = 0; i < HashSize; i++)
            {
                if (hashBytes[i + SaltSize] != hash[i])
                {
                    return false;
                }
            }

            return true;
        }

        #region HELPERS

        /// <summary>
        ///     Hashes the specified password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="iterations">The iterations.</param>
        /// <returns>System.String.</returns>
        private static string Hash(string password, int iterations)
        {
            byte[] salt;
            Rng.GetBytes(salt = new byte[SaltSize]);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            var hash = pbkdf2.GetBytes(HashSize);

            var hashBytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

            return Convert.ToBase64String(hashBytes);
        }

        #endregion
    }
}