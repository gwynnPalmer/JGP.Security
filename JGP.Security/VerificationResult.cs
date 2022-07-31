// ***********************************************************************
// Assembly         : JGP.Security
// Author           : Joshua Gwynn-Palmer
// Created          : 07-31-2022
//
// Last Modified By : Joshua Gwynn-Palmer
// Last Modified On : 07-31-2022
// ***********************************************************************
// <copyright file="VerificationResult.cs" company="Joshua Gwynn-Palmer">
//     Joshua Gwynn-Palmer
// </copyright>
// <summary></summary>
// ***********************************************************************

namespace JGP.Security
{
    using System.Text.Json.Serialization;

    /// <summary>
    ///     Class VerificationResult.
    /// </summary>
    public class VerificationResult
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="VerificationResult" /> class.
        /// </summary>
        private VerificationResult()
        {
        }

        /// <summary>
        ///     Gets or sets the message.
        /// </summary>
        /// <value>The message.</value>
        [JsonPropertyName("message")]
        public string? Message { get; set; }

        /// <summary>
        ///     Gets or sets the outcome.
        /// </summary>
        /// <value>The outcome.</value>
        [JsonPropertyName("outcome")]
        public VerificationOutcome Outcome { get; set; }

        /// <summary>
        ///     Gets the failure result.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <returns><see cref="VerificationResult"/>.</returns>
        public static VerificationResult GetFailureResult(string message)
        {
            return new VerificationResult
            {
                Outcome = VerificationOutcome.Failure,
                Message = message
            };
        }

        /// <summary>
        ///     Gets the success result.
        /// </summary>
        /// <returns><see cref="VerificationResult"/>.</returns>
        public static VerificationResult GetSuccessResult()
        {
            return new VerificationResult
            {
                Outcome = VerificationOutcome.Success,
                Message = null
            };
        }
    }
}