// Copyright © John Gietzen. All Rights Reserved. This source is subject to the MIT license. Please see license.md for more information.

namespace MurMurHashAlgorithm.Tests
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using Xunit;

    public class MurMurHash3Algorithm128x64Tests
    {
        [Theory]
        [InlineData(123, "Hello, world!", "8743acad421c8c73d373c3f5f19732fd")]
        [InlineData(321, "Hello, world!", "f86d4004ca47f42bb9546c7979200aee")]
        [InlineData(123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "becf7e04dbcf74637751664ef66e73e0")]
        [InlineData(123, "", "4cd9597081679d1abd92f8784bace33d")]
        public void ComputeHash_WhenGivenAWellKnownValue_ProducesTheExpectedResult(long seed, string input, string expected)
        {
            var inputBytes = Encoding.ASCII.GetBytes(input).ToArray();
            var subject = new MurMurHash3Algorithm128x64(seed);

            var hash = subject.ComputeHash(inputBytes);
            var result = $"{BitConverter.ToUInt32(hash, 0):x8}{BitConverter.ToUInt32(hash, 4):x8}{BitConverter.ToUInt32(hash, 8):x8}{BitConverter.ToUInt32(hash, 12):x8}";

            Assert.Equal(expected, result);
        }
    }
}
