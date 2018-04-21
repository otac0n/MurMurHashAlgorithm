// The MurMurHash3 algorithm was created by Austin Appleby and put into the public domain.  See https://github.com/aappleby/smhasher/blob/master/src/KeysetTest.cpp
// Some tests were written by Peter Scott, and are placed in the public domain.  See: https://github.com/PeterScott/murmur3/blob/master/test.c

namespace MurMurHashAlgorithm.Tests
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Xunit;

    public class VerificationTests
    {
        [Theory]
        [InlineData(typeof(MurMurHash3Algorithm32x86), 0xB0F57EE3)]
        [InlineData(typeof(MurMurHash3Algorithm128x86), 0xB3ECE62A)]
        [InlineData(typeof(MurMurHash3Algorithm128x64), 0x6384BA69)]
        public void VerificationTest(Type hashType, uint expected)
        {
            var hash = new Func<byte[], object, byte[]>((array, seed) => ((HashAlgorithm)Activator.CreateInstance(hashType, new[] { seed })).ComputeHash(array));

            // Hash keys of the form {0}, {0,1}, {0,1,2}... up to N=255,using 256-N as the seed
            var hashes = new byte[256][];
            for (var i = 0; i < 256; i++)
            {
                hashes[i] = hash(Enumerable.Range(0, i).Select(b => (byte)b).ToArray(), 256 - i);
            }

            // Then hash the result array
            var final = hash(hashes.SelectMany(b => b).ToArray(), 0);

            // The first four bytes of that hash, interpreted as a little-endian integer, is our verification value
            var verification = ((uint)final[0] << 0) | ((uint)final[1] << 8) | ((uint)final[2] << 16) | ((uint)final[3] << 24);

            Assert.Equal(expected, verification);
        }

        [Theory]
        [InlineData(typeof(MurMurHash3Algorithm32x86), 1234, "Hello, world!", "faf6cdb3")]
        [InlineData(typeof(MurMurHash3Algorithm32x86), 4321, "Hello, world!", "bf505788")]
        [InlineData(typeof(MurMurHash3Algorithm32x86), 1234, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "8905ac28")]
        [InlineData(typeof(MurMurHash3Algorithm32x86), 1234, "", "0f2cc00b")]
        [InlineData(typeof(MurMurHash3Algorithm128x86), 123, "Hello, world!", "61c9129e5a1aacd7a41621629e37c886")]
        [InlineData(typeof(MurMurHash3Algorithm128x86), 321, "Hello, world!", "d5fbdcb3c26c4193045880c5a7170f0f")]
        [InlineData(typeof(MurMurHash3Algorithm128x86), 123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "5e40bab278825a164cf929d31fec6047")]
        [InlineData(typeof(MurMurHash3Algorithm128x86), 123, "", "fedc524526f3e79926f3e79926f3e799")]
        [InlineData(typeof(MurMurHash3Algorithm128x64), 123, "Hello, world!", "8743acad421c8c73d373c3f5f19732fd")]
        [InlineData(typeof(MurMurHash3Algorithm128x64), 321, "Hello, world!", "f86d4004ca47f42bb9546c7979200aee")]
        [InlineData(typeof(MurMurHash3Algorithm128x64), 123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "becf7e04dbcf74637751664ef66e73e0")]
        [InlineData(typeof(MurMurHash3Algorithm128x64), 123, "", "4cd9597081679d1abd92f8784bace33d")]
        public void ComputeHash_WhenGivenAWellKnownValue_ProducesTheExpectedResult(Type hashType, object seed, string input, string expected)
        {
            var inputBytes = Encoding.ASCII.GetBytes(input).ToArray();
            var subject = (HashAlgorithm)Activator.CreateInstance(hashType, new[] { seed });

            var hash = subject.ComputeHash(inputBytes);
            var result = string.Concat(Enumerable.Range(0, hash.Length / sizeof(uint)).Select(h => BitConverter.ToUInt32(hash, h * sizeof(uint)).ToString("x8")));

            Assert.Equal(expected, result);
        }
    }
}
