// Copyright © John Gietzen. All Rights Reserved. This source is subject to the MIT license. Please see license.md for more information.
// The MurMurHash3 algorithm was created by Austin Appleby and put into the public domain.  See https://github.com/aappleby/smhasher/blob/master/src/KeysetTest.cpp

namespace MurMurHashAlgorithm.Tests
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using Xunit;

    public class VerificationTests
    {
        [Theory]
        [InlineData(typeof(MurMurHash3Algorithm128x64), 0x6384BA69)]
        public void VerificationTest(Type hashType, int expected)
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
            var verification = (final[0] << 0) | (final[1] << 8) | (final[2] << 16) | (final[3] << 24);

            Assert.Equal(expected, verification);
        }
    }
}
