// Copyright © John Gietzen. All Rights Reserved. This source is subject to the MIT license. Please see license.md for more information.
// The MurMurHash3 algorithm was created by Austin Appleby and put into the public domain.  See https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp

namespace MurMurHashAlgorithm
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// Computes the MurMurHash3 hash for the input data.
    /// </summary>
    public class MurMurHash3Algorithm128x64 : HashAlgorithm
    {
        private const ulong C1 = 0x87c37b91114253d5;
        private const ulong C2 = 0x4cf5ad432745937f;

        private readonly ulong seed;

        private ulong h1;
        private ulong h2;
        private ulong length;
        private byte[] tail;
        private int tailLength;

        /// <summary>
        /// Initializes a new instance of the <see cref="MurMurHash3Algorithm128x64"/> class.
        /// </summary>
        /// <param name="seed">The seed value to use.</param>
        public MurMurHash3Algorithm128x64(long seed = 0)
        {
            this.seed = unchecked((ulong)seed);
            this.Initialize();
        }

        /// <inheritdoc/>
        public override void Initialize()
        {
            this.h1 = this.seed;
            this.h2 = this.seed;
            this.length = 0;
            this.tailLength = 0;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this.length += (ulong)cbSize;

            if (this.tailLength > 0)
            {
                var newArray = new byte[cbSize + this.tailLength];
                Array.Copy(this.tail, newArray, this.tailLength);
                Array.Copy(array, ibStart, newArray, this.tailLength, cbSize);
                array = newArray;
                ibStart = 0;
                cbSize += newArray.Length;
            }

            var blocks = cbSize / (sizeof(ulong) * 2);
            this.tailLength = cbSize % (sizeof(ulong) * 2);
            if (this.tailLength != 0)
            {
                var tail = this.tail ?? (this.tail = new byte[(sizeof(ulong) * 2) - 1]);
                Array.Copy(array, ibStart + cbSize - this.tailLength, tail, 0, this.tailLength);
            }

            unchecked
            {
                for (var i = 0; i < blocks; i++)
                {
                    var k1 = GetBlock(array, ibStart, i * 2 + 0);
                    var k2 = GetBlock(array, ibStart, i * 2 + 1);

                    k1 *= C1;
                    k1 = RotateLeft(k1, 31);
                    k1 *= C2;
                    this.h1 ^= k1;

                    this.h1 = RotateLeft(this.h1, 27);
                    this.h1 += this.h2;
                    this.h1 = this.h1 * 5 + 0x52dce729;

                    k2 *= C2;
                    k2 = RotateLeft(k2, 33);
                    k2 *= C1;
                    this.h2 ^= k2;

                    this.h2 = RotateLeft(this.h2, 31);
                    this.h2 += this.h1;
                    this.h2 = this.h2 * 5 + 0x38495ab5;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            unchecked
            {
                ulong k1 = 0;
                ulong k2 = 0;

                switch (this.tailLength)
                {
                    case 15:
                        k2 ^= ((ulong)this.tail[14]) << 48;
                        goto case 14;
                    case 14:
                        k2 ^= ((ulong)this.tail[13]) << 40;
                        goto case 13;
                    case 13:
                        k2 ^= ((ulong)this.tail[12]) << 32;
                        goto case 12;
                    case 12:
                        k2 ^= ((ulong)this.tail[11]) << 24;
                        goto case 11;
                    case 11:
                        k2 ^= ((ulong)this.tail[10]) << 16;
                        goto case 10;
                    case 10:
                        k2 ^= ((ulong)this.tail[9]) << 8;
                        goto case 9;
                    case 9:
                        k2 ^= ((ulong)this.tail[8]) << 0;
                        k2 *= C2;
                        k2 = RotateLeft(k2, 33);
                        k2 *= C1;
                        this.h2 ^= k2;
                        goto case 8;

                    case 8:
                        k1 ^= ((ulong)this.tail[7]) << 56;
                        goto case 7;
                    case 7:
                        k1 ^= ((ulong)this.tail[6]) << 48;
                        goto case 6;
                    case 6:
                        k1 ^= ((ulong)this.tail[5]) << 40;
                        goto case 5;
                    case 5:
                        k1 ^= ((ulong)this.tail[4]) << 32;
                        goto case 4;
                    case 4:
                        k1 ^= ((ulong)this.tail[3]) << 24;
                        goto case 3;
                    case 3:
                        k1 ^= ((ulong)this.tail[2]) << 16;
                        goto case 2;
                    case 2:
                        k1 ^= ((ulong)this.tail[1]) << 8;
                        goto case 1;
                    case 1:
                        k1 ^= ((ulong)this.tail[0]) << 0;
                        k1 *= C1;
                        k1 = RotateLeft(k1, 31);
                        k1 *= C2;
                        this.h1 ^= k1;
                        break;
                }

                this.h1 ^= this.length;
                this.h2 ^= this.length;

                this.h1 += this.h2;
                this.h2 += this.h1;

                FinalizationMix(ref this.h1);
                FinalizationMix(ref this.h2);

                this.h1 += this.h2;
                this.h2 += this.h1;
            }

            var result = BitConverter.GetBytes(this.h1);
            var h2Bytes = BitConverter.GetBytes(this.h2);
            Array.Resize(ref result, sizeof(ulong) * 2);
            Array.Copy(h2Bytes, 0, result, sizeof(ulong), sizeof(ulong));
            return result;
        }

        private static ulong GetBlock(byte[] array, int start, int i)
        {
            i = start + i * sizeof(ulong);
            return ((ulong)array[i++] << 0) | ((ulong)array[i++] << 8) | ((ulong)array[i++] << 16) | ((ulong)array[i++] << 24) | ((ulong)array[i++] << 32) | ((ulong)array[i++] << 40) | ((ulong)array[i++] << 48) | ((ulong)array[i++] << 56);
        }

        /// <summary>
        /// Force all bits of a hash block to avalanche
        /// </summary>
        /// <param name="block">The hash block.</param>
        private static void FinalizationMix(ref ulong block)
        {
            unchecked
            {
                block ^= block >> 33;
                block *= 0xff51afd7ed558ccd;
                block ^= block >> 33;
                block *= 0xc4ceb9fe1a85ec53;
                block ^= block >> 33;
            }
        }

        private static ulong RotateLeft(ulong x, byte r) => (x << r) | (x >> (64 - r));
    }
}
