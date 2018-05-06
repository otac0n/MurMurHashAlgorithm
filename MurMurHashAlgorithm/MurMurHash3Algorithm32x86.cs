// Copyright © John Gietzen. All Rights Reserved. This source is subject to the MIT license. Please see license.md for more information.
// The MurMurHash3 algorithm was created by Austin Appleby and put into the public domain.  See https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp

namespace MurMurHashAlgorithm
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// Computes the MurMurHash3 hash for the input data.
    /// </summary>
    public class MurMurHash3Algorithm32x86 : HashAlgorithm
    {
        private const uint C1 = 0xcc9e2d51;
        private const uint C2 = 0x1b873593;

        private const int ChunkSize = sizeof(uint);

        private readonly uint seed;

        private uint h1;
        private uint length;
        private byte[] tail;
        private int tailLength;

        /// <summary>
        /// Initializes a new instance of the <see cref="MurMurHash3Algorithm32x86"/> class.
        /// </summary>
        /// <param name="seed">The seed value to use.</param>
        public MurMurHash3Algorithm32x86(int seed = 0)
        {
            this.seed = unchecked((uint)seed);
            this.Initialize();
        }

        /// <inheritdoc />
        public override int HashSize => ChunkSize;

        /// <inheritdoc />
        public override int InputBlockSize => ChunkSize;

        /// <inheritdoc />
        public override int OutputBlockSize => ChunkSize;

        /// <inheritdoc/>
        public override void Initialize()
        {
            this.h1 = this.seed;
            this.length = 0;
            this.tailLength = 0;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this.length += (uint)cbSize;

            if (this.tailLength > 0)
            {
                var newArray = new byte[cbSize + this.tailLength];
                Array.Copy(this.tail, newArray, this.tailLength);
                Array.Copy(array, ibStart, newArray, this.tailLength, cbSize);
                array = newArray;
                ibStart = 0;
                cbSize = newArray.Length;
            }

            var blocks = cbSize / ChunkSize;
            this.tailLength = cbSize % ChunkSize;
            if (this.tailLength != 0)
            {
                var tail = this.tail ?? (this.tail = new byte[ChunkSize - 1]);
                Array.Copy(array, ibStart + cbSize - this.tailLength, tail, 0, this.tailLength);
            }

            unchecked
            {
                for (var i = 0; i < blocks; i++)
                {
                    var k1 = GetBlock(array, ibStart, i);

                    k1 *= C1;
                    k1 = RotateLeft(k1, 15);
                    k1 *= C2;

                    this.h1 ^= k1;
                    this.h1 = RotateLeft(this.h1, 13);
                    this.h1 = this.h1 * 5 + 0xe6546b64;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            unchecked
            {
                uint k1 = 0;

                switch (this.tailLength)
                {
                    case 3:
                        k1 ^= (uint)this.tail[2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (uint)this.tail[1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= this.tail[0];
                        k1 *= C1;
                        k1 = RotateLeft(k1, 15);
                        k1 *= C2;
                        this.h1 ^= k1;
                        break;
                }

                this.h1 ^= this.length;

                FinalizationMix(ref this.h1);
            }

            return BitConverter.GetBytes(this.h1);
        }

        /// <summary>
        /// Force all bits of a hash block to avalanche
        /// </summary>
        /// <param name="block">The hash block.</param>
        private static void FinalizationMix(ref uint block)
        {
            unchecked
            {
                block ^= block >> 16;
                block *= 0x85ebca6b;
                block ^= block >> 13;
                block *= 0xc2b2ae35;
                block ^= block >> 16;
            }
        }

        private static uint GetBlock(byte[] array, int start, int i)
        {
            i = start + i * sizeof(uint);
            return ((uint)array[i++] << 0) | ((uint)array[i++] << 8) | ((uint)array[i++] << 16) | ((uint)array[i++] << 24);
        }

        private static uint RotateLeft(uint x, byte r) => (x << r) | (x >> (64 - r));
    }
}
