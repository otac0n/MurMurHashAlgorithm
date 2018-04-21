// Copyright © John Gietzen. All Rights Reserved. This source is subject to the MIT license. Please see license.md for more information.
// The MurMurHash3 algorithm was created by Austin Appleby and put into the public domain.  See https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp

namespace MurMurHashAlgorithm
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// Computes the MurMurHash3 hash for the input data.
    /// </summary>
    public class MurMurHash3Algorithm128x86 : HashAlgorithm
    {
        private const uint C1 = 0x239b961b;
        private const uint C2 = 0xab0e9789;
        private const uint C3 = 0x38b34ae5;
        private const uint C4 = 0xa1e38b93;

        private const int ChunkSize = sizeof(ulong) * 2;
        private const int Stride = ChunkSize / sizeof(uint);

        private readonly uint seed;

        private uint h1;
        private uint h2;
        private uint h3;
        private uint h4;
        private uint length;
        private byte[] tail;
        private int tailLength;

        /// <summary>
        /// Initializes a new instance of the <see cref="MurMurHash3Algorithm128x86"/> class.
        /// </summary>
        /// <param name="seed">The seed value to use.</param>
        public MurMurHash3Algorithm128x86(int seed = 0)
        {
            this.seed = unchecked((uint)seed);
            this.Initialize();
        }

        /// <inheritdoc/>
        public override void Initialize()
        {
            this.h1 = this.seed;
            this.h2 = this.seed;
            this.h3 = this.seed;
            this.h4 = this.seed;
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
                cbSize += newArray.Length;
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
                    var k1 = GetBlock(array, ibStart, i * Stride + 0);
                    var k2 = GetBlock(array, ibStart, i * Stride + 1);
                    var k3 = GetBlock(array, ibStart, i * Stride + 2);
                    var k4 = GetBlock(array, ibStart, i * Stride + 3);

                    k1 *= C1;
                    k1 = RotateLeft(k1, 15);
                    k1 *= C2;
                    this.h1 ^= k1;

                    this.h1 = RotateLeft(this.h1, 19);
                    this.h1 += this.h2;
                    this.h1 = this.h1 * 5 + 0x561ccd1b;

                    k2 *= C2;
                    k2 = RotateLeft(k2, 16);
                    k2 *= C3;
                    this.h2 ^= k2;

                    this.h2 = RotateLeft(this.h2, 17);
                    this.h2 += this.h3;
                    this.h2 = this.h2 * 5 + 0x0bcaa747;

                    k3 *= C3;
                    k3 = RotateLeft(k3, 17);
                    k3 *= C4;
                    this.h3 ^= k3;

                    this.h3 = RotateLeft(this.h3, 15);
                    this.h3 += this.h4;
                    this.h3 = this.h3 * 5 + 0x96cd1c35;

                    k4 *= C4;
                    k4 = RotateLeft(k4, 18);
                    k4 *= C1;
                    this.h4 ^= k4;

                    this.h4 = RotateLeft(this.h4, 13);
                    this.h4 += this.h1;
                    this.h4 = this.h4 * 5 + 0x32ac3b17;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            unchecked
            {
                uint k1 = 0;
                uint k2 = 0;
                uint k3 = 0;
                uint k4 = 0;

                switch (this.tailLength)
                {
                    case 15:
                        k4 ^= (uint)this.tail[14] << 16;
                        goto case 14;
                    case 14:
                        k4 ^= (uint)this.tail[13] << 8;
                        goto case 13;
                    case 13:
                        k4 ^= (uint)this.tail[12] << 0;
                        k4 *= C4;
                        k4 = RotateLeft(k4, 18);
                        k4 *= C1;
                        this.h4 ^= k4;
                        goto case 12;
                    case 12:
                        k3 ^= (uint)this.tail[11] << 24;
                        goto case 11;
                    case 11:
                        k3 ^= (uint)this.tail[10] << 16;
                        goto case 10;
                    case 10:
                        k3 ^= (uint)this.tail[9] << 8;
                        goto case 9;
                    case 9:
                        k3 ^= (uint)this.tail[8] << 0;
                        k3 *= C3;
                        k3 = RotateLeft(k3, 17);
                        k3 *= C4;
                        this.h3 ^= k3;
                        goto case 8;
                    case 8:
                        k2 ^= (uint)this.tail[7] << 24;
                        goto case 7;
                    case 7:
                        k2 ^= (uint)this.tail[6] << 16;
                        goto case 6;
                    case 6:
                        k2 ^= (uint)this.tail[5] << 8;
                        goto case 5;
                    case 5:
                        k2 ^= (uint)this.tail[4] << 0;
                        k2 *= C2;
                        k2 = RotateLeft(k2, 16);
                        k2 *= C3;
                        this.h2 ^= k2;
                        goto case 4;
                    case 4:
                        k1 ^= (uint)this.tail[3] << 24;
                        goto case 3;
                    case 3:
                        k1 ^= (uint)this.tail[2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (uint)this.tail[1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= (uint)this.tail[0] << 0;
                        k1 *= C1;
                        k1 = RotateLeft(k1, 15);
                        k1 *= C2;
                        this.h1 ^= k1;
                        break;
                }

                this.h1 ^= this.length;
                this.h2 ^= this.length;
                this.h3 ^= this.length;
                this.h4 ^= this.length;

                this.h1 += this.h2;
                this.h1 += this.h3;
                this.h1 += this.h4;
                this.h2 += this.h1;
                this.h3 += this.h1;
                this.h4 += this.h1;

                FinalizationMix(ref this.h1);
                FinalizationMix(ref this.h2);
                FinalizationMix(ref this.h3);
                FinalizationMix(ref this.h4);

                this.h1 += this.h2;
                this.h1 += this.h3;
                this.h1 += this.h4;
                this.h2 += this.h1;
                this.h3 += this.h1;
                this.h4 += this.h1;
            }

            var result = BitConverter.GetBytes(this.h1);
            var h2Bytes = BitConverter.GetBytes(this.h2);
            var h3Bytes = BitConverter.GetBytes(this.h3);
            var h4Bytes = BitConverter.GetBytes(this.h4);
            Array.Resize(ref result, ChunkSize);
            Array.Copy(h2Bytes, 0, result, 1 * sizeof(uint), sizeof(uint));
            Array.Copy(h3Bytes, 0, result, 2 * sizeof(uint), sizeof(uint));
            Array.Copy(h4Bytes, 0, result, 3 * sizeof(uint), sizeof(uint));
            return result;
        }

        private static uint GetBlock(byte[] array, int start, int i)
        {
            i = start + i * sizeof(uint);
            return ((uint)array[i++] << 0) | ((uint)array[i++] << 8) | ((uint)array[i++] << 16) | ((uint)array[i++] << 24);
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

        private static uint RotateLeft(uint x, byte r) => (x << r) | (x >> (64 - r));
    }
}
