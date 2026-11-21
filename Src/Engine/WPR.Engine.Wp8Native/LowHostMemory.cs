using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WPR.Wp8Native
{
    /// <summary>
    /// Host buffers whose addresses fit in 31 bits. WP7 managed code ran on a 32-bit phone and
    /// does pointer arithmetic through <c>IntPtr.ToInt32()</c> (Fusion's
    /// <c>BundleInputStream.Read</c>: <c>new IntPtr(data.ToInt32() + i)</c>), which throws
    /// <see cref="OverflowException"/> for any address above 2 GB, i.e. for every
    /// <c>AllocHGlobal</c> block on a 64-bit host. A guest buffer handed to managed code is
    /// therefore copied into one of these instead.
    /// </summary>
    /// <remarks>
    /// Blocks are kept and reused (rounded to 64 KB), never unmapped, so the cost is bounded by
    /// the largest number of buffers in flight at once. When no memory below 2 GB can be had the
    /// caller falls back to <c>AllocHGlobal</c>, which is what it did before.
    /// </remarks>
    internal static unsafe class LowHostMemory
    {
        private static readonly object Gate = new();
        private static readonly List<(IntPtr Block, int Size)> Free = new();
        private static readonly Dictionary<IntPtr, int> Rented = new();

        /// <summary>A block of at least <paramref name="size"/> bytes below 2 GB, or IntPtr.Zero.</summary>
        public static IntPtr Rent(int size)
        {
            lock (Gate)
            {
                int best = -1;
                for (int i = 0; i < Free.Count; i++)
                {
                    if (Free[i].Size >= size && (best < 0 || Free[i].Size < Free[best].Size))
                    {
                        best = i;
                    }
                }

                if (best >= 0)
                {
                    (IntPtr block, int have) = Free[best];
                    Free.RemoveAt(best);
                    Rented[block] = have;
                    return block;
                }

                int rounded = (int)(((long)size + 0xFFFF) & ~0xFFFFL);
                IntPtr fresh = MapLow(rounded);
                if (fresh != IntPtr.Zero)
                {
                    Rented[fresh] = rounded;
                }

                return fresh;
            }
        }

        /// <summary>True when <paramref name="block"/> came from <see cref="Rent"/>; it is then reusable.</summary>
        public static bool Return(IntPtr block)
        {
            lock (Gate)
            {
                if (!Rented.Remove(block, out int size))
                {
                    return false;
                }

                Free.Add((block, size));
                return true;
            }
        }

        private static IntPtr MapLow(int size)
        {
            for (long hint = 0x10000000; hint < 0x7F000000; hint += 0x01000000)
            {
                IntPtr p = OperatingSystem.IsWindows()
                    ? VirtualAlloc((IntPtr)hint, (nuint)size, 0x3000 /* MEM_COMMIT | MEM_RESERVE */, 0x04 /* PAGE_READWRITE */)
                    : mmap((IntPtr)hint, (nuint)size, 3 /* PROT_READ | PROT_WRITE */, 0x22 /* MAP_PRIVATE | MAP_ANONYMOUS */, -1, 0);
                if (!OperatingSystem.IsWindows() && p == new IntPtr(-1))
                {
                    p = IntPtr.Zero;
                }

                if (p != IntPtr.Zero && (long)p + size <= 0x7FFFFFFF)
                {
                    return p;
                }

                if (p != IntPtr.Zero)
                {
                    if (OperatingSystem.IsWindows())
                    {
                        VirtualFree(p, 0, 0x8000 /* MEM_RELEASE */);
                    }
                    else
                    {
                        munmap(p, (nuint)size);
                    }
                }
            }

            return IntPtr.Zero;
        }

        [DllImport("kernel32")] private static extern IntPtr VirtualAlloc(IntPtr address, nuint size, uint type, uint protect);
        [DllImport("kernel32")] private static extern bool VirtualFree(IntPtr address, nuint size, uint type);
        [DllImport("libc")] private static extern IntPtr mmap(IntPtr address, nuint length, int prot, int flags, int fd, long offset);
        [DllImport("libc")] private static extern int munmap(IntPtr address, nuint length);
    }
}
