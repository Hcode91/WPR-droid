using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using WPR.Xna.Rhi;

namespace WPR.Xna.Compat
{
    /// <summary>
    /// What the patcher points a WP7 native-interop title's COM calls at (see
    /// <see cref="NativeComBackend"/>): <c>new C()</c> of a <c>[ComImport]</c> class.
    /// </summary>
    public static class ComInterop
    {
        /// <summary>REGDB_E_CLASSNOTREG: what WP7 threw for a class no DLL registered.</summary>
        private const int ClassNotRegistered = unchecked((int)0x80040154);

        /// <summary><c>newobj</c> of a <c>[ComImport]</c> class, rewritten to this with the class's token.</summary>
        public static object CreateComObject(RuntimeTypeHandle comClass)
        {
            Type type = Type.GetTypeFromHandle(comClass)!;
            INativeComHost host = NativeComBackend.Host
                ?? throw new COMException($"No native code can run here, so {type.FullName} cannot be created.", ClassNotRegistered);
            return host.CreateInstance(type);
        }

        /// <summary>
        /// <c>Marshal.ReleaseComObject</c>: a native object here is a managed proxy, which the BCL's
        /// call rejects (and off Windows there is no COM at all). WPR's proxies hold no references
        /// that a release would drop, so they answer 0, as for a last reference.
        /// </summary>
        public static int ReleaseComObject(object o)
        {
            if (o is null)
            {
                throw new ArgumentNullException(nameof(o));
            }

            return OperatingSystem.IsWindows() && Marshal.IsComObject(o) ? Marshal.ReleaseComObject(o) : 0;
        }
    }

    /// <summary>
    /// Arrays pinned by a native-interop title, by host address: the bridge to native code looks a
    /// host pointer up here to find the array it points into, and keeps a mirror of it in the
    /// emulated memory for as long as it is pinned.
    /// </summary>
    public static class PinnedArrays
    {
        /// <summary>One pinned array. <see cref="GuestCopy"/> and <see cref="Mirror"/> belong to the bridge.</summary>
        public sealed class Entry
        {
            internal Entry(Array array, IntPtr address, long length, int owner)
            {
                Array = array;
                Address = address;
                Length = length;
                Owner = owner;
            }

            public Array Array { get; }

            /// <summary>The host address of element 0.</summary>
            public IntPtr Address { get; }

            /// <summary>Bytes.</summary>
            public long Length { get; }

            /// <summary>The managed thread that pinned it: the one whose calls into native code keep it in step.</summary>
            public int Owner { get; }

            /// <summary>The guest address of the mirror, 0 until the array is first handed to native code.</summary>
            public long Mirror { get; set; }
        }

        private static readonly object Gate = new();
        private static readonly List<Entry> Live = new();

        /// <summary>Raised (on the unpinning thread) when an array that had a mirror is unpinned, so the bridge can free it.</summary>
        public static event Action<Entry>? Released;

        public static void Note(Array array, IntPtr address)
        {
            long length = (long)System.Buffer.ByteLength(array);
            lock (Gate)
            {
                foreach (Entry existing in Live)
                {
                    if (ReferenceEquals(existing.Array, array) && existing.Address == address)
                    {
                        return;
                    }
                }

                Live.Add(new Entry(array, address, length, Environment.CurrentManagedThreadId));
            }
        }

        public static void Forget(Array array)
        {
            List<Entry>? gone = null;
            lock (Gate)
            {
                for (int i = Live.Count - 1; i >= 0; i--)
                {
                    if (ReferenceEquals(Live[i].Array, array))
                    {
                        (gone ??= new()).Add(Live[i]);
                        Live.RemoveAt(i);
                    }
                }
            }

            if (gone is not null)
            {
                foreach (Entry entry in gone)
                {
                    if (entry.Mirror != 0)
                    {
                        Released?.Invoke(entry);
                    }
                }
            }
        }

        /// <summary>The pinned array <paramref name="address"/> points into, if any.</summary>
        public static Entry? Find(IntPtr address)
        {
            long a = (long)address;
            lock (Gate)
            {
                foreach (Entry entry in Live)
                {
                    long start = (long)entry.Address;
                    if (a >= start && a < start + Math.Max(1, entry.Length))
                    {
                        return entry;
                    }
                }
            }

            return null;
        }

        /// <summary>The pinned array whose mirror holds guest address <paramref name="guest"/>, if any.</summary>
        public static Entry? FindMirror(long guest)
        {
            lock (Gate)
            {
                foreach (Entry entry in Live)
                {
                    if (entry.Mirror != 0 && guest >= entry.Mirror && guest < entry.Mirror + Math.Max(1, entry.Length))
                    {
                        return entry;
                    }
                }
            }

            return null;
        }

        /// <summary>The live arrays with a mirror that <paramref name="owner"/> pinned.</summary>
        public static List<Entry> MirroredBy(int owner)
        {
            var result = new List<Entry>();
            lock (Gate)
            {
                foreach (Entry entry in Live)
                {
                    if (entry.Mirror != 0 && entry.Owner == owner)
                    {
                        result.Add(entry);
                    }
                }
            }

            return result;
        }

        /// <summary>Forgets every entry (a new launch).</summary>
        public static void Reset()
        {
            lock (Gate)
            {
                Live.Clear();
            }

            Released = null;
        }
    }
}
