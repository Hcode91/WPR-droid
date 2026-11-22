using System;
using System.Runtime.InteropServices;
using WPR.Xna.Compat;

namespace Microsoft.Phone.InteropServices
{
    /// <summary>
    /// Shim for <c>Microsoft.Phone.InteropServices.GCHandle</c>: how a WP7 native-interop title pinned
    /// an array to hand its address to its native DLL (Fusion's vertex, index and audio buffers).
    /// Over the BCL's handle; a pinned array's address is recorded in <see cref="PinnedArrays"/>, so
    /// the bridge to native code (which runs in emulated memory) can keep a copy of it there.
    /// </summary>
    public sealed class GCHandle
    {
        private System.Runtime.InteropServices.GCHandle _handle;

        public static GCHandle Alloc(object value, GCHandleType type)
            => new() { _handle = System.Runtime.InteropServices.GCHandle.Alloc(value, type) };

        public bool IsAllocated => _handle.IsAllocated;

        public object? Target
        {
            get => _handle.Target;
            set => _handle.Target = value;
        }

        public IntPtr AddrOfPinnedObject()
        {
            IntPtr address = _handle.AddrOfPinnedObject();
            if (_handle.Target is Array array)
            {
                PinnedArrays.Note(array, address);
            }

            return address;
        }

        public void Free()
        {
            if (_handle.IsAllocated && _handle.Target is Array array)
            {
                PinnedArrays.Forget(array);
            }

            _handle.Free();
        }
    }
}
