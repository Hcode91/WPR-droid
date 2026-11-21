using System;
using System.Runtime.InteropServices;

namespace Microsoft.Phone.InteropServices
{
    /// <summary>Shim for <c>Microsoft.Phone.InteropServices.Marshal</c>: the copy and size helpers WP7 gave native-interop titles.</summary>
    public static class Marshal
    {
        public static int SizeOf(object structure) => structure is Type type
            ? System.Runtime.InteropServices.Marshal.SizeOf(type)
            : System.Runtime.InteropServices.Marshal.SizeOf(structure);

        public static int SizeOf(Type t) => System.Runtime.InteropServices.Marshal.SizeOf(t);

        public static void Copy(byte[] source, int startIndex, IntPtr destination, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, startIndex, destination, length);

        public static void Copy(IntPtr source, byte[] destination, int startIndex, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, destination, startIndex, length);

        public static void Copy(short[] source, int startIndex, IntPtr destination, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, startIndex, destination, length);

        public static void Copy(IntPtr source, short[] destination, int startIndex, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, destination, startIndex, length);

        public static void Copy(int[] source, int startIndex, IntPtr destination, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, startIndex, destination, length);

        public static void Copy(IntPtr source, int[] destination, int startIndex, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, destination, startIndex, length);

        public static void Copy(float[] source, int startIndex, IntPtr destination, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, startIndex, destination, length);

        public static void Copy(IntPtr source, float[] destination, int startIndex, int length)
            => System.Runtime.InteropServices.Marshal.Copy(source, destination, startIndex, length);

        public static IntPtr AllocHGlobal(int cb) => System.Runtime.InteropServices.Marshal.AllocHGlobal(cb);

        public static void FreeHGlobal(IntPtr hglobal) => System.Runtime.InteropServices.Marshal.FreeHGlobal(hglobal);

        public static string? PtrToStringUni(IntPtr ptr) => System.Runtime.InteropServices.Marshal.PtrToStringUni(ptr);
    }
}
