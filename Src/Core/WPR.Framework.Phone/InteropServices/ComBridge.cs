using System;
using WPR.Xna.Rhi;

namespace Microsoft.Phone.InteropServices
{
    /// <summary>
    /// Shim for <c>Microsoft.Phone.InteropServices.ComBridge</c> (WP7's
    /// <c>Microsoft.Phone.InteropServices.dll</c>): how a partner studio's WP7 title loaded its own
    /// native ARM DLL and made a COM class of it available to <c>new</c> (Rovio's Amazing Alex).
    /// The patcher points <c>Microsoft.Phone.InteropServices</c> at this assembly.
    /// </summary>
    public static class ComBridge
    {
        /// <summary>HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND), what WP7 answered for a DLL it could not load.</summary>
        private const uint ModuleNotFound = 0x8007007E;

        /// <summary>
        /// Registers <paramref name="clsid"/> as implemented by <paramref name="componentDllName"/>, a
        /// native DLL in the package. Returns an HRESULT: 0 on success.
        /// </summary>
        public static uint RegisterComDll(string componentDllName, Guid clsid)
            => NativeComBackend.Host?.RegisterComDll(componentDllName, clsid) ?? ModuleNotFound;
    }
}
