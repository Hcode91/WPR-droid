using System;

namespace WPR.Xna.Rhi
{
    /// <summary>
    /// A WP7 title's native code, reached through COM: <c>Microsoft.Phone.InteropServices.ComBridge</c>
    /// registers a native DLL's class, and <c>new C()</c> of a <c>[ComImport]</c> class (rewritten by the
    /// patcher to <see cref="WPR.Xna.Compat.ComInterop.CreateComObject"/>) makes one. WP7 allowed this
    /// only to a few partner studios: Rovio's Amazing Alex runs its whole game (Fusion) this way, as a
    /// Windows CE ARM DLL driven by the XNA game and drawing through managed proxies.
    /// </summary>
    /// <remarks>
    /// Implemented by the WP8 runtime's emulator (<c>WPR.Wp8Native.Wp7ComHost</c>), which runs the
    /// DLL's ARM code. The contract speaks only <see cref="Type"/>, <see cref="Guid"/> and objects, so
    /// it can live here, below the engine, where the framework's own <c>ComBridge</c> reaches it.
    /// </remarks>
    public interface INativeComHost : IDisposable
    {
        /// <summary>
        /// <c>ComBridge.RegisterComDll</c>: makes <paramref name="clsid"/> of the package's
        /// <paramref name="dllFileName"/> available. Returns an HRESULT, 0 on success, as WP7 did.
        /// </summary>
        uint RegisterComDll(string dllFileName, Guid clsid);

        /// <summary>
        /// <c>new <paramref name="comClass"/>()</c>: an instance of a registered class, as an object
        /// implementing the class's COM interfaces.
        /// </summary>
        object CreateInstance(Type comClass);
    }

    /// <summary>The per-launch <see cref="INativeComHost"/>; null when nothing can run native code.</summary>
    public static class NativeComBackend
    {
        private static INativeComHost? _host;
        private static Func<INativeComHost>? _factory;

        /// <summary>
        /// Makes the host on first use, so a launch that never touches native code costs nothing.
        /// Set per launch by the game loop; <see cref="Reset"/> disposes what was made.
        /// </summary>
        public static void SetFactory(Func<INativeComHost>? factory)
        {
            Reset();
            _factory = factory;
        }

        /// <summary>The host, made now if it was not yet; null without a factory.</summary>
        public static INativeComHost? Host
        {
            get
            {
                if (_host is null && _factory is { } factory)
                {
                    _host = factory();
                }

                return _host;
            }
        }

        /// <summary>Disposes the host (stopping the native code) and forgets the factory.</summary>
        public static void Reset()
        {
            INativeComHost? host = _host;
            _host = null;
            _factory = null;
            host?.Dispose();
        }
    }
}
