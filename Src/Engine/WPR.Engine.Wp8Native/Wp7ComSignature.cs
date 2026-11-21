using System.Reflection;
using System.Runtime.InteropServices;

namespace WPR.Wp8Native
{
    /// <summary>How one parameter of a COM interface method crosses between managed code and CE ARM code.</summary>
    internal enum Wp7ComKind
    {
        /// <summary>Up to four bytes, passed in one word: ints, enums, bools, chars.</summary>
        Integer,
        /// <summary>Eight bytes in two words: long, ulong.</summary>
        Integer64,
        Float,
        Double,
        /// <summary>An <c>LPWStr</c>: a pointer to UTF-16 text.</summary>
        String,
        /// <summary>An interface pointer (a COM object).</summary>
        Interface,
        /// <summary>A raw pointer: a host address on the managed side, a guest address on the native side.</summary>
        Pointer,
        /// <summary>A blittable struct, passed by value as its words.</summary>
        Struct,
    }

    /// <summary>One parameter (or the [retval]) of a COM interface method.</summary>
    internal sealed record Wp7ComParameter(Type Type, Wp7ComKind Kind, int Size, bool ByRef, bool OutOnly, bool IsRetval)
    {
        /// <summary>Words it takes as a by-value argument (Windows CE packs 64-bit values into the next two words, unaligned).</summary>
        public int Words => ByRef ? 1 : Kind switch
        {
            Wp7ComKind.Integer64 or Wp7ComKind.Double => 2,
            Wp7ComKind.Struct => (Size + 3) / 4,
            _ => 1,
        };

        public bool IsSigned => Type == typeof(sbyte) || Type == typeof(short) || Type == typeof(int)
            || (Type.IsEnum && Type.GetEnumUnderlyingType() is var u && (u == typeof(sbyte) || u == typeof(short) || u == typeof(int)));
    }

    /// <summary>
    /// A method of a <c>[ComImport]</c> interface as Windows CE native code sees it: its vtable slot and
    /// the parameters after <c>this</c>, with the return value moved to a trailing [retval] pointer
    /// (none of WP7's interop assemblies use PreserveSig, so every method returns an HRESULT).
    /// </summary>
    internal sealed class Wp7ComMethod
    {
        private Wp7ComMethod(MethodInfo method, int slot, Wp7ComParameter[] parameters, Wp7ComParameter? retval, bool preserveSig)
        {
            Method = method;
            Slot = slot;
            Parameters = parameters;
            Retval = retval;
            PreserveSig = preserveSig;
        }

        public MethodInfo Method { get; }

        /// <summary>The vtable slot: 3 (after IUnknown) plus the method's place in its interface.</summary>
        public int Slot { get; }

        public Wp7ComParameter[] Parameters { get; }

        /// <summary>The trailing out-pointer the managed return value travels in; null for void (or PreserveSig).</summary>
        public Wp7ComParameter? Retval { get; }

        public bool PreserveSig { get; }

        /// <summary>Event accessors of a source interface (connection points), which have no vtable slot.</summary>
        public bool IsEventAccessor => Slot < 0;

        public string Name => $"{Method.DeclaringType?.Name}.{Method.Name}";

        private static readonly Dictionary<Type, Wp7ComMethod[]> Tables = new();

        /// <summary>The methods of <paramref name="iface"/>, in vtable order (inherited interfaces excluded; each is its own table).</summary>
        public static Wp7ComMethod[] For(Type iface)
        {
            lock (Tables)
            {
                if (Tables.TryGetValue(iface, out Wp7ComMethod[]? table))
                {
                    return table;
                }

                bool events = iface.GetCustomAttributes(false).Any(a => a.GetType().Name == "ComEventInterfaceAttribute");
                MethodInfo[] methods = iface.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
                    .OrderBy(m => m.MetadataToken)
                    .ToArray();
                table = methods.Select((m, i) => Build(m, events ? -1 : 3 + i)).ToArray();
                Tables[iface] = table;
                return table;
            }
        }

        /// <summary>The entry for <paramref name="method"/>, from its declaring interface's table.</summary>
        public static Wp7ComMethod Of(MethodInfo method)
            => For(method.DeclaringType!).First(m => m.Method == method);

        private static Wp7ComMethod Build(MethodInfo method, int slot)
        {
            // [PreserveSig] is a pseudo-attribute: it compiles to the PreserveSig implementation flag.
            bool preserveSig = (method.MethodImplementationFlags & MethodImplAttributes.PreserveSig) != 0;
            Wp7ComParameter[] parameters = method.GetParameters().Select(p => Describe(p.ParameterType, p.GetCustomAttribute<MarshalAsAttribute>(), p.IsOut && !p.IsIn, false)).ToArray();
            Wp7ComParameter? retval = method.ReturnType == typeof(void) || preserveSig
                ? null
                : Describe(method.ReturnType.MakeByRefType(), method.ReturnParameter.GetCustomAttribute<MarshalAsAttribute>(), true, true);
            return new Wp7ComMethod(method, slot, parameters, retval, preserveSig);
        }

        private static Wp7ComParameter Describe(Type type, MarshalAsAttribute? marshal, bool outOnly, bool retval)
        {
            bool byRef = type.IsByRef;
            Type t = byRef ? type.GetElementType()! : type;
            Type basic = t.IsEnum ? t.GetEnumUnderlyingType() : t;

            (Wp7ComKind kind, int size) = basic switch
            {
                _ when basic == typeof(float) => (Wp7ComKind.Float, 4),
                _ when basic == typeof(double) => (Wp7ComKind.Double, 8),
                _ when basic == typeof(long) || basic == typeof(ulong) => (Wp7ComKind.Integer64, 8),
                _ when basic == typeof(sbyte) || basic == typeof(byte) || basic == typeof(bool) => (Wp7ComKind.Integer, basic == typeof(bool) ? 4 : 1),
                _ when basic == typeof(short) || basic == typeof(ushort) || basic == typeof(char) => (Wp7ComKind.Integer, 2),
                _ when basic == typeof(int) || basic == typeof(uint) => (Wp7ComKind.Integer, 4),
                _ when basic == typeof(IntPtr) || basic == typeof(UIntPtr) => (Wp7ComKind.Pointer, 4),
                _ when basic == typeof(string) => (Wp7ComKind.String, 4),
                _ when basic.IsInterface || basic == typeof(object) => (Wp7ComKind.Interface, 4),
                _ when basic.IsValueType => (Wp7ComKind.Struct, Marshal.SizeOf(basic)),
                _ => (Wp7ComKind.Interface, 4),
            };

            // A bool in a COM signature is a 4-byte BOOL unless it says otherwise.
            if (basic == typeof(bool) && marshal?.Value is UnmanagedType.U1 or UnmanagedType.I1)
            {
                size = 1;
            }

            return new Wp7ComParameter(t, kind, size, byRef, outOnly, retval);
        }
    }
}
