using UnicornEngine.Const;

namespace WPR.Wp8Native
{
    /// <summary>
    /// The parts of Windows CE's COREDLL that cannot share WP8's handlers (WP7 native code: Amazing
    /// Alex's <c>AmazingAlex-native.dll</c>). COREDLL is the CE kernel, CRT and Win32 in one; most of
    /// its exports behave as their MSVCR110/kernel32 namesakes and reach those handlers by name
    /// (<see cref="CoreDllOrdinals"/>). The ones here differ in their calling convention or layout, so
    /// a COREDLL import looks here first (<see cref="CoreDllPrefix"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Soft-float.</b> CE's ARM ABI passes float and double arguments and results in core registers
    /// (a double in an even/odd pair), even on VFP hardware: the game calls <c>cos</c> with
    /// <c>vmov r0, r1, d0; blx</c>. WP8 is hard-float, so a maths function reads its arguments from
    /// r0-r3 here and runs the WP8 handler with them moved into s/d registers; the WP8 handlers
    /// already write a double result to r0:r1 as well as d0.
    /// </para>
    /// <para>
    /// <b>Runtime helpers</b>, read from Alex's call sites: <c>__rt_udiv/__rt_sdiv</c> take the
    /// divisor in r0 and the dividend in r1, and return the quotient in r0 and the remainder in r1;
    /// the 64-bit <c>__rt_*64by64</c> take the dividend in r0:r1 and the divisor in r2:r3 and return
    /// the quotient (div) or remainder (rem) in r0:r1; <c>__i64tod</c>/<c>__dtoi64</c> convert in r0:r1.
    /// </para>
    /// </remarks>
    public sealed partial class HostStubs
    {
        /// <summary>The prefix of a COREDLL-only handler's key; <see cref="Dispatch"/> tries it first for a COREDLL import.</summary>
        public const string CoreDllPrefix = "coredll!";

        private readonly Dictionary<long, uint[]> _ceJumpVfp = new();

        private void RegisterCoreDll()
        {
            void Ce(string name, Action handler) => _handlers[CoreDllPrefix + name] = handler;

            // C++ exceptions. COREDLL's export is _CxxThrowException under the name mingw's
            // table gives it; it is thrown exactly as on WP8 (the model reads CE's FuncInfo,
            // see CxxExceptionModel.WindowsCe). The frame handler is only ever named in .pdata
            // handler slots, never called: the host does the dispatching.
            Ce("__CxxThrowException", () => (_handlers.TryGetValue("_CxxThrowException", out Action? t) ? t : ThrowCxxException)());
            Ce("__CxxFrameHandler", () => Unreachable("__CxxFrameHandler", 1));

            // CreateThread has _beginthreadex's arguments (security, stack size, start, argument,
            // flags with CREATE_SUSPENDED = 4, thread id out) and its handle works with the same
            // waits, ResumeThread and CloseHandle. The store API WP8 runtime has no CreateThread.
            Ce("CreateThread", () => _handlers["_beginthreadex"]());

            // The compiler's array helpers, which COREDLL exports and the WP8 CRT inlines: an array
            // of objects with a constructor is built by one of these, so without them every element
            // keeps whatever the heap held (Fusion's string formatter read a std::string length out
            // of that and grew its buffer until the heap was gone). __cdecl, this in r0.
            //   __ehvec_ctor(void* array, size_t size, int count, ctor(void*), dtor(void*))
            //   __ehvec_dtor(void* array, size_t size, int count, dtor(void*))
            //   __ehvec_copy_ctor(void* to, void* from, size_t size, int count, copy(void*, void*), dtor(void*))
            Ce("??_L@YAXPAXIHP6AX0@Z1@Z", () =>
            {
                long array = Arg(0), size = Arg(1), count = (int)Arg(2), ctor = Arg(3);
                CallEach("vector constructor", count, i => (ctor, [array + (i * size)]));
            });
            Ce("??_M@YAXPAXIHP6AX0@Z@Z", () =>
            {
                long array = Arg(0), size = Arg(1), count = (int)Arg(2), dtor = Arg(3);
                CallEach("vector destructor", count, i => (dtor, [array + ((count - 1 - i) * size)]));
            });
            Action copyVector = () =>
            {
                long to = Arg(0), from = Arg(1), size = Arg(2), count = (int)Arg(3), copy = Arg(4);
                CallEach("vector copy constructor", count, i => (copy, [to + (i * size), from + (i * size)]));
            };
            Ce("??__C@YAXPAX0IHP6AX00@ZP6AX0@Z@Z", copyVector);
            Ce("??__D@YAXPAX0IHP6AX00@ZP6AX0@Z@Z", copyVector);

            // Soft-float wrappers: move the arguments where the hard-float handler reads them.
            void Doubles(string name, int count)
            {
                if (!_handlers.TryGetValue(name, out Action? hard)) return;
                Ce(name, () =>
                {
                    uint[] words = [(uint)Arg(0), (uint)Arg(1), (uint)Arg(2), (uint)Arg(3)];
                    for (int i = 0; i < count * 2; i++) _emulator.Cpu.VfpWrite(i, words[i]);
                    hard();
                });
            }

            // double f(double, X): the double in r0:r1, the other argument in r2, which the
            // hard-float handler reads from r0.
            void DoubleThenWord(string name)
            {
                if (!_handlers.TryGetValue(name, out Action? hard)) return;
                Ce(name, () =>
                {
                    long other = Arg(2);
                    _emulator.Cpu.VfpWrite(0, (uint)Arg(0));
                    _emulator.Cpu.VfpWrite(1, (uint)Arg(1));
                    _emulator.WriteRegister(Arm.UC_ARM_REG_R0, other);
                    hard();
                });
            }

            foreach (string name in new[] { "sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh", "exp", "log", "log10", "sqrt", "floor", "ceil", "fabs" })
            {
                Doubles(name, 1);
            }

            foreach (string name in new[] { "pow", "atan2", "fmod" })
            {
                Doubles(name, 2);
            }

            foreach (string name in new[] { "ldexp", "frexp", "modf" })
            {
                DoubleThenWord(name);
            }

            // float f(float): the float in r0, the result back in r0.
            foreach (string name in new[] { "floorf", "ceilf", "sqrtf", "sinf", "cosf", "fabsf" })
            {
                if (!_handlers.TryGetValue(name, out Action? hard)) continue;
                Ce(name, () =>
                {
                    _emulator.Cpu.VfpWrite(0, (uint)Arg(0));
                    hard();
                    Return(_emulator.Cpu.VfpRead(0));
                });
            }

            // atof/strtod return a double: the WP8 handlers put it in r0:r1 too, nothing to move.

            Ce("__rt_udiv", () =>
            {
                uint divisor = (uint)Arg(0), dividend = (uint)Arg(1);
                if (divisor == 0) { Return(0); _emulator.WriteRegister(Arm.UC_ARM_REG_R1, 0); return; }
                Return(dividend / divisor);
                _emulator.WriteRegister(Arm.UC_ARM_REG_R1, dividend % divisor);
            });
            Ce("__rt_sdiv", () =>
            {
                int divisor = unchecked((int)(uint)Arg(0)), dividend = unchecked((int)(uint)Arg(1));
                if (divisor == 0) { Return(0); _emulator.WriteRegister(Arm.UC_ARM_REG_R1, 0); return; }
                // int.MinValue / -1 overflows in C# and wraps on the CPU; unchecked keeps the wrap.
                int quotient = divisor == -1 ? unchecked(-dividend) : dividend / divisor;
                int remainder = divisor == -1 ? 0 : dividend % divisor;
                Return(unchecked((uint)quotient));
                _emulator.WriteRegister(Arm.UC_ARM_REG_R1, unchecked((uint)remainder));
            });

            ulong U64(int low) => (uint)Arg(low) | ((ulong)(uint)Arg(low + 1) << 32);
            void Ret64(ulong value) => Return64(unchecked((long)value));
            Ce("__rt_udiv64by64", () => { ulong d = U64(2); Ret64(d == 0 ? 0 : U64(0) / d); });
            Ce("__rt_urem64by64", () => { ulong d = U64(2); Ret64(d == 0 ? 0 : U64(0) % d); });
            Ce("__rt_sdiv64by64", () =>
            {
                long dividend = unchecked((long)U64(0)), divisor = unchecked((long)U64(2));
                Ret64(divisor == 0 ? 0 : divisor == -1 ? unchecked((ulong)-dividend) : unchecked((ulong)(dividend / divisor)));
            });
            Ce("__rt_srem64by64", () =>
            {
                long dividend = unchecked((long)U64(0)), divisor = unchecked((long)U64(2));
                Ret64(divisor is 0 or -1 ? 0 : unchecked((ulong)(dividend % divisor)));
            });
            Ce("__i64tod", () => Ret64(BitConverter.DoubleToUInt64Bits(unchecked((long)U64(0)))));
            Ce("__u64tod", () => Ret64(BitConverter.DoubleToUInt64Bits(U64(0))));
            Ce("__dtoi64", () =>
            {
                double value = BitConverter.UInt64BitsToDouble(U64(0));
                // Out of range or NaN gives the "integer indefinite" value, as the CPU's conversion.
                Ret64(double.IsNaN(value) || value >= 9.2233720368547758e18 || value < -9.2233720368547758e18
                    ? 0x8000000000000000UL
                    : unchecked((ulong)(long)value));
            });
            Ce("__dtou64", () =>
            {
                double value = BitConverter.UInt64BitsToDouble(U64(0));
                Ret64(double.IsNaN(value) || value < 0 || value >= 1.8446744073709552e19 ? 0 : (ulong)value);
            });

            // DWORD __security_gen_cookie2(void): a new /GS cookie. Any value that is not the
            // default works; a fixed one keeps runs repeatable.
            Ce("__security_gen_cookie2", () => Return(0x5A3C9E27));

            // FILE* _getstdfilex(int): CE's stdin/stdout/stderr (0, 1, 2), the same FILEs
            // __iob_func hands out to WP8 images.
            Ce("_getstdfilex", () =>
            {
                int index = (int)Arg(0);
                if (!_handlers.TryGetValue("__iob_func", out Action? iob) || index is < 0 or > 2)
                {
                    Return(0);
                    return;
                }

                iob();
                Return(Arg(0) + (index * 0x20));
            });

            // int setjmp(jmp_buf) / void longjmp(jmp_buf, int). A CE jmp_buf is 11 words, far
            // smaller than WP8's, so only r4-r11, sp and the return address go in it (40 bytes);
            // d8-d15 are kept host-side by buffer address.
            Ce("setjmp", () =>
            {
                long buffer = Arg(0);
                for (int i = 0; i < 8; i++)
                {
                    _emulator.WriteUInt32(buffer + (i * 4), (uint)_emulator.ReadRegister(Arm.UC_ARM_REG_R4 + i));
                }

                _emulator.WriteUInt32(buffer + 32, (uint)_emulator.ReadRegister(Arm.UC_ARM_REG_SP));
                _emulator.WriteUInt32(buffer + 36, (uint)_emulator.ReturnAddress);
                uint[] vfp = new uint[16];
                for (int i = 0; i < 16; i++) vfp[i] = _emulator.Cpu.VfpRead(16 + i);
                lock (_ceJumpVfp) _ceJumpVfp[buffer] = vfp;
                Return(0);
            });
            Ce("longjmp", () =>
            {
                long buffer = Arg(0);
                long value = Arg(1) == 0 ? 1 : Arg(1);
                for (int i = 0; i < 8; i++)
                {
                    _emulator.WriteRegister(Arm.UC_ARM_REG_R4 + i, _emulator.ReadUInt32(buffer + (i * 4)));
                }

                uint[]? vfp;
                lock (_ceJumpVfp) _ceJumpVfp.TryGetValue(buffer, out vfp);
                if (vfp is not null)
                {
                    for (int i = 0; i < 16; i++) _emulator.Cpu.VfpWrite(16 + i, vfp[i]);
                }

                _emulator.WriteRegister(Arm.UC_ARM_REG_SP, _emulator.ReadUInt32(buffer + 32));
                Return(value);
                _emulator.ContinueAt(_emulator.ReadUInt32(buffer + 36));
            });

            // The Interlocked family: functions in COREDLL (WP8 code inlines them). Guest threads
            // are switched only at host calls, so a read-modify-write here is atomic to them.
            int Read(long p) => unchecked((int)_emulator.ReadUInt32(p));
            void Write(long p, int v) => _emulator.WriteUInt32(p, unchecked((uint)v));
            Ce("InterlockedIncrement", () => { long p = Arg(0); int v = unchecked(Read(p) + 1); Write(p, v); Return(unchecked((uint)v)); });
            Ce("InterlockedDecrement", () => { long p = Arg(0); int v = unchecked(Read(p) - 1); Write(p, v); Return(unchecked((uint)v)); });
            Ce("InterlockedExchange", () => { long p = Arg(0); int old = Read(p); Write(p, (int)(uint)Arg(1)); Return(unchecked((uint)old)); });
            Ce("InterlockedExchangeAdd", () => { long p = Arg(0); int old = Read(p); Write(p, unchecked(old + (int)(uint)Arg(1))); Return(unchecked((uint)old)); });
            Ce("InterlockedCompareExchange", () =>
            {
                long p = Arg(0);
                int old = Read(p);
                if (old == (int)(uint)Arg(2)) Write(p, (int)(uint)Arg(1));
                Return(unchecked((uint)old));
            });
            Ce("InterlockedTestExchange", () =>
            {
                // CE's own: (target, oldValue, newValue) - the CompareExchange arguments the other way round.
                long p = Arg(0);
                int old = Read(p);
                if (old == (int)(uint)Arg(1)) Write(p, (int)(uint)Arg(2));
                Return(unchecked((uint)old));
            });

            // BOOL AccelerometerCalibrate(...): nothing to calibrate.
            Ce("AccelerometerCalibrate", () => Return(1));
        }

        /// <summary>
        /// Calls <paramref name="call"/>(0 .. count-1) one after another on the guest from the
        /// import trap the CPU is on, then returns from that import.
        /// </summary>
        private void CallEach(string name, long count, Func<long, (long Function, long[] Arguments)> call)
        {
            long callerReturn = _emulator.ReturnAddress;
            long next = 0;

            void RunNext()
            {
                if (next >= count || count > 1_000_000)
                {
                    _emulator.ContinueAt(callerReturn);
                    return;
                }

                (long function, long[] arguments) = call(next++);
                if (function == 0)
                {
                    _emulator.ContinueAt(callerReturn);
                    return;
                }

                _emulator.CallEmulated(name, function, arguments, recycle: true, onReturn: RunNext);
            }

            RunNext();
        }
    }
}
