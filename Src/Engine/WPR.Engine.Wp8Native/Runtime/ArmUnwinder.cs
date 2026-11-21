namespace WPR.Wp8Native
{
    /// <summary>One frame recovered while walking the stack.</summary>
    public sealed record UnwoundFrame(
        long Address,
        uint FunctionRva,
        long FrameBytes,
        bool HasHandler,
        string Encoding)
    {
        /// <summary>RVA of the language-specific handler, when the frame has one.</summary>
        public uint HandlerRva { get; init; }

        /// <summary>
        /// RVA of the handler's own data. For C++ this is the FuncInfo describing the
        /// function's try blocks and catch handlers.
        /// </summary>
        public uint HandlerDataRva { get; init; }

        /// <summary>Stack pointer on entry to this frame, which a catch funclet needs.</summary>
        public long FramePointer { get; init; }

        /// <summary>
        /// The callee-saved registers as they stood in this frame.
        /// </summary>
        /// <remarks>
        /// Unwinding recovers these on the way past, and a catch needs them: the code after
        /// the catch belongs to this frame and expects its own r4-r11 back, not whatever
        /// the last cleanup funclet happened to leave behind.
        /// </remarks>
        public IReadOnlyList<long> Registers { get; init; } = [];

        /// <summary>
        /// Where the image this frame's function lives in is mapped. Every RVA on the frame
        /// (function, handler, handler data, and everything the FuncInfo names) is relative to
        /// it - with package DLLs loaded that is not always the main image.
        /// </summary>
        public long ImageBase { get; init; }

        public override string ToString()
            => FunctionRva == 0
                ? $"0x{Address:X8}  {Encoding}"
                : $"0x{Address:X8}  in function 0x{FunctionRva:X8}  frame {FrameBytes,5} bytes  " +
                  $"{Encoding}{(HasHandler ? "  [has handler]" : string.Empty)}";
    }

    /// <summary>
    /// Windows-on-ARM stack unwinding, driven by the image's own <c>.pdata</c> table.
    /// </summary>
    /// <remarks>
    /// Every non-leaf function in an ARM PE has a RUNTIME_FUNCTION entry describing how to
    /// undo its prologue. Two encodings are in use, and this image needs both: 3,554 of its
    /// 7,671 entries pack the description into the entry itself, and the other 4,117 point
    /// at an <c>.xdata</c> record holding a byte-coded program.
    ///
    /// The unwind codes are not a description of a frame's *shape* - they are a small
    /// instruction set that has to be **executed**, in order, against real machine state.
    /// That distinction matters: <c>mov sp,rX</c> restores the stack pointer from a
    /// register rather than by an offset, which is how a function using a frame pointer
    /// (and therefore possibly dynamic stack allocation) unwinds. No amount of adding up
    /// frame sizes recovers it. So this interprets the codes against a register file that
    /// starts as the live CPU state and is updated as registers are popped - which is also
    /// what makes each successive frame's registers correct.
    ///
    /// Encodings are per the ARM exception handling specification.
    /// </remarks>
    public sealed class ArmUnwinder
    {
        private readonly ArmEmulator _emulator;

        /// <summary>
        /// One image's .pdata, and the code range it covers. A process with package DLLs loaded
        /// (see ModuleLoader.cs) has one per module: each is searched by the address being
        /// unwound, and every RVA a frame carries is relative to the image that frame is in.
        /// </summary>
        private sealed class Table
        {
            public required long ImageBase { get; init; }
            public required long CodeStart { get; init; }
            public required long CodeEnd { get; init; }
            public required uint[] BeginRvas { get; init; }
            public required uint[] UnwindData { get; init; }

            /// <summary>Windows CE's .pdata: absolute begin addresses, and a flags word instead of unwind data (see <see cref="RunWindowsCe"/>).</summary>
            public bool WindowsCe { get; init; }
        }

        private readonly List<Table> _tables = new();

        public ArmUnwinder(PeImage image, ArmEmulator emulator)
        {
            _emulator = emulator;
            AddImage(image, image.ImageBase);
        }

        /// <summary>
        /// Adds a mapped image's .pdata, read from guest memory at <paramref name="imageBase"/>
        /// (where it was mapped, which need not be its preferred base: the table is RVAs).
        /// </summary>
        public void AddImage(PeImage image, long imageBase)
        {
            // The code range is the section holding the entry point - the main image's rule
            // from the start - or, for a DLL with no entry point, its first executable section.
            PeSection? code = image.EntryPointRva != 0
                ? image.Sections.FirstOrDefault(s =>
                    image.EntryPointRva >= s.VirtualAddress &&
                    image.EntryPointRva < s.VirtualAddress + s.MappedSize)
                : null;
            if (code is null || code.Value.MappedSize == 0)
            {
                code = image.Sections.FirstOrDefault(s => s.IsExecutable || s.Name.StartsWith(".text", StringComparison.Ordinal));
            }

            if (code is null || code.Value.MappedSize == 0)
            {
                return;
            }

            int count = (int)(image.ExceptionDirectorySize / 8);
            uint[] begin = new uint[count];
            uint[] unwind = new uint[count];

            bool windowsCe = image.Machine == PeImage.MachineArmThumb;
            long table = imageBase + image.ExceptionDirectoryRva;
            for (int i = 0; i < count; i++)
            {
                begin[i] = _emulator.ReadUInt32(table + (i * 8));
                unwind[i] = _emulator.ReadUInt32(table + (i * 8) + 4);
                if (windowsCe)
                {
                    // An address (relocated with the image, Thumb bit set), not an RVA.
                    begin[i] = (uint)(((long)begin[i] & ~1L) - imageBase);
                }
            }

            long start = imageBase + code.Value.VirtualAddress;
            _tables.Add(new Table
            {
                ImageBase = imageBase,
                CodeStart = start,
                CodeEnd = start + code.Value.MappedSize,
                BeginRvas = begin,
                UnwindData = unwind,
                WindowsCe = windowsCe,
            });
        }

        /// <summary>Forgets an unloaded module's table.</summary>
        public void RemoveImage(long imageBase) => _tables.RemoveAll(t => t.ImageBase == imageBase);

        private Table? TableFor(long address)
        {
            foreach (Table table in _tables)
            {
                if (address >= table.CodeStart && address < table.CodeEnd)
                {
                    return table;
                }
            }

            return null;
        }

        /// <summary>RUNTIME_FUNCTION entries across every image.</summary>
        public int FunctionCount => _tables.Sum(t => t.BeginRvas.Length);

        /// <summary>
        /// The start address of the function containing <paramref name="address"/>, or zero
        /// if no image's .pdata table covers it.
        /// </summary>
        /// <remarks>
        /// The table has no end addresses, so a hit past the last function - or in a range
        /// .pdata simply does not describe, which includes every leaf function too small to
        /// need unwind data - is indistinguishable from a hit inside one. Anything outside a
        /// code section is rejected outright; beyond that this is the same answer the real
        /// unwinder would give, with the same limitation.
        /// </remarks>
        public long FunctionStart(long address)
        {
            if (TableFor(address) is not { } table)
            {
                return 0;
            }

            int index = FindIndex(table, address);
            return index < 0 ? 0 : table.ImageBase + table.BeginRvas[index];
        }

        public int PackedCount => _tables.Sum(t => t.UnwindData.Count(u => (u & 3) != 0));

        public int XdataCount => _tables.Sum(t => t.UnwindData.Count(u => (u & 3) == 0));

        /// <summary>The machine state an unwind operates on, one frame at a time.</summary>
        private sealed class UnwindState
        {
            public long Sp;
            public long Lr;
            public readonly long[] Registers = new long[16];
            public readonly bool[] Known = new bool[16];

            public long Pop(ArmEmulator emulator, int register)
            {
                long value = emulator.ReadUInt32(Sp);
                Sp += 4;

                if (register is >= 0 and < 16)
                {
                    Registers[register] = value;
                    Known[register] = true;
                }

                return value;
            }
        }

        /// <summary>
        /// Finds the RUNTIME_FUNCTION covering an address. The table is sorted, so this is
        /// the same binary search the real unwinder does.
        /// </summary>
        private static int FindIndex(Table table, long address)
        {
            uint rva = (uint)(address - table.ImageBase);
            uint[] beginRvas = table.BeginRvas;
            int low = 0;
            int high = beginRvas.Length - 1;
            int found = -1;

            while (low <= high)
            {
                int middle = (low + high) / 2;
                if (beginRvas[middle] <= rva)
                {
                    found = middle;
                    low = middle + 1;
                }
                else
                {
                    high = middle - 1;
                }
            }

            return found;
        }

        /// <summary>
        /// Walks the stack from a throw point outwards, recovering one frame at a time.
        /// </summary>
        public List<UnwoundFrame> Walk(long pc, IReadOnlyList<long> liveRegisters, int maxFrames = 24)
        {
            UnwindState state = new();
            for (int i = 0; i < 16 && i < liveRegisters.Count; i++)
            {
                state.Registers[i] = liveRegisters[i];
                state.Known[i] = true;
            }

            state.Sp = state.Registers[13];
            state.Lr = state.Registers[14];

            List<UnwoundFrame> frames = new();
            long currentPc = pc;

            for (int depth = 0; depth < maxFrames; depth++)
            {
                Table? table = TableFor(currentPc);
                int index = table is null ? -1 : FindIndex(table, currentPc);
                if (table is null || index < 0)
                {
                    frames.Add(new UnwoundFrame(currentPc, 0, 0, false, "walk stopped: no .pdata entry"));
                    break;
                }

                uint functionRva = table.BeginRvas[index];
                uint unwind = table.UnwindData[index];
                long entrySp = state.Sp;

                if (table.WindowsCe)
                {
                    long[] here = (long[])state.Registers.Clone();
                    RunWindowsCe(table, index, currentPc, state, out bool ceHandler, out long funcInfo, out long establisher);
                    frames.Add(new UnwoundFrame(currentPc, (uint)(table.ImageBase + functionRva), state.Sp - establisher, ceHandler, "ce")
                    {
                        HandlerRva = ceHandler ? _emulator.ReadUInt32(table.ImageBase + functionRva - 8) : 0,
                        HandlerDataRva = (uint)funcInfo,
                        FramePointer = establisher,
                        Registers = here,
                        ImageBase = table.ImageBase,
                    });

                    long returnTo = state.Lr & ~1L;
                    if (TableFor(returnTo) is not { } caller || FindIndex(caller, returnTo) < 0 || returnTo == (currentPc & ~1L))
                    {
                        frames.Add(new UnwoundFrame(returnTo, 0, 0, false, "walk stopped: return address is not in executable code"));
                        break;
                    }

                    currentPc = returnTo;
                    continue;
                }

                // Snapshot before unwinding: this is the register state *inside* this frame.
                long[] registersHere = (long[])state.Registers.Clone();

                bool hasHandler = false;
                uint handlerRva = 0;
                uint handlerDataRva = 0;
                string failure;
                bool ok = (unwind & 3) != 0
                    ? RunPacked(unwind, state, out failure)
                    : RunXdata(table.ImageBase + unwind, state, out hasHandler, out handlerRva, out handlerDataRva, out failure);

                string encoding = (unwind & 3) != 0 ? "packed" : "xdata";
                if (!ok)
                {
                    frames.Add(new UnwoundFrame(currentPc, functionRva, 0, hasHandler, $"{encoding} ({failure})")
                    {
                        ImageBase = table.ImageBase,
                    });
                    break;
                }

                frames.Add(new UnwoundFrame(currentPc, functionRva, state.Sp - entrySp, hasHandler, encoding)
                {
                    HandlerRva = handlerRva,
                    HandlerDataRva = handlerDataRva,
                    FramePointer = entrySp,
                    Registers = registersHere,
                    ImageBase = table.ImageBase,
                });

                // The caller may be in another module: a callback from a package DLL into the
                // game, or the game calling a DLL export, unwinds straight across.
                long target = state.Lr & ~1L;
                if (TableFor(target) is not { } next || FindIndex(next, target) < 0)
                {
                    frames.Add(new UnwoundFrame(
                        target, 0, 0, false, "walk stopped: return address is not in executable code"));
                    break;
                }

                currentPc = target;
            }

            return frames;
        }

        /// <summary>
        /// Windows CE's ARM unwinding (WP7 native code): a .pdata entry is the function's address
        /// and a word of flags - prologue length in halfwords (bits 0-7), function length in
        /// halfwords for Thumb (bits 8-29), a 32-bit-code flag (30) and an exception flag (31),
        /// which means the eight bytes before the function hold its language handler and that
        /// handler's data (the FuncInfo). There is no unwind program: the unwinder reads the
        /// prologue itself. CE's Thumb-2 compiler writes a fixed shape -
        /// <c>[push {r0-r3}] push {…, r11, lr}; add r11, sp, #n; [vpush]; sub sp, #m; mov r7, sp</c> -
        /// so this decodes the pushes and stack adjustments, finds the caller's stack pointer
        /// through r11 where the prologue set it, and pops the saved registers.
        /// </summary>
        /// <remarks>
        /// <paramref name="establisher"/> is the stack pointer at the end of the prologue: what
        /// the function's r7 holds, the frame its funclets are handed (in r3) and the stack a
        /// catch continues on. Only the core registers are restored; VFP saves are skipped over.
        /// </remarks>
        private void RunWindowsCe(Table table, int index, long pc, UnwindState state, out bool hasHandler, out long funcInfo, out long establisher)
        {
            long start = table.ImageBase + table.BeginRvas[index];
            uint flags = table.UnwindData[index];
            int prologBytes = (int)(flags & 0xFF) * 2;
            long functionBytes = ((flags >> 8) & 0x3FFFFF) * (((flags >> 30) & 1) != 0 ? 4 : 2);
            hasHandler = (flags >> 31) != 0;
            funcInfo = hasHandler ? _emulator.ReadUInt32(start - 4) : 0;

            if ((pc & ~1L) >= start + functionBytes)
            {
                // Past the function .pdata describes: a leaf with no entry of its own, whose
                // return address is still in lr.
                hasHandler = false;
                funcInfo = 0;
                establisher = state.Sp;
                return;
            }

            var saved = new List<(int Register, int Offset)>(); // offset below the entry sp
            int below = 0;          // bytes pushed or allocated so far
            int fpBelow = -1;       // r11 = entry sp - fpBelow, once set
            int frameBelow = -1;    // r7 = entry sp - frameBelow (mov r7, sp)
            long address = start;
            long end = Math.Min(start + prologBytes, pc & ~1L);
            while (address < end)
            {
                ushort first = (ushort)_emulator.ReadUInt32(address);
                bool wide = (first & 0xF800) is 0xE800 or 0xF000 or 0xF800;
                ushort second = wide ? (ushort)(_emulator.ReadUInt32(address) >> 16) : (ushort)0;

                if (!wide && (first & 0xFE00) == 0xB400)
                {
                    int list = (first & 0xFF) | ((first & 0x100) != 0 ? 1 << 14 : 0);
                    PushList(list);
                }
                else if (wide && first == 0xE92D)
                {
                    PushList(second);
                }
                else if (wide && first == 0xF84D && (second & 0x0FFF) == 0x0D04)
                {
                    below += 4;
                    saved.Add((second >> 12, below));
                }
                else if (!wide && (first & 0xFF80) == 0xB080)
                {
                    below += (first & 0x7F) * 4;
                }
                else if (wide && (first & 0xFBEF) == 0xF1AD && (second & 0x8F00) == 0x0D00)
                {
                    below += (int)ThumbExpandImmediate(first, second);
                }
                else if (wide && (first & 0xFBFF) == 0xF2AD && (second & 0x8F00) == 0x0D00)
                {
                    below += Immediate12(first, second);
                }
                else if (wide && first == 0xED2D && (second & 0x0E00) == 0x0A00)
                {
                    below += (second & 0xFF) * 4;
                }
                else if (!wide && first == 0x466F)
                {
                    // mov r7, sp: the frame base the body (and its funclets) address locals from.
                    // A prologue often goes on to reserve outgoing-argument space below it.
                    frameBelow = below;
                }
                else if (wide && (first & 0xFBFF) == 0xF20D && (second & 0x8F00) == 0x0B00)
                {
                    fpBelow = below - Immediate12(first, second);
                }
                else if (wide && (first & 0xFBEF) == 0xF10D && (second & 0x8F00) == 0x0B00)
                {
                    fpBelow = below - (int)ThumbExpandImmediate(first, second);
                }

                address += wide ? 4 : 2;
            }

            long entry = fpBelow >= 0 && state.Known[11]
                ? state.Registers[11] + fpBelow
                : state.Sp + below;
            establisher = entry - (frameBelow >= 0 ? frameBelow : below);

            long lr = state.Lr;
            foreach ((int register, int offset) in saved)
            {
                long value = _emulator.ReadUInt32(entry - offset);
                if (register == 14)
                {
                    lr = value;
                }
                else if (register is >= 4 and <= 12)
                {
                    state.Registers[register] = value;
                    state.Known[register] = true;
                }
            }

            state.Sp = entry;
            state.Lr = lr;
            state.Registers[13] = entry;
            state.Registers[14] = lr;

            void PushList(int list)
            {
                int count = System.Numerics.BitOperations.PopCount((uint)list);
                int slot = 0;
                for (int register = 0; register < 16; register++)
                {
                    if ((list & (1 << register)) != 0)
                    {
                        // The lowest register goes lowest: slot 0 sits furthest below the entry.
                        saved.Add((register, below + ((count - slot) * 4)));
                        slot++;
                    }
                }

                below += count * 4;
            }
        }

        private static int Immediate12(ushort first, ushort second)
            => ((first >> 10) & 1) << 11 | ((second >> 12) & 7) << 8 | (second & 0xFF);

        private static uint ThumbExpandImmediate(ushort first, ushort second)
        {
            int imm12 = Immediate12(first, second);
            uint imm8 = (uint)(imm12 & 0xFF);
            if ((imm12 >> 10) == 0)
            {
                return ((imm12 >> 8) & 3) switch
                {
                    0 => imm8,
                    1 => (imm8 << 16) | imm8,
                    2 => (imm8 << 24) | (imm8 << 8),
                    _ => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
                };
            }

            uint unrotated = 0x80 | (imm8 & 0x7F);
            int rotation = (imm12 >> 7) & 0x1F;
            return (unrotated >> rotation) | (unrotated << (32 - rotation));
        }

        /// <summary>
        /// The packed encoding: a prologue of the standard shape - optionally home r0-r3,
        /// push the callee-saved registers and lr, save VFP registers, allocate locals.
        /// </summary>
        private bool RunPacked(uint unwind, UnwindState state, out string failure)
        {
            failure = string.Empty;

            bool homing = ((unwind >> 15) & 1) != 0;
            int reg = (int)((unwind >> 16) & 0x7);
            bool savesVfp = ((unwind >> 19) & 1) != 0;
            bool savesLr = ((unwind >> 20) & 1) != 0;
            bool chainsFrame = ((unwind >> 21) & 1) != 0;
            int stackAdjust = (int)((unwind >> 22) & 0x3FF);

            // 0x3F4 and above is not a byte count: the low bits carry a small word count
            // plus prologue/epilogue folding flags. Folded or not, the space sits below the
            // saved registers, so the layout works out the same.
            int localWords = stackAdjust >= 0x3F4 ? (stackAdjust & 0x3) + 1 : stackAdjust;

            state.Sp += localWords * 4L;

            if (savesVfp)
            {
                // R=1 with Reg=7 is "no registers saved", not d8-d15.
                if (reg != 7)
                {
                    state.Sp += (reg + 1) * 8L;
                }
            }
            else
            {
                for (int r = 4; r <= 4 + reg; r++)
                {
                    state.Pop(_emulator, r);
                }
            }

            // C: the function sets up a frame chain, which adds r11 to the push - after the
            // callee-saved registers and before lr. Leaving it out made lr's pop read r11's slot:
            // the "return address" became a stack address, the walk stopped there, and every C++
            // throw through such a frame was reported uncaught (Angry Birds Stella's rethrown
            // HttpRequestException, push {r1-r6, r11, lr} at 0xD9739).
            if (chainsFrame)
            {
                state.Pop(_emulator, 11);
            }

            if (savesLr)
            {
                state.Lr = state.Pop(_emulator, 14);
            }

            if (homing)
            {
                state.Sp += 16;
            }

            return true;
        }

        /// <summary>
        /// The .xdata encoding: a header, then a byte-coded program describing the prologue.
        /// </summary>
        private bool RunXdata(
            long record,
            UnwindState state,
            out bool hasHandler,
            out uint handlerRva,
            out uint handlerDataRva,
            out string failure)
        {
            uint header = _emulator.ReadUInt32(record);
            hasHandler = ((header >> 20) & 1) != 0;              // X
            bool epilogueInHeader = ((header >> 21) & 1) != 0;   // E
            handlerRva = 0;
            handlerDataRva = 0;

            int epilogueScopes = (int)((header >> 23) & 0x1F);
            int codeWords = (int)((header >> 28) & 0xF);

            long cursor = record + 4;
            if ((header >> 23) == 0)
            {
                // Extended header: the counts did not fit in the first word.
                uint extended = _emulator.ReadUInt32(cursor);
                epilogueScopes = (int)(extended & 0xFFFF);
                codeWords = (int)((extended >> 16) & 0xFF);
                cursor += 4;
            }

            // With E set there are no separate epilogue scope words - the field is an index
            // into the codes instead.
            if (!epilogueInHeader)
            {
                cursor += epilogueScopes * 4L;
            }

            long codesAt = cursor;

            // The handler RVA sits immediately after the unwind codes, and its own data
            // after that - for C++ a single RVA naming the FuncInfo.
            if (hasHandler)
            {
                long afterCodes = codesAt + (codeWords * 4L);
                handlerRva = _emulator.ReadUInt32(afterCodes);
                handlerDataRva = _emulator.ReadUInt32(afterCodes + 4);
            }

            return RunUnwindCodes(codesAt, codesAt + (codeWords * 4L), state, out failure);
        }

        /// <summary>
        /// Executes the unwind codes in order. Encodings follow the ARM exception handling
        /// specification; the multi-byte operands are stored most significant byte first.
        /// </summary>
        private bool RunUnwindCodes(long cursor, long end, UnwindState state, out string failure)
        {
            failure = string.Empty;

            while (cursor < end)
            {
                byte code = ReadByte(cursor++);

                switch (code)
                {
                    // 00-7F: add sp,sp,#(Code & 0x7F)*4
                    case <= 0x7F:
                        state.Sp += (code & 0x7F) * 4L;
                        break;

                    // 80-BF: pop {r0-r12, lr}; lr if bit 13, registers from bits 0-12
                    case >= 0x80 and <= 0xBF:
                    {
                        int word = (code << 8) | ReadByte(cursor++);
                        PopRegisterMask(state, word & 0x1FFF, (word & 0x2000) != 0);
                        break;
                    }

                    // C0-CF: mov sp,rX - the stack pointer comes from a register, not an
                    // offset. This is the case a frame-size calculation cannot express.
                    case >= 0xC0 and <= 0xCF:
                    {
                        int register = code & 0x0F;
                        if (!state.Known[register])
                        {
                            failure = $"mov sp,r{register} but r{register} is not recovered yet";
                            return false;
                        }

                        state.Sp = state.Registers[register];
                        break;
                    }

                    // D0-D7: pop {r4-rX, lr}, X = (Code & 3) + 4, lr if Code & 4
                    case >= 0xD0 and <= 0xD7:
                        PopRegisterRange(state, 4, (code & 0x3) + 4, (code & 0x4) != 0);
                        break;

                    // D8-DF: pop {r4-rX, lr}, X = (Code & 3) + 8, lr if Code & 4
                    case >= 0xD8 and <= 0xDF:
                        PopRegisterRange(state, 4, (code & 0x3) + 8, (code & 0x4) != 0);
                        break;

                    // E0-E7: vpop {d8-dX}, X = (Code & 7) + 8
                    case >= 0xE0 and <= 0xE7:
                        state.Sp += ((code & 0x7) + 1) * 8L;
                        break;

                    // E8-EB: addw sp,sp,#(Code & 0x3FF)*4
                    case >= 0xE8 and <= 0xEB:
                    {
                        int word = (code << 8) | ReadByte(cursor++);
                        state.Sp += (word & 0x3FF) * 4L;
                        break;
                    }

                    // EC-ED: pop {r0-r7, lr}; lr if bit 8, registers from bits 0-7
                    case 0xEC:
                    case 0xED:
                    {
                        int word = (code << 8) | ReadByte(cursor++);
                        PopRegisterMask(state, word & 0x00FF, (word & 0x0100) != 0);
                        break;
                    }

                    // EE: Microsoft-specific, with one operand byte.
                    case 0xEE:
                        cursor++;
                        break;

                    // EF: ldr lr,[sp],#(Code & 0xF)*4
                    case 0xEF:
                    {
                        int operand = ReadByte(cursor++);
                        state.Lr = _emulator.ReadUInt32(state.Sp);
                        state.Registers[14] = state.Lr;
                        state.Known[14] = true;
                        state.Sp += (operand & 0x0F) * 4L;
                        break;
                    }

                    // F5: vpop {dS-dE}   F6: the same, 16 registers higher
                    case 0xF5:
                    case 0xF6:
                    {
                        int operand = ReadByte(cursor++);
                        int first = (operand >> 4) & 0xF;
                        int last = operand & 0xF;
                        state.Sp += (last - first + 1) * 8L;
                        break;
                    }

                    // F7 and F9 take a 16-bit operand, F8 and FA a 24-bit one.
                    case 0xF7:
                    case 0xF9:
                        state.Sp += ReadBigEndian(ref cursor, 2) * 4L;
                        break;

                    case 0xF8:
                    case 0xFA:
                        state.Sp += ReadBigEndian(ref cursor, 3) * 4L;
                        break;

                    // FB, FC: nop. FD, FE, FF: end.
                    case 0xFB:
                    case 0xFC:
                        break;

                    case 0xFD:
                    case 0xFE:
                    case 0xFF:
                        return true;

                    default:
                        failure = $"unwind code 0x{code:X2} is reserved";
                        return false;
                }
            }

            // Running out of code words without an end code is still complete: the array is
            // padded rather than terminated.
            return true;
        }

        private void PopRegisterMask(UnwindState state, int mask, bool includeLr)
        {
            for (int register = 0; register <= 12; register++)
            {
                if ((mask & (1 << register)) != 0)
                {
                    state.Pop(_emulator, register);
                }
            }

            if (includeLr)
            {
                state.Lr = state.Pop(_emulator, 14);
            }
        }

        private void PopRegisterRange(UnwindState state, int first, int last, bool includeLr)
        {
            for (int register = first; register <= last; register++)
            {
                state.Pop(_emulator, register);
            }

            if (includeLr)
            {
                state.Lr = state.Pop(_emulator, 14);
            }
        }

        private byte ReadByte(long address) => _emulator.ReadMemory(address, 1)[0];

        private long ReadBigEndian(ref long cursor, int byteCount)
        {
            long value = 0;
            for (int i = 0; i < byteCount; i++)
            {
                value = (value << 8) | ReadByte(cursor++);
            }

            return value;
        }

        /// <summary>The raw unwind record for an address, for checking a decode against the bytes.</summary>
        public string Dump(long address)
        {
            Table? table = TableFor(address);
            int index = table is null ? -1 : FindIndex(table, address);
            if (table is null || index < 0)
            {
                return "no .pdata entry";
            }

            uint unwind = table.UnwindData[index];
            if ((unwind & 3) != 0)
            {
                return $"packed 0x{unwind:X8}";
            }

            long record = table.ImageBase + unwind;
            uint header = _emulator.ReadUInt32(record);
            byte[] following = _emulator.ReadMemory(record + 4, 16);

            return $"xdata @0x{unwind:X8} header=0x{header:X8} " +
                   $"(len={(header & 0x3FFFF) * 2} X={(header >> 20) & 1} E={(header >> 21) & 1} " +
                   $"epilogue={(header >> 23) & 0x1F} codeWords={(header >> 28) & 0xF}) " +
                   $"codes={string.Join(" ", following.Select(b => b.ToString("X2")))}";
        }
    }
}
