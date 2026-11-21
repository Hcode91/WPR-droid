using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using UnicornEngine.Const;
using WPR.Xna.Compat;
using WPR.Xna.Rhi;

namespace WPR.Wp8Native
{
    /// <summary>
    /// Runs a WP7 title's native COM DLL (Windows CE 7 ARM, Thumb-2: Rovio's Amazing Alex and its
    /// Fusion engine) on the WP8 runtime's emulator, and bridges COM between it and the title's own
    /// managed code, which keeps running as shipped. Registered per launch through
    /// <see cref="NativeComBackend"/>; started by <c>ComBridge.RegisterComDll</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Managed to native</b>: a <c>[ComImport]</c> object is a <see cref="Wp7GuestObject"/> proxy.
    /// A call is queued for the guest thread that serves the calling managed thread (the main guest
    /// thread for the game thread, a guest thread of its own - a lane - for any other, such as the
    /// audio thread), made through the object's vtable with Windows CE's soft-float ABI, and waited
    /// for.
    /// </para>
    /// <para>
    /// <b>Native to managed</b>: a managed object handed to native code gets a CCW, a guest object
    /// whose vtable slots are traps. The call is run on the managed thread that is waiting on the guest
    /// (the game thread, so XNA is used on its own thread), while the guest thread parks. A call that
    /// managed code makes back into native code meanwhile (Fusion's <c>Primitive</c> reads its native
    /// <c>IVertexFormat</c> while <c>AllocatePrimitive</c> is still running) runs on that parked guest
    /// thread, as it would have on the phone, where it was the same thread.
    /// </para>
    /// <para>
    /// <b>Memory</b>: native code writes vertices, pixels and audio straight into managed arrays
    /// that Fusion pins (<c>GetVertexPtr</c>, <c>GetMemoryBuffer</c>, <c>IAudioCallback.Fill</c>). The
    /// patcher routes the title's <c>GCHandle</c> pinning to <see cref="PinnedArrays"/>, and each pinned
    /// array handed to native code gets a mirror in guest memory, copied in and out each time control
    /// crosses between the two sides on its thread.
    /// </para>
    /// </remarks>
    public sealed class Wp7ComHost : INativeComHost
    {
        private const int EFail = unchecked((int)0x80004005);
        private const int ENoInterface = unchecked((int)0x80004002);
        private const int EPointer = unchecked((int)0x80004003);
        private const uint ModuleNotFound = 0x8007007E;
        private const uint Unexpected = 0x8000FFFF;
        private const uint NotSupported = 0x80070032;

        /// <summary>
        /// How long a guest thread waiting on managed code (or for work) parks before looking
        /// again. Its wake-up is set by another OS thread, which the scheduler cannot see, so an
        /// untimed wait would read as a deadlock the moment every other guest thread was idle.
        /// </summary>
        private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(4);

        /// <summary>How long either side spins for the other before parking (see <see cref="SpinFor"/>).</summary>
        private static readonly long HandoffSpin = System.Diagnostics.Stopwatch.Frequency / 500; // 2 ms

        /// <summary>
        /// Spins until <paramref name="condition"/> holds or <paramref name="ticks"/> pass. Not
        /// <see cref="SpinWait.SpinUntil(Func{bool}, int)"/>: that sleeps a millisecond at a time once
        /// it has spun a little, which is the very cost this avoids.
        /// </summary>
        private static bool SpinFor(Func<bool> condition, long ticks)
        {
            long until = System.Diagnostics.Stopwatch.GetTimestamp() + ticks;
            int round = 0;
            while (!condition())
            {
                if (System.Diagnostics.Stopwatch.GetTimestamp() > until)
                {
                    return false;
                }

                if (++round % 64 == 0)
                {
                    Thread.Yield();
                }
                else
                {
                    Thread.SpinWait(16);
                }
            }

            return true;
        }

        private static readonly Guid IidUnknown = new("00000000-0000-0000-C000-000000000046");
        private static readonly Guid IidClassFactory = new("00000001-0000-0000-C000-000000000046");

        private readonly string _installFolder;
        private readonly string _sandboxRoot;
        private readonly Action<string>? _log;

        private readonly object _gate = new();
        private Thread? _guestOs;
        private ArmEmulator? _e;
        private readonly ManualResetEventSlim _started = new(false);
        private string? _dll;
        private long _getClassObject;
        private string? _failure;
        private volatile bool _closing;
        private volatile bool _stopped;
        private int _primary = -1;
        private readonly Dictionary<Guid, string> _classes = new();

        // ---- managed -> guest
        private readonly ConcurrentQueue<Request> _main = new();
        private readonly SemaphoreSlim _guestSignal = new(0, int.MaxValue);
        private readonly ConcurrentDictionary<int, Lane> _lanes = new();
        private readonly ConcurrentQueue<Lane> _lanesToStart = new();
        private readonly ConcurrentDictionary<int, Inbox> _inboxes = new();

        [ThreadStatic]
        private static Stack<Callback>? t_servicing;

        // ---- guest side: touched only on the guest's OS thread
        private long _serveEntry;
        private long _queryInterface, _addRef, _release;
        private readonly Dictionary<int, Stack<int>> _owners = new();
        private readonly Dictionary<int, int> _workers = new();
        private readonly Dictionary<long, (CcwObject Object, Type Interface)> _ccws = new();
        private readonly Dictionary<object, CcwObject> _ccwObjects = new(ReferenceEqualityComparer.Instance);
        private readonly Dictionary<Type, long> _vtables = new();
        private readonly Dictionary<(long Pointer, Type Interface), object> _rcws = new();
        private readonly ConcurrentQueue<long> _mirrorsToFree = new();
        private readonly HashSet<string> _noted = new(StringComparer.Ordinal);

        /// <param name="installFolder">The title's install folder, where the DLL is.</param>
        /// <param name="sandboxRoot">Its isolated store on the host: native code's <c>\Applications\Data\{id}\Data\IsolatedStore</c>.</param>
        /// <param name="log">Per-game trace sink.</param>
        public Wp7ComHost(string installFolder, string sandboxRoot, Action<string>? log)
        {
            _installFolder = installFolder;
            _sandboxRoot = sandboxRoot;
            _log = log;
            PinnedArrays.Released += OnMirrorReleased;
        }

        private void Log(string line)
        {
            _log?.Invoke("[wpr-com] " + line);
            Trace.WriteLine("[wpr-com] " + line);
        }

        private void NoteOnce(string key, string line)
        {
            lock (_noted)
            {
                if (!_noted.Add(key))
                {
                    return;
                }
            }

            Log(line);
        }

        // =============================================================================
        // INativeComHost
        // =============================================================================

        public uint RegisterComDll(string dllFileName, Guid clsid)
        {
            string path = Path.Combine(_installFolder, dllFileName.Replace('\\', Path.DirectorySeparatorChar));
            if (!File.Exists(path))
            {
                string? match = Directory.EnumerateFiles(_installFolder)
                    .FirstOrDefault(f => string.Equals(Path.GetFileName(f), Path.GetFileName(dllFileName), StringComparison.OrdinalIgnoreCase));
                if (match is null)
                {
                    Log($"RegisterComDll({dllFileName}): no such file in the package");
                    return ModuleNotFound;
                }

                path = match;
            }

            lock (_gate)
            {
                if (_dll is not null && !string.Equals(_dll, path, StringComparison.OrdinalIgnoreCase))
                {
                    Log($"RegisterComDll({dllFileName}): a second native DLL ({Path.GetFileName(_dll)} is loaded); only one is supported");
                    return NotSupported;
                }

                _classes[clsid] = path;
                if (_dll is null)
                {
                    _dll = path;
                    _guestOs = new Thread(RunGuest, 64 * 1024 * 1024)
                    {
                        Name = "WP7 native (dynarmic)",
                        IsBackground = true,
                    };
                    _guestOs.Start();
                }
            }

            if (!_started.Wait(TimeSpan.FromSeconds(60)))
            {
                Log($"RegisterComDll({dllFileName}): DllMain did not return within a minute");
                return Unexpected;
            }

            if (_failure is not null)
            {
                Log($"RegisterComDll({dllFileName}) failed: {_failure}");
                return _failure.StartsWith("module", StringComparison.Ordinal) ? ModuleNotFound : Unexpected;
            }

            Log($"RegisterComDll({Path.GetFileName(path)}, {clsid}) = S_OK");
            return 0;
        }

        public object CreateInstance(Type comClass)
        {
            Guid clsid = comClass.GUID;
            Type iface = comClass.GetInterfaces().FirstOrDefault(i => i.GetCustomAttribute<CoClassAttribute>()?.CoClass == comClass)
                ?? comClass.GetInterfaces().First(i => i.IsImport && !IsEventInterface(i));
            Guid iid = InterfaceId(iface);

            lock (_gate)
            {
                if (!_classes.ContainsKey(clsid))
                {
                    throw new COMException($"Class {comClass.FullName} ({clsid}) is not registered.", unchecked((int)0x80040154));
                }
            }

            var request = new Request($"CreateInstance({comClass.Name})");
            request.Run = done => CreateOnGuest(request, clsid, iid, iface, done);
            Execute(request);
            object instance = request.Result ?? throw new COMException($"{comClass.FullName} could not be created.", EFail);
            Log($"created {comClass.Name} as {iface.Name}");
            return instance;
        }

        public void Dispose()
        {
            PinnedArrays.Released -= OnMirrorReleased;
            _closing = true;
            _guestSignal.Release(16);
            foreach (Inbox inbox in _inboxes.Values)
            {
                inbox.Wake.Release();
            }

            if (_guestOs is { } os && os != Thread.CurrentThread)
            {
                os.Join(TimeSpan.FromSeconds(3));
            }
        }

        // =============================================================================
        // The guest's OS thread
        // =============================================================================

        private void RunGuest()
        {
            try
            {
                HostStubs.SandboxRoot = _sandboxRoot;
                Directory.CreateDirectory(_sandboxRoot);
                PeImage image = PeImage.Load(_dll!);
                if (!image.IsArm)
                {
                    _failure = $"not an ARM image (machine 0x{image.Machine:X4})";
                    return;
                }

                if (!image.Exports.TryGetValue("DllGetClassObject", out uint getClassRva))
                {
                    _failure = "module exports no DllGetClassObject";
                    return;
                }

                _e = new ArmEmulator(image, _installFolder, collectBlockStats: false) { RecordCallSites = false };
                _getClassObject = image.ImageBase + getClassRva;
                _serveEntry = ArmEmulator.ThumbEntry(_e.RegisterVtableMethod("WP7 COM: serve", Serve));
                _queryInterface = ArmEmulator.ThumbEntry(_e.RegisterVtableMethod("WP7 COM: IUnknown.QueryInterface (managed)", CcwQueryInterface));
                _addRef = ArmEmulator.ThumbEntry(_e.RegisterVtableMethod("WP7 COM: IUnknown.AddRef (managed)", CcwAddRef));
                _release = ArmEmulator.ThumbEntry(_e.RegisterVtableMethod("WP7 COM: IUnknown.Release (managed)", CcwRelease));

                long start;
                if (image.EntryPointRva != 0)
                {
                    _e.CallEmulated("DllMain", image.EntryPoint, [image.ImageBase, 1, 0], onReturn: () =>
                    {
                        long result = _e.ReadRegister(Arm.UC_ARM_REG_R0);
                        Log($"{Path.GetFileName(_dll)}: DllMain(PROCESS_ATTACH) = {result}");
                        if (result == 0)
                        {
                            _failure = "DllMain refused to load";
                        }

                        _started.Set();
                        _e.ContinueAt(_serveEntry);
                    });
                    start = _e.StartWithModuleInitialisers(image.EntryPoint);
                }
                else
                {
                    _started.Set();
                    start = _serveEntry;
                }

                string? fault = _e.Run(start, long.MaxValue / 4);
                Log($"native code stopped: {fault ?? _e.StopReason ?? (_e.HeapExhausted ? "the guest heap is full" : "returned")}");
                if ((fault is not null || _e.HeapExhausted) && !_closing)
                {
                    Log("  " + DescribeFrames());
                    foreach (string line in _e.DescribeThreads())
                    {
                        Log("  " + line);
                    }
                }
            }
            catch (Exception ex)
            {
                _failure ??= ex.Message;
                Log("native code failed: " + ex);
            }
            finally
            {
                _stopped = true;
                _started.Set();
                FailPending();
            }
        }

        private int _throwsReported;

        /// <summary>A failed call usually means native code caught its own exception at the COM boundary: name the throws since the last report.</summary>
        private void ReportNewThrows(string call)
        {
            List<string> history = _e!.Stubs.ThrowHistory;
            for (; _throwsReported < history.Count; _throwsReported++)
            {
                NoteOnce("throw:" + history[_throwsReported], $"{call}: native code threw {history[_throwsReported]}");
            }

            foreach (string line in _e.Stubs.TransferLog.TakeLast(12))
            {
                NoteOnce("transfer:" + line, "  " + line);
            }
        }

        /// <summary>
        /// The faulting thread's call chain, from its frame pointers: the CE compiler keeps r11 as
        /// one (<c>push {…, r11, lr}; add r11, sp, #n</c>), so [r11] is the caller's r11 and
        /// [r11 + 4] the return address.
        /// </summary>
        private string DescribeFrames()
        {
            ArmEmulator e = _e!;
            var frames = new List<string> { $"pc=0x{e.ReadRegister(Arm.UC_ARM_REG_PC):X8} lr=0x{e.ReadRegister(Arm.UC_ARM_REG_LR):X8}" };
            try
            {
                long fp = e.ReadRegister(Arm.UC_ARM_REG_R11) & 0xFFFFFFFF;
                for (int i = 0; i < 24 && fp != 0 && (fp & 3) == 0; i++)
                {
                    long next = e.ReadUInt32(fp);
                    frames.Add($"0x{e.ReadUInt32(fp + 4):X8}");
                    if (next <= fp)
                    {
                        break;
                    }

                    fp = next;
                }
            }
            catch (Exception)
            {
                frames.Add("…");
            }

            return "frames: " + string.Join(" < ", frames);
        }

        /// <summary>Answers every request still waiting, once the guest can no longer run them.</summary>
        private void FailPending()
        {
            void Fail(Request r)
            {
                r.Error ??= new COMException("The native code has stopped.", EFail);
                r.Finish();
            }

            while (_main.TryDequeue(out Request? r)) Fail(r);
            foreach (Lane lane in _lanes.Values)
            {
                while (lane.Queue.TryDequeue(out Request? r)) Fail(r);
            }

            foreach (Inbox inbox in _inboxes.Values)
            {
                inbox.Wake.Release();
            }
        }

        /// <summary>The main guest thread between requests: the next one, or a wait for it.</summary>
        private void Serve()
        {
            ArmEmulator e = _e!;
            FreeReleasedMirrors();
            StartPendingLanes();
            if (_closing)
            {
                foreach (string line in e.DescribeThreads())
                {
                    Log("  at close: " + line);
                }

                e.Stop("the game closed");
                return;
            }

            if (_main.TryDequeue(out Request? request))
            {
                Begin(request, () => e.ContinueAt(_serveEntry));
                return;
            }

            e.ContinueAt(_serveEntry);
            if (e.OtherThreadRunnable())
            {
                e.RunOtherThreads(() => e.ContinueAt(_serveEntry));
                return;
            }

            _guestSignal.Wait(16);
        }

        private void StartPendingLanes()
        {
            while (_lanesToStart.TryDequeue(out Lane? lane))
            {
                Lane captured = lane;
                lane.Entry = ArmEmulator.ThumbEntry(_e!.RegisterVtableMethod($"WP7 COM: lane ({lane.Name})", () => ServeLane(captured)));
                int id = _e.CreateGuestThread($"COM lane ({lane.Name})", lane.Entry, 0);
                Log($"guest thread {id} serves the calls of {lane.Name}");
            }
        }

        private void ServeLane(Lane lane)
        {
            ArmEmulator e = _e!;
            if (_closing)
            {
                e.EndCurrentGuestThread("the game closed");
                return;
            }

            if (lane.Queue.TryDequeue(out Request? request))
            {
                Begin(request, () => e.ContinueAt(lane.Entry));
                return;
            }

            e.ContinueAt(lane.Entry);
            if (e.BlockCurrentThread(() => !lane.Queue.IsEmpty || _closing, onResume: () => e.ContinueAt(lane.Entry), why: $"lane {lane.Name} idle", timeout: Poll))
            {
                return;
            }

            _guestSignal.Wait(16);
        }

        /// <summary>Starts a request on the current guest thread; <paramref name="then"/> runs (in a trap) once it is answered, and must set r12.</summary>
        private void Begin(Request request, Action then)
        {
            int guestThread = _e!.CurrentThreadId;
            PushOwner(guestThread, request.Requester);
            SyncToGuest(request.Requester);
            try
            {
                request.Run!(() =>
                {
                    SyncToHost(request.Requester);
                    PopOwner(guestThread);
                    request.Finish();
                    then();
                });
            }
            catch (Exception ex)
            {
                PopOwner(guestThread);
                request.Error = ex;
                request.Finish();
                then();
            }
        }

        private void PushOwner(int guestThread, int managedThread)
        {
            if (!_owners.TryGetValue(guestThread, out Stack<int>? stack))
            {
                _owners[guestThread] = stack = new Stack<int>();
            }

            stack.Push(managedThread);
        }

        private void PopOwner(int guestThread)
        {
            if (_owners.TryGetValue(guestThread, out Stack<int>? stack) && stack.Count > 0)
            {
                stack.Pop();
            }
        }

        /// <summary>The managed thread that runs managed code for the current guest thread: the one it is answering, or a worker of its own.</summary>
        private int OwnerOfCurrentThread()
        {
            int guestThread = _e!.CurrentThreadId;
            if (_owners.TryGetValue(guestThread, out Stack<int>? stack) && stack.Count > 0)
            {
                return stack.Peek();
            }

            if (_workers.TryGetValue(guestThread, out int worker))
            {
                return worker;
            }

            // A thread the native code made itself: managed code it calls runs on a worker of its own.
            var thread = new Thread(() => Pump(InboxOf(Environment.CurrentManagedThreadId), () => _closing))
            {
                Name = $"WP7 native thread {guestThread}: managed calls",
                IsBackground = true,
            };
            _workers[guestThread] = thread.ManagedThreadId;
            InboxOf(thread.ManagedThreadId);
            thread.Start();
            return thread.ManagedThreadId;
        }

        // =============================================================================
        // Requests: managed code calling native code
        // =============================================================================

        private sealed class Request(string name)
        {
            public string Name { get; } = name;

            /// <summary>Runs on the guest thread, in a trap; calls its argument once answered.</summary>
            public Action<Action>? Run { get; set; }

            public int Requester { get; set; }

            public Inbox? Waiter { get; set; }

            private volatile bool _done;

            public bool Done => _done;

            public object? Result { get; set; }

            public Exception? Error { get; set; }

            public void Finish()
            {
                _done = true;
                Waiter?.Wake.Release();
            }
        }

        private sealed class Lane(int managedThread, string? name)
        {
            public int ManagedThread { get; } = managedThread;

            public string Name { get; } = name ?? $"managed thread {managedThread}";

            public ConcurrentQueue<Request> Queue { get; } = new();

            public long Entry { get; set; }
        }

        /// <summary>A managed thread's queue of native-to-managed calls to run while it waits on the guest.</summary>
        private sealed class Inbox
        {
            public ConcurrentQueue<Callback> Queue { get; } = new();

            public SemaphoreSlim Wake { get; } = new(0, int.MaxValue);
        }

        private Inbox InboxOf(int managedThread) => _inboxes.GetOrAdd(managedThread, _ => new Inbox());

        /// <summary>Queues <paramref name="request"/> for the right guest thread and waits for it, running native-to-managed calls meanwhile.</summary>
        private void Execute(Request request)
        {
            if (_stopped || _e is null)
            {
                throw new COMException($"{request.Name}: the native code is not running.", EFail);
            }

            int me = Environment.CurrentManagedThreadId;
            Interlocked.CompareExchange(ref _primary, me, -1);
            request.Requester = me;
            request.Waiter = InboxOf(me);

            if (t_servicing is { Count: > 0 } servicing)
            {
                // Called back into native code from managed code that native code called: run it on
                // the guest thread that is waiting for that managed code.
                servicing.Peek().Nested.Enqueue(request);
            }
            else if (me == _primary)
            {
                _main.Enqueue(request);
            }
            else
            {
                Lane lane = _lanes.GetOrAdd(me, id =>
                {
                    var created = new Lane(id, Thread.CurrentThread.Name);
                    _lanesToStart.Enqueue(created);
                    return created;
                });
                lane.Queue.Enqueue(request);
            }

            _guestSignal.Release();
            Pump(request.Waiter, () => request.Done);
            if (!request.Done)
            {
                throw new COMException($"{request.Name}: the native code stopped before it returned.", EFail);
            }

            if (request.Error is { } error)
            {
                if (error is COMException)
                {
                    throw error;
                }

                throw new COMException($"{request.Name}: {error.Message}", error);
            }
        }

        /// <summary>Waits until <paramref name="done"/>, running the native-to-managed calls that arrive for this thread.</summary>
        private void Pump(Inbox inbox, Func<bool> done)
        {
            while (!done())
            {
                if (inbox.Queue.TryDequeue(out Callback? callback))
                {
                    Service(callback);
                    continue;
                }

                if (_stopped && !done())
                {
                    return;
                }

                // A call into native code that calls straight back costs two handoffs between
                // this thread and the guest's; parking for each would make a frame's hundreds of
                // render-state calls cost milliseconds. Spin briefly first.
                if (SpinFor(() => done() || !inbox.Queue.IsEmpty || _stopped, HandoffSpin))
                {
                    continue;
                }

                inbox.Wake.Wait(50);
            }
        }

        private void Service(Callback callback)
        {
            t_servicing ??= new Stack<Callback>();
            t_servicing.Push(callback);
            try
            {
                callback.Result = callback.Invoke();
            }
            catch (TargetInvocationException ex)
            {
                callback.Error = ex.InnerException ?? ex;
            }
            catch (Exception ex)
            {
                callback.Error = ex;
            }
            finally
            {
                t_servicing.Pop();
                callback.Finish();
                _guestSignal.Release();
            }
        }

        private void CreateOnGuest(Request request, Guid clsid, Guid iid, Type iface, Action done)
        {
            ArmEmulator e = _e!;
            long scratch = e.AllocateHeap(64);
            e.WriteMemory(scratch, clsid.ToByteArray());
            e.WriteMemory(scratch + 16, IidClassFactory.ToByteArray());
            e.WriteMemory(scratch + 32, iid.ToByteArray());
            e.WriteUInt32(scratch + 48, 0);
            e.WriteUInt32(scratch + 52, 0);

            void Finish(string? error)
            {
                if (error is not null)
                {
                    request.Error = new COMException(error, EFail);
                }

                e.FreeHeap(scratch);
                done();
            }

            e.CallEmulated("DllGetClassObject", _getClassObject, [scratch, scratch + 16, scratch + 48], onReturn: () =>
            {
                uint hr = (uint)e.ReadRegister(Arm.UC_ARM_REG_R0);
                long factory = e.ReadUInt32(scratch + 48);
                if ((int)hr < 0 || factory == 0)
                {
                    Finish($"DllGetClassObject({clsid}) = 0x{hr:X8}");
                    return;
                }

                long createInstance = e.ReadUInt32(e.ReadUInt32(factory) + 12);
                e.CallEmulated("IClassFactory.CreateInstance", createInstance, [factory, 0, scratch + 32, scratch + 52], onReturn: () =>
                {
                    uint hr2 = (uint)e.ReadRegister(Arm.UC_ARM_REG_R0);
                    long instance = e.ReadUInt32(scratch + 52);
                    long release = e.ReadUInt32(e.ReadUInt32(factory) + 8);
                    e.CallEmulated("IClassFactory.Release", release, [factory], onReturn: () =>
                    {
                        if ((int)hr2 < 0 || instance == 0)
                        {
                            Finish($"IClassFactory.CreateInstance({iid}) = 0x{hr2:X8}");
                            return;
                        }

                        request.Result = WrapGuest(instance, iface);
                        Finish(null);
                    });
                });
            });
        }

        /// <summary>A call on a native object, from <see cref="Wp7GuestObject"/>.</summary>
        internal object? InvokeFromManaged(Wp7GuestObject proxy, MethodInfo method, object?[] args)
        {
            Wp7ComMethod m = Wp7ComMethod.Of(method);
            if (m.IsEventAccessor)
            {
                NoteOnce("event:" + m.Name, $"{m.Name}: connection-point events are not raised");
                return null;
            }

            var request = new Request(m.Name);
            request.Run = done => CallGuestMethod(request, proxy.Pointer, m, args, done);
            Execute(request);
            return request.Result;
        }

        /// <summary>Calls slot <see cref="Wp7ComMethod.Slot"/> of <paramref name="target"/> with managed arguments (on the guest thread).</summary>
        private void CallGuestMethod(Request request, long target, Wp7ComMethod m, object?[] args, Action done)
        {
            ArmEmulator e = _e!;
            var temps = new List<long>();
            var after = new List<Action>();
            var words = new List<long> { target };

            for (int i = 0; i < m.Parameters.Length; i++)
            {
                AppendArgument(m, i, args, words, temps, after);
            }

            long retvalSlot = 0;
            if (m.Retval is { } retval)
            {
                retvalSlot = e.AllocateHeap(Math.Max(8, retval.Size));
                e.WriteMemory(retvalSlot, new byte[Math.Max(8, retval.Size)]);
                temps.Add(retvalSlot);
                words.Add(retvalSlot);
            }

            long function = e.ReadUInt32(e.ReadUInt32(target) + (m.Slot * 4));
            e.CallEmulated(m.Name, function, words.ToArray(), onReturn: () =>
            {
                uint hr = (uint)e.ReadRegister(Arm.UC_ARM_REG_R0);
                try
                {
                    foreach (Action a in after)
                    {
                        a();
                    }

                    if (m.PreserveSig)
                    {
                        request.Result = m.Method.ReturnType == typeof(void) ? null : FromBits(hr, m.Method.ReturnType, 4);
                    }
                    else if ((int)hr < 0)
                    {
                        request.Error = new COMException($"{m.Name} failed (0x{hr:X8}).", (int)hr);
                        ReportNewThrows(m.Name);
                    }
                    else if (m.Retval is { } rv)
                    {
                        request.Result = ReadValue(retvalSlot, rv);
                    }
                }
                catch (Exception ex)
                {
                    request.Error = ex;
                }

                foreach (long temp in temps)
                {
                    e.FreeHeap(temp);
                }

                done();
            });
        }

        /// <summary>One managed argument as CE argument words (and any memory it needs).</summary>
        private void AppendArgument(Wp7ComMethod m, int index, object?[] args, List<long> words, List<long> temps, List<Action> after)
        {
            ArmEmulator e = _e!;
            Wp7ComParameter p = m.Parameters[index];
            object? value = args[index];

            if (p.ByRef)
            {
                int size = Math.Max(4, p.Size);
                long slot = e.AllocateHeap(size);
                temps.Add(slot);
                e.WriteMemory(slot, new byte[size]);
                if (!p.OutOnly && value is not null)
                {
                    WriteValue(slot, p, value, addRef: false);
                }

                words.Add(slot);
                after.Add(() => args[index] = ReadValue(slot, p));
                return;
            }

            switch (p.Kind)
            {
                case Wp7ComKind.Integer:
                    words.Add((long)(uint)ToBits(value, p));
                    break;
                case Wp7ComKind.Float:
                    words.Add(BitConverter.SingleToUInt32Bits(Convert.ToSingle(value)));
                    break;
                case Wp7ComKind.Double:
                case Wp7ComKind.Integer64:
                {
                    ulong bits = p.Kind == Wp7ComKind.Double ? BitConverter.DoubleToUInt64Bits(Convert.ToDouble(value)) : ToBits(value, p);
                    words.Add((long)(bits & 0xFFFFFFFF));
                    words.Add((long)(bits >> 32));
                    break;
                }

                case Wp7ComKind.String:
                    words.Add(value is string text ? NewGuestString(text, temps) : 0);
                    break;
                case Wp7ComKind.Interface:
                    words.Add(ToGuestInterface(value, p.Type, addRef: false));
                    break;
                case Wp7ComKind.Pointer:
                {
                    IntPtr host = value is IntPtr ip ? ip : value is UIntPtr up ? (IntPtr)(long)(ulong)up : IntPtr.Zero;
                    words.Add(HostPointerToGuest(host, SizeHint(m, index, args), temps, after));
                    break;
                }

                case Wp7ComKind.Struct:
                {
                    byte[] bytes = StructBytes(value!, p.Size);
                    for (int i = 0; i < p.Words; i++)
                    {
                        words.Add(BitConverter.ToUInt32(Pad(bytes, p.Words * 4), i * 4));
                    }

                    break;
                }
            }
        }

        /// <summary>The size of the buffer a pointer argument points at: the integer argument after it, the usual (pointer, size) pair.</summary>
        private static int SizeHint(Wp7ComMethod m, int index, object?[] args)
        {
            if (index + 1 < m.Parameters.Length && m.Parameters[index + 1].Kind == Wp7ComKind.Integer && args[index + 1] is { } size)
            {
                try
                {
                    return Math.Max(0, Convert.ToInt32(size));
                }
                catch (Exception)
                {
                    return 0;
                }
            }

            return 0;
        }

        private long NewGuestString(string text, List<long> temps)
        {
            byte[] bytes = new byte[(text.Length + 1) * 2];
            System.Text.Encoding.Unicode.GetBytes(text, 0, text.Length, bytes, 0);
            long pointer = _e!.AllocateHeap(bytes.Length);
            _e.WriteMemory(pointer, bytes);
            temps.Add(pointer);
            return pointer;
        }

        // =============================================================================
        // Callbacks: native code calling managed code
        // =============================================================================

        private sealed class Callback(Func<object?> invoke)
        {
            public Func<object?> Invoke { get; } = invoke;

            public object? Result { get; set; }

            public Exception? Error { get; set; }

            private volatile bool _done;

            public bool Done => _done;

            /// <summary>Calls managed code makes back into native code while this one runs.</summary>
            public ConcurrentQueue<Request> Nested { get; } = new();

            public void Finish() => _done = true;
        }

        private sealed class CcwObject(object target)
        {
            public object Target { get; } = target;

            public int References { get; set; }

            public Dictionary<Type, long> Pointers { get; } = new();
        }

        /// <summary>The guest pointer for <paramref name="value"/> as interface <paramref name="iface"/>: a native object's own pointer, or a CCW for a managed one.</summary>
        private long ToGuestInterface(object? value, Type iface, bool addRef)
        {
            switch (value)
            {
                case null:
                    return 0;
                case Wp7GuestObject guest:
                    return guest.Pointer;
            }

            if (iface == typeof(object) || !iface.IsInterface || !iface.IsInstanceOfType(value))
            {
                iface = value.GetType().GetInterfaces().FirstOrDefault(i => i.IsImport && !IsEventInterface(i))
                    ?? throw new COMException($"{value.GetType().FullName} implements no COM interface.", ENoInterface);
            }

            long pointer = Ccw(value, iface);
            if (addRef)
            {
                _ccwObjects[value].References++;
            }

            return pointer;
        }

        private long Ccw(object value, Type iface)
        {
            ArmEmulator e = _e!;
            if (!_ccwObjects.TryGetValue(value, out CcwObject? ccw))
            {
                _ccwObjects[value] = ccw = new CcwObject(value);
            }

            if (!ccw.Pointers.TryGetValue(iface, out long pointer))
            {
                pointer = e.AllocateHeap(8);
                e.WriteUInt32(pointer, (uint)Vtable(iface));
                e.WriteUInt32(pointer + 4, 0);
                ccw.Pointers[iface] = pointer;
                _ccws[pointer] = (ccw, iface);
            }

            return pointer;
        }

        private long Vtable(Type iface)
        {
            if (_vtables.TryGetValue(iface, out long vtable))
            {
                return vtable;
            }

            ArmEmulator e = _e!;
            Wp7ComMethod[] methods = Wp7ComMethod.For(iface).Where(m => !m.IsEventAccessor).ToArray();
            int slots = 3 + (methods.Length == 0 ? 0 : methods.Max(m => m.Slot - 2));
            vtable = e.AllocateHeap(slots * 4);
            e.WriteUInt32(vtable, (uint)_queryInterface);
            e.WriteUInt32(vtable + 4, (uint)_addRef);
            e.WriteUInt32(vtable + 8, (uint)_release);
            foreach (Wp7ComMethod m in methods)
            {
                Wp7ComMethod captured = m;
                long trap = ArmEmulator.ThumbEntry(e.RegisterVtableMethod($"{iface.Name}.{m.Method.Name} (managed)", () => CcwCall(captured)));
                e.WriteUInt32(vtable + (m.Slot * 4), (uint)trap);
            }

            _vtables[iface] = vtable;
            return vtable;
        }

        private void CcwQueryInterface()
        {
            ArmEmulator e = _e!;
            long self = e.ReadRegister(Arm.UC_ARM_REG_R0);
            long riid = e.ReadRegister(Arm.UC_ARM_REG_R1);
            long ppv = e.ReadRegister(Arm.UC_ARM_REG_R2);
            if (ppv == 0)
            {
                e.WriteRegister(Arm.UC_ARM_REG_R0, unchecked((uint)EPointer));
                return;
            }

            e.WriteUInt32(ppv, 0);
            if (!_ccws.TryGetValue(self, out var entry) || riid == 0)
            {
                e.WriteRegister(Arm.UC_ARM_REG_R0, unchecked((uint)ENoInterface));
                return;
            }

            Guid iid = new(e.ReadMemory(riid, 16));
            Type? found = iid == IidUnknown
                ? entry.Object.Pointers.Keys.First()
                : InterfaceId(entry.Interface) == iid
                    ? entry.Interface
                    : entry.Object.Target.GetType().GetInterfaces().FirstOrDefault(i => i.IsImport && !IsEventInterface(i) && InterfaceId(i) == iid);
            if (found is null)
            {
                NoteOnce($"qi:{entry.Object.Target.GetType().Name}:{iid}", $"QueryInterface({iid}) on managed {entry.Object.Target.GetType().Name}: E_NOINTERFACE");
                e.WriteRegister(Arm.UC_ARM_REG_R0, unchecked((uint)ENoInterface));
                return;
            }

            e.WriteUInt32(ppv, (uint)Ccw(entry.Object.Target, found));
            entry.Object.References++;
            e.WriteRegister(Arm.UC_ARM_REG_R0, 0);
        }

        private void CcwAddRef()
        {
            long self = _e!.ReadRegister(Arm.UC_ARM_REG_R0);
            int count = _ccws.TryGetValue(self, out var entry) ? ++entry.Object.References : 1;
            _e.WriteRegister(Arm.UC_ARM_REG_R0, (uint)count);
        }

        private void CcwRelease()
        {
            ArmEmulator e = _e!;
            long self = e.ReadRegister(Arm.UC_ARM_REG_R0);
            if (!_ccws.TryGetValue(self, out var entry))
            {
                e.WriteRegister(Arm.UC_ARM_REG_R0, 0);
                return;
            }

            CcwObject ccw = entry.Object;
            if (ccw.References > 0 && --ccw.References == 0)
            {
                // The last native reference is gone: native code cannot reach these pointers any more.
                foreach (long pointer in ccw.Pointers.Values)
                {
                    _ccws.Remove(pointer);
                    e.FreeHeap(pointer);
                }

                _ccwObjects.Remove(ccw.Target);
            }

            e.WriteRegister(Arm.UC_ARM_REG_R0, (uint)ccw.References);
        }

        /// <summary>A native call to a managed object's method: runs it on the managed thread that owns this guest thread, and waits.</summary>
        private void CcwCall(Wp7ComMethod m)
        {
            ArmEmulator e = _e!;
            long self = e.ReadRegister(Arm.UC_ARM_REG_R0);
            if (!_ccws.TryGetValue(self, out var entry))
            {
                e.WriteRegister(Arm.UC_ARM_REG_R0, unchecked((uint)EPointer));
                return;
            }

            long returnTo = e.ReturnAddress;
            object?[] args = new object?[m.Parameters.Length];
            var outs = new List<(int Index, long Pointer, Wp7ComParameter Parameter)>();
            var hostBuffers = new List<(IntPtr Host, long Guest, int Size)>();
            int word = 1;

            for (int i = 0; i < m.Parameters.Length; i++)
            {
                Wp7ComParameter p = m.Parameters[i];
                if (p.ByRef)
                {
                    long pointer = Word(word++);
                    args[i] = pointer != 0 && !p.OutOnly ? ReadValue(pointer, p) : Default(p.Type);
                    outs.Add((i, pointer, p));
                    continue;
                }

                switch (p.Kind)
                {
                    case Wp7ComKind.Integer:
                        args[i] = FromBits((ulong)Word(word++), p.Type, p.Size);
                        break;
                    case Wp7ComKind.Float:
                        args[i] = BitConverter.UInt32BitsToSingle((uint)Word(word++));
                        break;
                    case Wp7ComKind.Double:
                    case Wp7ComKind.Integer64:
                    {
                        ulong bits = (ulong)(uint)Word(word) | ((ulong)(uint)Word(word + 1) << 32);
                        word += 2;
                        args[i] = p.Kind == Wp7ComKind.Double ? BitConverter.UInt64BitsToDouble(bits) : FromBits(bits, p.Type, 8);
                        break;
                    }

                    case Wp7ComKind.String:
                    {
                        long pointer = Word(word++);
                        args[i] = pointer == 0 ? null : e.ReadUtf16String(pointer, 1 << 16);
                        break;
                    }

                    case Wp7ComKind.Interface:
                        args[i] = WrapGuest(Word(word++), p.Type);
                        break;
                    case Wp7ComKind.Pointer:
                    {
                        long pointer = Word(word++);
                        int size = 0;
                        if (i + 1 < m.Parameters.Length && m.Parameters[i + 1] is { Kind: Wp7ComKind.Integer } next)
                        {
                            long raw = Word(word);
                            size = next.ByRef ? (raw == 0 ? 0 : (int)e.ReadUInt32(raw)) : (int)raw;
                        }

                        args[i] = GuestPointerToHost(pointer, size, hostBuffers);
                        break;
                    }

                    case Wp7ComKind.Struct:
                    {
                        byte[] bytes = new byte[p.Words * 4];
                        for (int w = 0; w < p.Words; w++)
                        {
                            BitConverter.GetBytes((uint)Word(word++)).CopyTo(bytes, w * 4);
                        }

                        args[i] = BytesToStruct(bytes, p.Type);
                        break;
                    }
                }
            }

            long retvalPointer = m.Retval is not null ? Word(word++) : 0;
            int owner = OwnerOfCurrentThread();
            SyncToHost(owner);

            object target = entry.Object.Target;
            var callback = new Callback(() => m.Method.Invoke(target, args));
            Inbox inbox = InboxOf(owner);
            inbox.Queue.Enqueue(callback);
            inbox.Wake.Release();

            void Finish()
            {
                int hr = 0;
                if (callback.Error is { } error)
                {
                    hr = error is COMException com ? com.HResult : error is ArgumentException ? unchecked((int)0x80070057) : EFail;
                    NoteOnce("fail:" + m.Name + error.GetType().Name, $"{m.Name} threw {error.GetType().Name}: {error.Message} (answered 0x{hr:X8})");
                }
                else
                {
                    try
                    {
                        foreach ((int index, long pointer, Wp7ComParameter p) in outs)
                        {
                            if (pointer != 0)
                            {
                                WriteValue(pointer, p, args[index], addRef: true);
                            }
                        }

                        if (retvalPointer != 0 && m.Retval is { } rv)
                        {
                            WriteValue(retvalPointer, rv, callback.Result, addRef: true);
                        }
                        else if (m.PreserveSig && callback.Result is not null)
                        {
                            hr = (int)ToBits(callback.Result, new Wp7ComParameter(callback.Result.GetType(), Wp7ComKind.Integer, 4, false, false, false));
                        }
                    }
                    catch (Exception ex)
                    {
                        hr = EFail;
                        NoteOnce("out:" + m.Name, $"{m.Name}: its results could not be handed back ({ex.Message})");
                    }
                }

                foreach ((IntPtr host, long guest, int size) in hostBuffers)
                {
                    byte[] bytes = new byte[size];
                    Marshal.Copy(host, bytes, 0, size);
                    e.WriteMemory(guest, bytes);
                    Marshal.FreeHGlobal(host);
                }

                SyncToGuest(owner);
                e.WriteRegister(Arm.UC_ARM_REG_R0, (uint)hr);
                e.ContinueAt(returnTo);
            }

            void Wait()
            {
                if (callback.Done)
                {
                    Finish();
                    return;
                }

                if (callback.Nested.TryDequeue(out Request? nested))
                {
                    Begin(nested, Wait);
                    return;
                }

                bool Ready() => callback.Done || !callback.Nested.IsEmpty || _closing;

                // Nearly every call back is a short one (a render state, a matrix), answered in
                // microseconds: wait for it here before handing the CPU to another guest thread,
                // which would cost a scheduler poll per call.
                if (SpinFor(Ready, HandoffSpin))
                {
                    Wait();
                    return;
                }

                if (e.OtherThreadRunnable() && e.BlockCurrentThread(Ready, onResume: Wait, why: $"managed {m.Name}", timeout: Poll))
                {
                    return;
                }

                while (!Ready())
                {
                    _guestSignal.Wait(16);
                    if (!Ready() && e.OtherThreadRunnable() && e.BlockCurrentThread(Ready, onResume: Wait, why: $"managed {m.Name}", timeout: Poll))
                    {
                        return;
                    }
                }

                if (_closing && !callback.Done)
                {
                    e.WriteRegister(Arm.UC_ARM_REG_R0, unchecked((uint)EFail));
                    e.ContinueAt(returnTo);
                    return;
                }

                Wait();
            }

            Wait();
        }

        /// <summary>Argument word <paramref name="index"/> of the call being trapped: r0-r3, then the caller's stack.</summary>
        private long Word(int index)
        {
            ArmEmulator e = _e!;
            return index < 4
                ? e.ReadRegister(Arm.UC_ARM_REG_R0 + index) & 0xFFFFFFFF
                : e.ReadUInt32(e.ReadRegister(Arm.UC_ARM_REG_SP) + ((index - 4) * 4));
        }

        /// <summary>A guest interface pointer as a managed object: the managed object behind a CCW, or a proxy for a native object.</summary>
        private object? WrapGuest(long pointer, Type iface)
        {
            if (pointer == 0)
            {
                return null;
            }

            if (_ccws.TryGetValue(pointer, out var entry))
            {
                return entry.Object.Target;
            }

            if (!iface.IsInterface)
            {
                NoteOnce("unk:" + iface.Name, $"a native object typed {iface.Name} reached managed code; it has no interface to wrap it as");
                return null;
            }

            if (!_rcws.TryGetValue((pointer, iface), out object? proxy))
            {
                proxy = Wp7GuestObject.Create(this, pointer, iface);
                _rcws[(pointer, iface)] = proxy;
            }

            return proxy;
        }

        // =============================================================================
        // Values
        // =============================================================================

        private object? ReadValue(long pointer, Wp7ComParameter p)
        {
            ArmEmulator e = _e!;
            switch (p.Kind)
            {
                case Wp7ComKind.Integer:
                    return FromBits(e.ReadUInt32(pointer) & (p.Size >= 4 ? 0xFFFFFFFFUL : (1UL << (p.Size * 8)) - 1), p.Type, p.Size);
                case Wp7ComKind.Integer64:
                    return FromBits(BitConverter.ToUInt64(e.ReadMemory(pointer, 8)), p.Type, 8);
                case Wp7ComKind.Float:
                    return BitConverter.UInt32BitsToSingle(e.ReadUInt32(pointer));
                case Wp7ComKind.Double:
                    return BitConverter.ToDouble(e.ReadMemory(pointer, 8));
                case Wp7ComKind.String:
                {
                    long text = e.ReadUInt32(pointer);
                    return text == 0 ? null : e.ReadUtf16String(text, 1 << 16);
                }

                case Wp7ComKind.Interface:
                    return WrapGuest(e.ReadUInt32(pointer), p.Type);
                case Wp7ComKind.Pointer:
                {
                    long guest = e.ReadUInt32(pointer);
                    PinnedArrays.Entry? mirror = guest == 0 ? null : PinnedArrays.FindMirror(guest);
                    return mirror is not null ? mirror.Address + (nint)(guest - mirror.Mirror) : (IntPtr)guest;
                }

                case Wp7ComKind.Struct:
                    return BytesToStruct(e.ReadMemory(pointer, p.Size), p.Type);
            }

            return null;
        }

        private void WriteValue(long pointer, Wp7ComParameter p, object? value, bool addRef)
        {
            ArmEmulator e = _e!;
            switch (p.Kind)
            {
                case Wp7ComKind.Integer:
                case Wp7ComKind.Integer64:
                {
                    byte[] bytes = BitConverter.GetBytes(ToBits(value, p));
                    e.WriteMemory(pointer, bytes.AsSpan(0, p.Size).ToArray());
                    break;
                }

                case Wp7ComKind.Float:
                    e.WriteUInt32(pointer, BitConverter.SingleToUInt32Bits(Convert.ToSingle(value ?? 0f)));
                    break;
                case Wp7ComKind.Double:
                    e.WriteMemory(pointer, BitConverter.GetBytes(Convert.ToDouble(value ?? 0d)));
                    break;
                case Wp7ComKind.String:
                {
                    // The callee allocates a returned string and the caller frees it: on the guest's
                    // heap, which CoTaskMemFree, LocalFree and free all release.
                    if (value is not string text)
                    {
                        e.WriteUInt32(pointer, 0);
                        break;
                    }

                    byte[] bytes = new byte[(text.Length + 1) * 2];
                    System.Text.Encoding.Unicode.GetBytes(text, 0, text.Length, bytes, 0);
                    long copy = e.AllocateHeap(bytes.Length);
                    e.WriteMemory(copy, bytes);
                    e.WriteUInt32(pointer, (uint)copy);
                    break;
                }
                case Wp7ComKind.Interface:
                    e.WriteUInt32(pointer, (uint)ToGuestInterface(value, p.Type, addRef));
                    break;
                case Wp7ComKind.Pointer:
                {
                    IntPtr host = value is IntPtr ip ? ip : IntPtr.Zero;
                    e.WriteUInt32(pointer, (uint)HostPointerToGuest(host, 0, null, null));
                    break;
                }

                case Wp7ComKind.Struct:
                    e.WriteMemory(pointer, StructBytes(value!, p.Size));
                    break;
            }
        }

        private static ulong ToBits(object? value, Wp7ComParameter p) => value switch
        {
            null => 0,
            bool b => b ? 1UL : 0UL,
            char c => c,
            Enum en => unchecked((ulong)Convert.ToInt64(en)),
            ulong u => u,
            uint u => u,
            IConvertible c => unchecked((ulong)c.ToInt64(null)),
            _ => 0,
        };

        private static object? FromBits(ulong bits, Type type, int size)
        {
            Type basic = type.IsEnum ? type.GetEnumUnderlyingType() : type;
            object value = basic switch
            {
                _ when basic == typeof(bool) => (bits & (size >= 4 ? 0xFFFFFFFFUL : 0xFF)) != 0,
                _ when basic == typeof(sbyte) => (sbyte)(byte)bits,
                _ when basic == typeof(byte) => (byte)bits,
                _ when basic == typeof(short) => (short)(ushort)bits,
                _ when basic == typeof(ushort) => (ushort)bits,
                _ when basic == typeof(char) => (char)(ushort)bits,
                _ when basic == typeof(int) => (int)(uint)bits,
                _ when basic == typeof(uint) => (uint)bits,
                _ when basic == typeof(long) => (long)bits,
                _ when basic == typeof(ulong) => bits,
                _ => (int)(uint)bits,
            };
            return type.IsEnum ? Enum.ToObject(type, value) : value;
        }

        private static object? Default(Type type) => type.IsValueType ? Activator.CreateInstance(type) : null;

        private static byte[] StructBytes(object value, int size)
        {
            byte[] bytes = new byte[size];
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
            }
            finally
            {
                handle.Free();
            }

            return bytes;
        }

        private static object BytesToStruct(byte[] bytes, Type type)
        {
            GCHandle handle = GCHandle.Alloc(Pad(bytes, Marshal.SizeOf(type)), GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure(handle.AddrOfPinnedObject(), type)!;
            }
            finally
            {
                handle.Free();
            }
        }

        private static byte[] Pad(byte[] bytes, int size)
        {
            if (bytes.Length >= size)
            {
                return bytes;
            }

            byte[] padded = new byte[size];
            bytes.CopyTo(padded, 0);
            return padded;
        }

        private static bool IsEventInterface(Type type) =>
            type.GetCustomAttributes(false).Any(a => a.GetType().Name == "ComEventInterfaceAttribute");

        /// <summary>An interface's IID: its [Guid], or for a coclass interface without one, its default interface's.</summary>
        private static Guid InterfaceId(Type iface)
        {
            if (iface.GetCustomAttribute<GuidAttribute>() is { } guid)
            {
                return new Guid(guid.Value);
            }

            Type? inherited = iface.GetInterfaces().FirstOrDefault(i => i.IsImport && !IsEventInterface(i));
            return inherited is not null ? InterfaceId(inherited) : iface.GUID;
        }

        // =============================================================================
        // Pointers and pinned arrays
        // =============================================================================

        /// <summary>
        /// A host pointer as native code sees it: inside a pinned array, that array's mirror; otherwise a
        /// copy of <paramref name="size"/> bytes, copied back after the call (when <paramref name="after"/> is given).
        /// </summary>
        private long HostPointerToGuest(IntPtr host, int size, List<long>? temps, List<Action>? after)
        {
            if (host == IntPtr.Zero)
            {
                return 0;
            }

            if (PinnedArrays.Find(host) is { } entry)
            {
                return Mirror(entry) + ((long)host - (long)entry.Address);
            }

            if (size > 0 && temps is not null && after is not null)
            {
                ArmEmulator e = _e!;
                long guest = e.AllocateHeap(size);
                temps.Add(guest);
                byte[] bytes = new byte[size];
                Marshal.Copy(host, bytes, 0, size);
                e.WriteMemory(guest, bytes);
                after.Add(() =>
                {
                    byte[] back = e.ReadMemory(guest, size);
                    Marshal.Copy(back, 0, host, size);
                });
                return guest;
            }

            NoteOnce("rawptr", $"a host pointer 0x{(long)host:X} that is in no pinned array went to native code as is");
            return (long)host & 0xFFFFFFFF;
        }

        /// <summary>A guest pointer as managed code sees it: inside a mirror, the pinned array; otherwise a host copy of <paramref name="size"/> bytes.</summary>
        private IntPtr GuestPointerToHost(long guest, int size, List<(IntPtr Host, long Guest, int Size)> buffers)
        {
            if (guest == 0)
            {
                return IntPtr.Zero;
            }

            if (PinnedArrays.FindMirror(guest) is { } entry)
            {
                return entry.Address + (nint)(guest - entry.Mirror);
            }

            if (size > 0)
            {
                IntPtr host = Marshal.AllocHGlobal(size);
                Marshal.Copy(_e!.ReadMemory(guest, size), 0, host, size);
                buffers.Add((host, guest, size));
                return host;
            }

            NoteOnce("rawguest", $"a guest pointer 0x{guest:X8} of unknown size went to managed code as is");
            return (IntPtr)guest;
        }

        /// <summary>The guest mirror of a pinned array, made (and filled) on first use.</summary>
        private long Mirror(PinnedArrays.Entry entry)
        {
            if (entry.Mirror == 0)
            {
                ArmEmulator e = _e!;
                long size = Math.Max(16, (entry.Length + 15) & ~15L);
                long guest = e.AllocateHeap(size);
                CopyIn(entry, guest);
                entry.Mirror = guest;
            }

            return entry.Mirror;
        }

        private void CopyIn(PinnedArrays.Entry entry, long guest)
        {
            if (entry.Length <= 0)
            {
                return;
            }

            byte[] bytes = new byte[entry.Length];
            Marshal.Copy(entry.Address, bytes, 0, bytes.Length);
            _e!.WriteMemory(guest, bytes);
        }

        /// <summary>Managed changes to <paramref name="owner"/>'s pinned arrays, into their mirrors.</summary>
        private void SyncToGuest(int owner)
        {
            foreach (PinnedArrays.Entry entry in PinnedArrays.MirroredBy(owner))
            {
                CopyIn(entry, entry.Mirror);
            }
        }

        /// <summary>Native changes to <paramref name="owner"/>'s mirrors, into the pinned arrays.</summary>
        private void SyncToHost(int owner)
        {
            foreach (PinnedArrays.Entry entry in PinnedArrays.MirroredBy(owner))
            {
                if (entry.Length > 0)
                {
                    byte[] bytes = _e!.ReadMemory(entry.Mirror, (int)entry.Length);
                    Marshal.Copy(bytes, 0, entry.Address, bytes.Length);
                }
            }
        }

        private void OnMirrorReleased(PinnedArrays.Entry entry) => _mirrorsToFree.Enqueue(entry.Mirror);

        private void FreeReleasedMirrors()
        {
            while (_mirrorsToFree.TryDequeue(out long mirror))
            {
                _e!.FreeHeap(mirror);
            }
        }
    }

    /// <summary>A native COM object as managed code sees it: calls go to <see cref="Wp7ComHost"/>.</summary>
    public class Wp7GuestObject : DispatchProxy
    {
        internal Wp7ComHost? Host { get; private set; }

        /// <summary>The object's interface pointer in guest memory.</summary>
        public long Pointer { get; private set; }

        public Type? Interface { get; private set; }

        internal static object Create(Wp7ComHost host, long pointer, Type iface)
        {
            MethodInfo create = typeof(DispatchProxy).GetMethods()
                .First(m => m.Name == nameof(DispatchProxy.Create) && m.IsGenericMethodDefinition && m.GetGenericArguments().Length == 2)
                .MakeGenericMethod(iface, typeof(Wp7GuestObject));
            var proxy = (Wp7GuestObject)create.Invoke(null, null)!;
            proxy.Host = host;
            proxy.Pointer = pointer;
            proxy.Interface = iface;
            return proxy;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
            => Host!.InvokeFromManaged(this, targetMethod!, args ?? []);
    }
}
