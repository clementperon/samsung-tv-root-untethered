// S95F SWU command-0 oracle from inside a signed dotnet host.
//
// Why this exists: the TV's UEP policy refuses to execute or map any uploaded
// native binary, so the armv7 LD_PRELOAD preloads cannot be used (verified live
// 2026-10-26).  Managed IL runs fine because /usr/bin/dotnet is trusted, and
// dlopen of a *verified* file is allowed, so this payload loads Samsung's own
// signed SWUMainApp and calls its SWU trust-zone client through it.
//
// It performs at most: dlopen + construct + open + one init() call per run.  It
// never calls commands 1 or 2, never starts an update, never retries, and never
// prints key material - only Samsung's own accept/reject integers.
//
// usage:
//   dotnet SamsungTvSwuOracle.dll open
//   dotnet SamsungTvSwuOracle.dll init <candidate.bin> <salt.bin>
//   dotnet SamsungTvSwuOracle.dll --library <path.so> open|init …
//
// output:  open_result=<n> init_result=<n>
// exit:    0 accepted, 1 rejected or open failed, 2 usage/environment error
//
// --library lets the same payload run against a local stub during development.

using System;
using System.IO;
using System.Runtime.InteropServices;

internal static class Program
{
    private const string SwuApplication =
        "/usr/apps/org.tizen.tv.swu/bin/SWUMainApp";
    private const string ConstructSymbol =
        "_ZN3SWU8Platform18SWUTrustZoneClientC1Ev";
    private const string OpenSymbol =
        "_ZN3SWU8Platform18SWUTrustZoneClient4openEv";
    private const string InitSymbol =
        "_ZN3SWU8Platform18SWUTrustZoneClient4initEbbNS_6Common2IO22"
        + "AESKeyDerivationMethodENS3_10AESKeySizeENS3_11AESModeTypeERKS"
        + "t6vectorIhSaIhEESB_j";
    private const string DestroySymbol =
        "_ZN3SWU8Platform18SWUTrustZoneClientD1Ev";

    private const int ClientSize = 0x78;
    private const int ExpectedCandidateSize = 416;
    private const int ExpectedSaltSize = 8;
    private const uint MaximumSharedSize = 0x10000;
    private const int InitialisedByteOffset = 0x75;
    private const int BatchHeaderSize = 16;
    private const int MaximumCandidates = 256;

    private static readonly byte[] BatchMagic =
        { 0x53, 0x57, 0x55, 0x4f, 0x52, 0x42, 0x31, 0x00 }; // SWUORB1

    private static readonly byte[] ResultMagic =
        { 0x53, 0x57, 0x55, 0x4f, 0x52, 0x52, 0x31, 0x00 }; // SWUORR1

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void Construct(IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Open(IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void Destroy(IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Init(
        IntPtr client,
        int encrypt,
        int passphraseEncrypted,
        int keyDerivation,
        int keySize,
        int mode,
        IntPtr passphrase,
        IntPtr salt,
        uint chunkSize);

    private static int Main(string[] arguments)
    {
        try
        {
            string library = SwuApplication;
            if (arguments.Length >= 3 && arguments[0] == "--library")
            {
                library = arguments[1];
                arguments = arguments[2..];
            }
            if (arguments.Length == 1 && arguments[0] == "open")
            {
                return RunOpen(library);
            }
            if (arguments.Length == 3 && arguments[0] == "init")
            {
                return RunInit(library, arguments[1], arguments[2]);
            }
            if (arguments.Length == 4 && arguments[0] == "batch")
            {
                return RunBatch(library, arguments[1], arguments[2], arguments[3]);
            }
            Console.Error.WriteLine(
                "usage: SamsungTvSwuOracle.dll [--library <path.so>] open | "
                + "init <candidate.bin> <salt.bin> | "
                + "batch <batch.bin> <salt.bin> <result.bin>");
            return 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("error=" + error.GetType().Name + ": " + error.Message);
            return 2;
        }
    }

    private static int RunOpen(string library)
    {
        IntPtr handle = NativeLibrary.Load(library);
        try
        {
            IntPtr client = AllocateZeroed(ClientSize);
            bool constructed = false;
            try
            {
                Construct construct = LoadDelegate<Construct>(handle, ConstructSymbol);
                Open open = LoadDelegate<Open>(handle, OpenSymbol);
                Destroy destroy = LoadDelegate<Destroy>(handle, DestroySymbol);
                construct(client);
                constructed = true;
                int openResult = open(client);
                Console.WriteLine("open_result=" + openResult);
                return openResult != 0 ? 0 : 1;
            }
            finally
            {
                if (constructed)
                {
                    Destroy destroy = LoadDelegate<Destroy>(handle, DestroySymbol);
                    destroy(client);
                }
                Marshal.FreeHGlobal(client);
            }
        }
        finally
        {
            NativeLibrary.Free(handle);
        }
    }

    private static int RunInit(string library, string candidatePath, string saltPath)
    {
        byte[] candidate = ReadExact(candidatePath, ExpectedCandidateSize, "candidate");
        byte[] salt = ReadExact(saltPath, ExpectedSaltSize, "salt");

        IntPtr handle = NativeLibrary.Load(library);
        try
        {
            IntPtr client = AllocateZeroed(ClientSize);
            bool constructed = false;
            IntPtr candidateBuffer = CopyToUnmanaged(candidate);
            IntPtr saltBuffer = CopyToUnmanaged(salt);
            IntPtr candidateVector = Vector(candidateBuffer, candidate.Length);
            IntPtr saltVector = Vector(saltBuffer, salt.Length);
            try
            {
                Construct construct = LoadDelegate<Construct>(handle, ConstructSymbol);
                Open open = LoadDelegate<Open>(handle, OpenSymbol);
                Init init = LoadDelegate<Init>(handle, InitSymbol);

                construct(client);
                constructed = true;
                int openResult = open(client);
                int initResult = 0;
                if (openResult != 0)
                {
                    // open() guards on the client's initialised byte; the verified
                    // preload sets it so init() reuses the explicit session.
                    Marshal.WriteByte(client, InitialisedByteOffset, 1);
                    initResult = init(
                        client,
                        0, // decrypt
                        1, // encrypted passphrase
                        1, // SHA-256 key derivation
                        2, // AES-256
                        1, // CBC
                        candidateVector,
                        saltVector,
                        MaximumSharedSize);
                }
                // One field per line: the recovery tool parses name=value lines.
                Console.WriteLine("open_result=" + openResult);
                Console.WriteLine("init_result=" + initResult);
                return initResult != 0 ? 0 : 1;
            }
            finally
            {
                if (constructed)
                {
                    Destroy destroy = LoadDelegate<Destroy>(handle, DestroySymbol);
                    destroy(client);
                }
                Marshal.FreeHGlobal(client);
                Marshal.FreeHGlobal(candidateBuffer);
                Marshal.FreeHGlobal(saltBuffer);
                Marshal.FreeHGlobal(candidateVector);
                Marshal.FreeHGlobal(saltVector);
            }
        }
        finally
        {
            NativeLibrary.Free(handle);
        }
    }

    private static int RunBatch(
        string library,
        string batchPath,
        string saltPath,
        string resultPath)
    {
        byte[] batch = File.ReadAllBytes(batchPath);
        byte[] salt = ReadExact(saltPath, ExpectedSaltSize, "salt");
        if (batch.Length < BatchHeaderSize || !StartsWith(batch, BatchMagic))
        {
            throw new InvalidDataException("batch file has an invalid header");
        }
        int count = BitConverter.ToInt32(batch, 8);
        int candidateSize = BitConverter.ToInt32(batch, 12);
        if (count < 1 || count > MaximumCandidates
            || candidateSize != ExpectedCandidateSize
            || batch.Length != BatchHeaderSize + count * ExpectedCandidateSize)
        {
            throw new InvalidDataException("batch file has invalid metadata");
        }

        IntPtr handle = NativeLibrary.Load(library);
        try
        {
            Construct construct = LoadDelegate<Construct>(handle, ConstructSymbol);
            Open open = LoadDelegate<Open>(handle, OpenSymbol);
            Init init = LoadDelegate<Init>(handle, InitSymbol);
            Destroy destroy = LoadDelegate<Destroy>(handle, DestroySymbol);
            IntPtr saltBuffer = CopyToUnmanaged(salt);
            IntPtr saltVector = Vector(saltBuffer, salt.Length);
            IntPtr client = AllocateZeroed(ClientSize);
            byte[] results = new byte[count];
            int accepted = 0;
            int completed = 0;
            bool openFailed = false;
            try
            {
                for (int index = 0; index < count; index++)
                {
                    byte[] candidate = new byte[ExpectedCandidateSize];
                    Array.Copy(
                        batch,
                        BatchHeaderSize + index * ExpectedCandidateSize,
                        candidate,
                        0,
                        ExpectedCandidateSize);
                    IntPtr candidateBuffer = CopyToUnmanaged(candidate);
                    IntPtr candidateVector = Vector(candidateBuffer, candidate.Length);
                    bool constructed = false;
                    try
                    {
                        // A fresh client per candidate mirrors the verified preload,
                        // which destroys each constructed client before the next one.
                        Zero(client, ClientSize);
                        construct(client);
                        constructed = true;
                        if (open(client) == 0)
                        {
                            results[index] = 0xFF;
                            completed = index + 1;
                            openFailed = true;
                            break;
                        }
                        Marshal.WriteByte(client, InitialisedByteOffset, 1);
                        int initResult = init(
                            client, 0, 1, 1, 2, 1, candidateVector, saltVector, MaximumSharedSize);
                        results[index] = initResult != 0 ? (byte)1 : (byte)0;
                        accepted += initResult != 0 ? 1 : 0;
                        completed = index + 1;
                    }
                    finally
                    {
                        if (constructed)
                        {
                            destroy(client);
                        }
                        Marshal.FreeHGlobal(candidateBuffer);
                        Marshal.FreeHGlobal(candidateVector);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(client);
                Marshal.FreeHGlobal(saltBuffer);
                Marshal.FreeHGlobal(saltVector);
            }

            byte[] output = new byte[BatchHeaderSize + completed];
            Array.Copy(ResultMagic, 0, output, 0, ResultMagic.Length);
            BitConverter.GetBytes(completed).CopyTo(output, 8);
            BitConverter.GetBytes(ExpectedCandidateSize).CopyTo(output, 12);
            Array.Copy(results, 0, output, BatchHeaderSize, completed);
            File.WriteAllBytes(resultPath, output);
            Console.WriteLine("accepted_count=" + accepted);
            Console.WriteLine("completed_count=" + completed);
            return openFailed ? 1 : 0;
        }
        finally
        {
            NativeLibrary.Free(handle);
        }
    }

    private static bool StartsWith(byte[] data, byte[] prefix)
    {
        if (data.Length < prefix.Length)
        {
            return false;
        }
        for (int index = 0; index < prefix.Length; index++)
        {
            if (data[index] != prefix[index])
            {
                return false;
            }
        }
        return true;
    }

    private static void Zero(IntPtr pointer, int size)
    {
        for (int offset = 0; offset < size; offset += 8)
        {
            Marshal.WriteInt64(pointer, offset, 0);
        }
    }

    private static T LoadDelegate<T>(IntPtr handle, string symbol) where T : Delegate
    {
        IntPtr address = NativeLibrary.GetExport(handle, symbol);
        if (address == IntPtr.Zero)
        {
            throw new InvalidOperationException("missing symbol " + symbol);
        }
        return Marshal.GetDelegateForFunctionPointer<T>(address);
    }

    private static byte[] ReadExact(string path, int expected, string label)
    {
        byte[] data = File.ReadAllBytes(path);
        if (data.Length != expected)
        {
            throw new InvalidDataException(
                label + " has " + data.Length + " bytes, expected " + expected);
        }
        return data;
    }

    private static IntPtr AllocateZeroed(int size)
    {
        IntPtr pointer = Marshal.AllocHGlobal(size);
        for (int offset = 0; offset < size; offset += 8)
        {
            Marshal.WriteInt64(pointer, offset, 0);
        }
        return pointer;
    }

    private static IntPtr CopyToUnmanaged(byte[] data)
    {
        IntPtr pointer = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, pointer, data.Length);
        return pointer;
    }

    private static IntPtr Vector(IntPtr data, int length)
    {
        IntPtr vector = Marshal.AllocHGlobal(3 * IntPtr.Size);
        Marshal.WriteIntPtr(vector, 0, data);
        Marshal.WriteIntPtr(vector, IntPtr.Size, data + length);
        Marshal.WriteIntPtr(vector, 2 * IntPtr.Size, data + length);
        return vector;
    }
}