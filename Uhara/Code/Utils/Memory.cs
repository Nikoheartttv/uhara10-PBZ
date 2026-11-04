using SharpDisasm;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static TImports;

internal class TMemory
{
    private sealed class SectionSnapshot
    {
        internal ulong Address;
        internal byte[] Bytes;
    }

    private sealed class SectionCacheEntry
    {
        internal long Bytes;
        internal List<SectionSnapshot> Sections;
    }

    private static readonly object SectionCacheLock = new object();
    private static readonly Dictionary<string, SectionCacheEntry> SectionCache = new Dictionary<string, SectionCacheEntry>();
    private const int MaxCachedModules = 4;
    private const long MaxCachedSectionBytes = 1024L * 1024L * 1024L;

    internal static IntPtr ScanSimple(Process process, string signature, string moduleName = null)
    {
        return (IntPtr)ScanSingle(process, signature, moduleName);
    }

    internal static ulong DerefPointer(Process process, ulong address, params int[] offsets)
    {
        do
        {
            if (address == 0) break;
            address = ReadMemory<ulong>(process, address);
            if (address == 0) break;

            for (int i = 0; i < offsets.Length; i++)
            {
                address = ReadMemory<ulong>(process, address + (ulong)offsets[i]);
                if (address == 0) return 0;
            }

            return address;
        }
        while (false);
        return 0;
    }

    internal static string ReadMemoryString(Process process, ulong address, int maxLength)
    {
        byte[] textBytes = ReadMemoryBytes(process, address, maxLength);
        return TUtils.MultibyteToString(textBytes);
    }

    internal static ulong[] ScanMultiple(Process process, string signature, string moduleName = null, int memoryProtection = -1)
    {
        List<ulong> resultsRaw = new List<ulong>();
        byte[] searchBytes = TSignature.GetBytes(signature);
        string searchMask = TSignature.GetMask(signature);

        List<SectionSnapshot> sections = GetSectionSnapshots(process, moduleName);

        for (int i = 0; i < sections.Count; i++)
        {
            SectionSnapshot section = sections[i];
            int searchOffset = 0;
            while (searchOffset < section.Bytes.Length)
            {
                searchOffset = FindInArray(section.Bytes, searchBytes, searchMask, searchOffset);
                if (searchOffset == -1) break;

                ulong foundAddress = section.Address + (ulong)searchOffset;

                if (memoryProtection == -1) resultsRaw.Add(foundAddress);
                else if (GetMemoryProtection(process, foundAddress) == memoryProtection)
                    resultsRaw.Add(foundAddress);

                searchOffset += searchBytes.Length;
                if (searchOffset >= section.Bytes.Length) break;
            }
        }

        return resultsRaw.ToArray();
    }

    internal static int GetMemoryProtection(Process process, ulong address, int size = 0x1000)
    {
        MBI mBi = new MBI();
        if (!VirtualQueryEx(process.Handle, (IntPtr)address, out mBi, (uint)size)) return -1;
        return (int)mBi.Protect;
    }

    internal static int GetMinimumOverwriteBackwards(Process process, ulong address, int overwrite)
    {
        ulong hookAddress = address - 0x1000;
        byte[] pageBytes = ReadMemoryBytes(process, hookAddress, 0x1000);
        Instruction[] instructions = TInstruction.GetInstructions2(pageBytes);

        List<int> insLengths = new List<int>();

        foreach (Instruction ins in instructions)
        {
            hookAddress += (ulong)ins.Bytes.Length;
            insLengths.Add(ins.Bytes.Length);

            if (hookAddress == address) break;
        }

        int offset = 0;
        for (int i = insLengths.Count - 1; i >= 0; i--)
        {
            offset += insLengths[i];
            if (offset >= overwrite)
            {
                return offset;
            }
        }

        return 0;
    }

    internal static ulong GetFunctionStartByPadding(Process process, ulong address, int maxBack = 0x200, int minPadding = 4)
    {
        if (process == null || address == 0) return 0;

        int back = maxBack;
        if ((ulong)back > address) back = (int)address;
        if (back <= minPadding) return 0;

        ulong windowStart = address - (ulong)back;
        byte[] bytes = ReadMemoryBytes(process, windowStart, back);
        if (bytes == null || bytes.Length != back) return 0;

        // Walk back over code until the nearest run of int3 padding that is at
        // least minPadding bytes long; the function starts right after it.
        int index = bytes.Length - 1;
        while (index >= 0)
        {
            while (index >= 0 && bytes[index] != 0xCC) index--;
            if (index < 0) return 0;

            int paddingEnd = index;
            int padding = 0;
            while (index >= 0 && bytes[index] == 0xCC)
            {
                padding++;
                index--;
            }

            if (padding >= minPadding)
                return windowStart + (ulong)(paddingEnd + 1);
        }

        return 0;
    }

    internal static ulong GetFunctionStart(Process process, ulong address)
    {
        ulong newAddress = address - 0x1000;
        byte[] pageBytes = ReadMemoryBytes(process, newAddress, 0x1000);
        Instruction[] instructions = TInstruction.GetInstructions2(pageBytes, newAddress);

        int insIndex = 0;
        for (int i = 0; i < instructions.Length; i++)
        {
            newAddress += (ulong)instructions[i].Bytes.Length;

            if (newAddress == address)
            {
                newAddress = instructions[i].Offset;
                insIndex = i;
                break;
            }
        }

        if (insIndex == 0) return 0;

        for (int i = insIndex; i >= 0; i--)
        {
            if (instructions[i].ToString() == "int3" || instructions[i].ToString() == "ret")
            {
                return instructions[i].Offset + 1;
            }
        }

        return 0;
    }

    internal static ulong GetFunctionReturn(Process process, ulong functionAddress)
    {
        byte[] pageBytes = ReadMemoryBytes(process, functionAddress, 0x1000);
        Instruction[] instructions = TInstruction.GetInstructions2(pageBytes);

        ulong retAddress = functionAddress;
        int offset = 0;

        foreach (Instruction ins in instructions)
        {
            if (ins.ToString() == "ret") return retAddress + (ulong)offset;
            else offset += ins.Bytes.Length;
        }

        return 0;
    }

    internal static byte[] ConvertRelativeToAbsolute(byte[] bytes, ulong originalAddress)
    {
        Instruction[] instructions = TInstruction.GetInstructions2(bytes);
        List<byte[]> newBytes = new List<byte[]>();

        int offset = 0;
        foreach (Instruction ins in instructions)
        {
            string txtIns = ins.ToString();

            if (ins.Bytes.Length == 5)
            {
                if (txtIns.StartsWith("call"))
                {
                    ulong actualEnd = GetActualAddressFromRelative5ByteInstruction(ins.Bytes, originalAddress + (ulong)offset);
                    newBytes.Add(GetAbsoluteCallBytes(actualEnd));
                }

                else if (txtIns.StartsWith("jmp"))
                {
                    ulong actualEnd = GetActualAddressFromRelative5ByteInstruction(ins.Bytes, originalAddress + (ulong)offset);
                    newBytes.Add(GetAbsoluteJumpBytes(actualEnd));
                }
                else newBytes.Add(ins.Bytes);
            }

            else newBytes.Add(ins.Bytes);

            offset += ins.Bytes.Length;
        }

        return TArray.Merge(newBytes);
    }

    internal static ulong GetActualAddressFromRelative5ByteInstruction(byte[] bytes, ulong address)
    {
        Instruction instr = TInstruction.GetInstruction2(bytes, address);
        if (instr.Bytes.Length == 5)
        {
            int value = BitConverter.ToInt32(bytes, 1);
            return address + (ulong)(value + instr.Bytes.Length);
        }
        return 0;
    }

    internal static bool ConfirmBytes(Process process, ulong address, string signature)
    {
        return ConfirmBytes(process, address, TSignature.GetBytes(signature));
    }

    internal static bool ConfirmBytes(Process process, ulong address, byte[] bytes)
    {
        byte[] read = ReadMemoryBytes(process, address, bytes.Length);

        if (read != null) return read.SequenceEqual(bytes);
        else return false;
    }

    internal static string GetSignature(byte[] array, bool noSpaces = false)
    {
        string hex = BitConverter.ToString(array);
        if (noSpaces) return hex.Replace("-", " ").Replace(" ", "");
        else return hex.Replace("-", " ");
    }

    internal static bool FreeMemory(Process process, ulong address, int size, uint type = 0x00008000)
    {
        return TImports.VirtualFreeEx(process.Handle, (IntPtr)address, size, type);
    }

    internal static void FixRelative(Process process, ulong original, ulong current, int size)
    {
        byte[] originalBytes = ReadMemoryBytes(process, original, size);
        byte[] currentBytes = ReadMemoryBytes(process, current, size);

        Instruction[] _org = TInstruction.GetInstructions2(originalBytes);
        Instruction[] _cur = TInstruction.GetInstructions2(originalBytes);

        int total = 0;
        for (int i = 0; i < _org.Length; i++)
        {
            if (total != 0) total += _org[i - 1].Bytes.Length;

            string orgTxt = _org[i].ToString();
            string curTxt = _cur[i].ToString();

            byte[] orgFullBytes = _org[i].Bytes;
            byte[] curFullBytes = _cur[i].Bytes;

            if (orgTxt != curTxt) continue;
            if (!orgFullBytes.SequenceEqual(curFullBytes)) continue;

            if (orgTxt.Contains("rip"))
            {
                if (!orgTxt.Contains("]")) continue;

                string ripValueTxt = orgTxt.Remove(orgTxt.IndexOf("]"));
                ripValueTxt = ripValueTxt.Substring(ripValueTxt.IndexOf("rip") + 3);
                uint ripValue = TConvert.Parse<uint>(ripValueTxt);

                if (ripValue == 0) continue;

                byte[] ripValueBytes = BitConverter.GetBytes(ripValue);
                int byteOffset = FindInArray(curFullBytes, ripValueBytes);

                byte[] newRipValueBytes = BitConverter.GetBytes(ripValue - (uint)(current - original));

                Main.RefWriteBytes(process, current + (ulong)(byteOffset + total), newRipValueBytes);
            }
            else if (orgTxt.StartsWith("call"))
            {
                if (orgFullBytes.Length != 5) continue;
                if (orgTxt.StartsWith("call e") || orgTxt.StartsWith("call r")) continue;

                uint ripValue = BitConverter.ToUInt32(orgFullBytes, 1);
                byte[] newRipValueBytes = BitConverter.GetBytes(ripValue - (uint)(current - original));
                Main.RefWriteBytes(process, current + 1 + (ulong)total, newRipValueBytes);
            }
        }
    }
    
    internal static byte[] GetAbsoluteJumpBytes(ulong destination)
    {
        byte[] stub = new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        byte[] full = TArray.Merge(stub, BitConverter.GetBytes(destination));
        return full;
    }

    internal static ulong CreateAbsoluteJump(Process process, ulong source, ulong destination)
    {
        byte[] stub = new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        byte[] full = TArray.Merge(stub, BitConverter.GetBytes(destination));
        Main.RefWriteBytes(process, source, full);
        return (ulong)full.Length;
    }

    internal static ulong CreateAbsoluteCall(Process process, ulong source, ulong destination, byte rspArguments = 0)
    {
        byte[] subRsp = new byte[] { 0x48, 0x83, 0xEC, rspArguments };
        byte[] start = new byte[] { 0xEB, 0x08 };
        byte[] address = BitConverter.GetBytes(destination);
        byte[] end = new byte[] { 0xFF, 0x15, 0xF2, 0xFF, 0xFF, 0xFF, 0x90 };
        byte[] addRsp = new byte[] { 0x48, 0x83, 0xC4, rspArguments };

        byte[] full = null;
        if (rspArguments == 0) full = TArray.Merge(start, address, end);
        else full = TArray.Merge(subRsp, start, address, end, addRsp);

        Main.RefWriteBytes(process, source, full);
        return (ulong)full.Length;
    }

    internal static byte[] GetAbsoluteCallBytes(ulong destination)
    {
        byte[] start = new byte[] { 0xEB, 0x08 };
        byte[] address = BitConverter.GetBytes(destination);
        byte[] end = new byte[] { 0xFF, 0x15, 0xF2, 0xFF, 0xFF, 0xFF, 0x90 };
        return TArray.Merge(start, address, end);
    }

    public static ulong ScanAdvanced(Process process, TSignature.ScanData scanData, string moduleName = null)
    {
        ulong searchAddress = 0;

        List<SectionSnapshot> sections = GetSectionSnapshots(process, moduleName);

        List<KeyValuePair<string, int>> checkpoints = new List<KeyValuePair<string, int>>(scanData.Checkpoints);
        checkpoints.Insert(0, new KeyValuePair<string, int>(scanData.Signature, 0));

        // incorrect queen index check
        if (scanData.QueenCheckpointIndex < 0 || scanData.QueenCheckpointIndex >= checkpoints.Count)
            return 0;

        byte[] baseByteSignature = TSignature.GetBytes(scanData.Signature);

        for (int i = 0; i < sections.Count; i++)
        {
            SectionSnapshot section = sections[i];
            if (section.Bytes == null || section.Bytes.Length == 0) continue;
            int searchOffset = 0;

            int offsetSuccess = 0;

            bool chainSuccess = false;
            int baseOffset = 0;

            for (int j = 0; j < checkpoints.Count; j++)
            {
                string[] separateSigs = checkpoints[j].Key.Split(',');
                for (int k = 0; k < separateSigs.Length; k++)
                {
                    byte[] searchBytes = TSignature.GetBytes(separateSigs[k]);
                    string searchMask = TSignature.GetMask(separateSigs[k]);

                    int maxDistance = 0;

                    if (checkpoints[j].Value == 0) maxDistance = 0;
                    else maxDistance = checkpoints[j].Value;

                    if (scanData.ReversedSearch && j != 0 && k == 0)
                    {
                        searchOffset = searchOffset - checkpoints[j].Value;
                        if (searchOffset <= 0 && Math.Abs(searchOffset) < searchBytes.Length)
                        {
                            chainSuccess = false;
                            break;
                        }
                    }

                    int searchOffset2 = FindInArray(section.Bytes, searchBytes, searchMask, searchOffset, maxDistance);
                    chainSuccess = searchOffset2 != -1;

                    if (chainSuccess)
                    {
                        searchOffset = searchOffset2;
                        if (j == 0) baseOffset = searchOffset2;
                        if (j == scanData.QueenCheckpointIndex) offsetSuccess = searchOffset2;
                        break;
                    }
                    else continue;
                }

                if (chainSuccess) continue;
                else if (j == 0) break;
                else
                {
                    searchOffset = baseOffset + baseByteSignature.Length;
                    if (searchOffset + baseByteSignature.Length > section.Bytes.Length) break;
                    j = -1;
                }
            }

            if (chainSuccess)
            {
                searchAddress = section.Address + (ulong)offsetSuccess;
                break;
            }
        }

        if (searchAddress != 0)
        {
            if (scanData.Relative)
            {
                ulong searchAddressRelative = (ulong)((long)searchAddress + scanData.ToRelativeInstructionOffset);
                Instruction instr = TInstruction.GetInstruction2(process, searchAddressRelative);

                long value = TInstruction.ExtractRipValue(instr);

                if (value != 0) searchAddress = (ulong)((long)searchAddressRelative + value) + (ulong)instr.Bytes.Length;
                else return 0;
            }
            else if (scanData.FindStartFunction)
            {
                ulong newAddress = TInstruction.GetAlignedAddress(process, searchAddress);
                byte[] disasm = ReadMemoryBytes(process, newAddress - 0x1000, 0x1000);
                Instruction[] instrs = TInstruction.GetInstructions2(disasm, newAddress - 0x1000);

                for (int i = instrs.Length - 1; i >= 0; i--)
                {
                    if (instrs[i].ToString() == "int3")
                    {
                        break;
                    }

                    newAddress -= (ulong)instrs[i].Bytes.Length;
                }

                searchAddress = newAddress;
            }

            searchAddress = (ulong)((long)searchAddress + scanData.Offset);
        }

        return searchAddress;
    }

    internal static ulong ScanSingle(Process process, string signature, string moduleName = null, int memoryProtection = -1)
    {
        byte[] searchBytes = TSignature.GetBytes(signature);
        string searchMask = TSignature.GetMask(signature);

        List<SectionSnapshot> sections = GetSectionSnapshots(process, moduleName);

        for (int i = 0; i < sections.Count; i++)
        {
            SectionSnapshot section = sections[i];
            int searchOffset = 0;
            while (searchOffset < section.Bytes.Length)
            {
                searchOffset = FindInArray(section.Bytes, searchBytes, searchMask, searchOffset);
                if (searchOffset == -1) break;

                ulong foundAddress = section.Address + (ulong)searchOffset;
                if (memoryProtection == -1) return foundAddress;
                else if (GetMemoryProtection(process, foundAddress) == memoryProtection)
                    return foundAddress;

                searchOffset += 1;
                if (searchOffset >= section.Bytes.Length) break;
                if (searchOffset + searchBytes.Length - 1 >= section.Bytes.Length) break;
            }
        }

        return 0;
    }

    internal static ulong ScanRel(Process process, int offset, string signature)
    {
        byte[] searchBytes = TSignature.GetBytes(signature);
        string searchMask = TSignature.GetMask(signature);

        List<SectionSnapshot> sections = GetSectionSnapshots(process);

        foreach (SectionSnapshot section in sections)
        {
            int searchOffset = FindInArray(section.Bytes, searchBytes, searchMask);
            if (searchOffset != -1)
            {
                ulong searchAddress = section.Address + (ulong)searchOffset;
                ulong relativeAddress = (ulong)((long)searchAddress + offset);
                int relativeValue = ReadMemory<int>(Main.ProcessInstance, relativeAddress);
                ulong destinationAddress = (ulong)((long)searchAddress + relativeValue + offset + 4);
                return destinationAddress;
            }
        }

        return 0;
    }

    internal static ulong ScanRel2(Process process, string signature, string moduleName = null, int offset = 0)
    {
        byte[] searchBytes = TSignature.GetBytes(signature);
        string searchMask = TSignature.GetMask(signature);

        ulong searchAddress = ScanSingle(process, signature, moduleName);
        if (searchAddress == 0) return 0;

        searchAddress = (ulong)((long)searchAddress + offset);

        Instruction instr = TInstruction.GetInstruction2(process, searchAddress);
        long value = TInstruction.ExtractRipValue(instr);

        if (value != 0) searchAddress = (ulong)((long)searchAddress + value) + (ulong)instr.Bytes.Length;
        else return 0;

        return searchAddress;
    }

    internal static void ClearScanCache()
    {
        lock (SectionCacheLock) SectionCache.Clear();
    }

    private static List<SectionSnapshot> GetSectionSnapshots(Process process, string moduleName = null)
    {
        string key = GetScanCacheKey(process, moduleName);
        if (key == null) return ReadSectionSnapshots(process, moduleName);

        lock (SectionCacheLock)
        {
            SectionCacheEntry cached;
            if (SectionCache.TryGetValue(key, out cached)) return cached.Sections;

            List<SectionSnapshot> snapshots = ReadSectionSnapshots(process, moduleName);
            if (snapshots.Count == 0) return snapshots;

            long snapshotBytes = 0;
            for (int i = 0; i < snapshots.Count; i++) snapshotBytes += snapshots[i].Bytes.Length;
            if (snapshotBytes > MaxCachedSectionBytes) return snapshots;

            long cachedBytes = 0;
            foreach (SectionCacheEntry entry in SectionCache.Values) cachedBytes += entry.Bytes;
            while (SectionCache.Count > 0 &&
                   (SectionCache.Count >= MaxCachedModules || cachedBytes + snapshotBytes > MaxCachedSectionBytes))
            {
                string firstKey = null;
                foreach (string existingKey in SectionCache.Keys)
                {
                    firstKey = existingKey;
                    break;
                }
                if (firstKey == null) break;

                cachedBytes -= SectionCache[firstKey].Bytes;
                SectionCache.Remove(firstKey);
            }

            SectionCache[key] = new SectionCacheEntry { Bytes = snapshotBytes, Sections = snapshots };
            return snapshots;
        }
    }

    private static List<SectionSnapshot> ReadSectionSnapshots(Process process, string moduleName)
    {
        List<SectionSnapshot> snapshots = new List<SectionSnapshot>();
        List<ulong[]> sections = GetAllSections(process, moduleName);

        for (int i = 0; i < sections.Count; i++)
        {
            int size = (int)sections[i][1];
            if (size <= 0) continue;

            byte[] bytes = ReadMemoryBytes(process, sections[i][0], size);
            if (bytes == null || bytes.Length == 0) continue;

            snapshots.Add(new SectionSnapshot
            {
                Address = sections[i][0],
                Bytes = bytes
            });
        }

        return snapshots;
    }

    private static string GetScanCacheKey(Process process, string moduleName)
    {
        if (process == null) return null;

        try
        {
            return TProcess.GetToken(process) + "|" + (moduleName ?? "<main>").ToUpperInvariant();
        }
        catch
        {
            return null;
        }
    }

    public static List<ulong[]> GetAllSections(Process process, string moduleName = null)
    {
        List<ulong[]> sections = new List<ulong[]>();

        ProcessModule procModule = TProcess.GetModule(process, moduleName);
        if (procModule == null) return sections;

        ulong baseAddress = (ulong)procModule.BaseAddress;
        byte[] peHeader = GetPEHeader(process, baseAddress);
        if (peHeader == null) return sections;

        int peHeaderOffset = BitConverter.ToInt32(peHeader, 0x3C);
        if (peHeaderOffset < 0 || peHeaderOffset + 0x18 > peHeader.Length) return sections;
        int sectionCount = BitConverter.ToUInt16(peHeader, peHeaderOffset + 0x6);
        int optionalHeaderSize = BitConverter.ToUInt16(peHeader, peHeaderOffset + 0x14);
        int sectionHeaderOffset = peHeaderOffset + 0x18 + optionalHeaderSize;
        if (sectionHeaderOffset < 0 || sectionHeaderOffset + sectionCount * 0x28 > peHeader.Length) return sections;

        long imageSize = procModule.ModuleMemorySize;
        if (imageSize <= 0) return sections;

        for (int i = 0; i < sectionCount; i++)
        {
            int currentSectionOffset = sectionHeaderOffset + (i * 0x28);
            uint virtualSize = BitConverter.ToUInt32(peHeader, currentSectionOffset + 0x08);
            uint rawSize = BitConverter.ToUInt32(peHeader, currentSectionOffset + 0x10);
            uint virtualAddress = BitConverter.ToUInt32(peHeader, currentSectionOffset + 0x0C);

            long sectionSize = virtualSize > 0 ? virtualSize : rawSize;
            if (sectionSize <= 0 || virtualAddress >= imageSize) continue;
            sectionSize = Math.Min(sectionSize, imageSize - virtualAddress);
            if (sectionSize > int.MaxValue) continue;

            sections.Add(new ulong[] { baseAddress + virtualAddress, (ulong)sectionSize });
        }

        if (sections.Count > 0) sections = sections.OrderBy(x => x[0]).ToList();
        return sections;
    }

    internal static byte[] GetPEHeader(Process process, ulong baseAddress)
    {
        byte[] dosHeader = ReadMemoryBytes(process, baseAddress, 0x40);
        if (dosHeader == null || dosHeader.Length < 0x40 || BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D) return null;

        int peHeaderOffset = BitConverter.ToInt32(dosHeader, 0x3C);
        if (peHeaderOffset < 0x40 || peHeaderOffset > 0x100000) return null;

        byte[] peHeaderInfo = ReadMemoryBytes(process, baseAddress + (ulong)peHeaderOffset, 0x18);
        if (peHeaderInfo == null || peHeaderInfo.Length < 0x18 || BitConverter.ToUInt32(peHeaderInfo, 0) != 0x00004550) return null;

        int sectionCount = BitConverter.ToUInt16(peHeaderInfo, 0x6);
        int optionalHeaderSize = BitConverter.ToUInt16(peHeaderInfo, 0x14);
        if (sectionCount <= 0 || sectionCount > 96 || optionalHeaderSize < 0x60) return null;

        long totalSize = (long)peHeaderOffset + 0x18 + optionalHeaderSize + sectionCount * 0x28L;
        if (totalSize <= 0 || totalSize > 0x100000) return null;
        return ReadMemoryBytes(process, baseAddress, (int)totalSize);
    }

    internal static int FindInArray(byte[] chunkData, string signature, int startPosition = 0, int maxDistance = 0)
    {
        return FindInArray(chunkData, TSignature.GetBytes(signature), TSignature.GetMask(signature), startPosition, maxDistance);
    }

    internal static int FindInArray(byte[] chunkData, byte[] byteSignature, string mask = "", int startPosition = 0, int maxDistance = 0)
    {
        if (mask.Contains("<") || mask.Contains(">")) return FindInArrayWithHalfBytes(chunkData, byteSignature, mask, startPosition, maxDistance);

        int position = startPosition;
        bool maskOn = mask.Contains("?") || mask.Contains("!");
        int found = 0; bool flag = false;

        while (position < chunkData.Length)
        {
            flag = false;
            if (maskOn)
            {
                if ((mask[found] == 'x' && chunkData[position] == byteSignature[found]) ||
                (mask[found] == '?') || (mask[found] == '!' && chunkData[position] != byteSignature[found]))
                {
                    flag = true;
                }
            }
            else if (chunkData[position] == byteSignature[found]) flag = true;

            if (flag == true)
            {
                found += 1;
                if (found == byteSignature.Length) return position - found + 1;

            }
            else
            {
                position -= found - 1;
                found = 0;
            }

            if (flag) position += 1;
            if (maxDistance != 0 && position >= startPosition + maxDistance)
            {
                return -1;
            }
        }
        return -1;
    }

    private static int FindInArrayWithHalfBytes(byte[] chunkData, byte[] byteSignature, string mask = "", int startPosition = 0, int maxDistance = 0)
    {
        int position = startPosition;
        bool maskOn = true;
        int found = 0; bool flag = false;

        while (position < chunkData.Length)
        {
            flag = false;
            if (maskOn)
            {
                if ((mask[found] == 'x' && chunkData[position] == byteSignature[found]) ||
                (mask[found] == '?') ||
                (mask[found] == '<' && BitConverter.ToString(new byte[] { chunkData[position] })[1] == BitConverter.ToString(new byte[] { byteSignature[found] })[1]) || 
                (mask[found] == '>' && BitConverter.ToString(new byte[] { chunkData[position] })[0] == BitConverter.ToString(new byte[] { byteSignature[found] })[0]) || 
                (mask[found] == '!' && chunkData[position] != byteSignature[found]))
                {
                    flag = true;
                }
            }
            else if (chunkData[position] == byteSignature[found]) flag = true;

            if (flag == true)
            {
                found += 1;
                if (found == byteSignature.Length) return position - found + 1;

            }
            else
            {
                position -= found - 1;
                found = 0;
            }

            if (flag) position += 1;
            if (maxDistance != 0 && position >= startPosition + maxDistance)
            {
                return -1;
            }
        }
        return -1;
    }

    internal static T ReadMemory<T>(Process process, ulong address) where T : unmanaged
    {
        return ReadMemory<T>(process, (IntPtr)address);
    }

    internal static T ReadMemory<T>(Process process, IntPtr address) where T : unmanaged
    {
        int typeSize = Marshal.SizeOf(typeof(T));
        byte[] data = new byte[typeSize];

        if (ReadProcessMemory(process.Handle, address, data, data.Length, out _))
        {
            if (typeof(T) == typeof(IntPtr)) return (T)(object)(IntPtr)BitConverter.ToUInt64(data, 0);
            else if (typeof(T) == typeof(bool)) return (T)(object)BitConverter.ToBoolean(data, 0);
            else if (typeof(T) == typeof(byte)) return (T)(object)data[0];
            else if (typeof(T) == typeof(sbyte)) return (T)(object)data[0];
            else if (typeof(T) == typeof(char)) return (T)(object)data[0];
            else if (typeof(T) == typeof(short)) return (T)(object)BitConverter.ToInt16(data, 0);
            else if (typeof(T) == typeof(ushort)) return (T)(object)BitConverter.ToUInt16(data, 0);
            else if (typeof(T) == typeof(int)) return (T)(object)BitConverter.ToInt32(data, 0);
            else if (typeof(T) == typeof(uint)) return (T)(object)BitConverter.ToUInt32(data, 0);
            else if (typeof(T) == typeof(long)) return (T)(object)BitConverter.ToInt64(data, 0);
            else if (typeof(T) == typeof(ulong)) return (T)(object)BitConverter.ToUInt64(data, 0);
            else if (typeof(T) == typeof(float)) return (T)(object)BitConverter.ToSingle(data, 0);
            else if (typeof(T) == typeof(double)) return (T)(object)BitConverter.ToDouble(data, 0);
            else if (typeof(T) == typeof(decimal)) return (T)(object)TUtils.ToDecimal(data);
        }
        return default(T);
    }

    internal static byte[] ReadMemoryBytes(Process process, ulong address, int size)
    {
        return ReadMemoryBytes(process, (IntPtr)address, size);
    }

    internal static byte[] ReadMemoryBytes(Process process, IntPtr address, int size)
    {
        if (process == null || address == IntPtr.Zero || size <= 0) return null;

        byte[] data = new byte[size];
        if (ReadProcessMemory(process.Handle, address, data, data.Length, out IntPtr bytesRead) && bytesRead.ToInt64() == size)
            return data;

        const int chunkSize = 0x100000;
        int offset = 0;
        while (offset < size)
        {
            int count = Math.Min(chunkSize, size - offset);
            IntPtr currentAddress = (IntPtr)((ulong)address + (ulong)offset);
            byte[] chunk = new byte[count];
            if (!ReadProcessMemory(process.Handle, currentAddress, chunk, count, out bytesRead)) return null;
            if (bytesRead.ToInt64() != count) return null;

            Array.Copy(chunk, 0, data, offset, count);
            offset += count;
        }

        return data;
    }
}
