------------------------------------------
DDI Table Offset finder, Artem Malyi, 2012
------------------------------------------

The goal of this utility is to simplify the development of Text Recognition for future Windows OSes.
This utility scans kernel memory and prints to the console the offset of found DDI (Graphic Device Driver Interface) functions table.
Please make sure that you're familiar with Feng Yuang's DCOBJ structure (Windows Graphics Programming, p.194).
    https://books.google.com.ua/books?id=-O92IIF1Bj4C&lpg=PP1&hl=en&pg=PA194#v=onepage&q&f=false

-----------
How to use:
    1. Make sure that Windows box is connected to internet. The tool will try to download win32k.pdb and gdi32.pdb from Microsoft Symbols Server.
    2. On x64bit OS please make sure that you've disabled driver signature enforcement. E.g. on Windows 7 you can do it like this (with admin provileges):
        > bcdedit.exe -set loadoptions DDISABLE_INTEGRITY_CHECKS
        > bcdedit.exe -set TESTSIGNING ON
        The driver that is used by the tool is signed by the test certificate, so you need to disable driver signature check on your test Windows box.
    3. On x64bit OS reboot the system to Test Mode.
    4. Run the dtfinder.exe from console. It must return something similar to:
        > c:\ws\offset-finder\bin>dtfinder.exe
        >
        >         DDI Table Offset Finder 0.1
        > Usage: offset-finder.exe <DCOBJ-iterations> <PDEV-iterations>
        > Try to obtain symbols information for WIN32K.SYS. This may take some time
        > Try to obtain symbols information for GDI32.DLL. This may take some time
        > Try to install kernel mode component
        > Going to perform kernel memory scan from 0xfffff900c01ec010 location
        > 	with the following iteration values: DCOBJ - 50, PDEV_WIN32K - 500
        > +-------------------------------------------------+
        > | DDI table is found at DCOBJ+0x0030, PDEV+0x0a30 |
        > +-------------------------------------------------+
        > Uninstall kernel mode component
        >
    5. Now, notice the offsets DCOBJ+0x0030 and PDEV+0x0a30 and hardcode them in the lr-trunk/app/Protocols/text_trap/app/pal_drv/pal_hook.c!GetDataOnTextOutPointer() function.

Troubleshooting:
    If you observe the result like this:
    > +-----------------------------------------------------------------------+
    > | DDI table was not found. Try increasing the number of scan iterations.|
    > | Current values are: DCOBJ - 50        PDEV_WIN32K - 500               |
    > +-----------------------------------------------------------------------+
    This means that the tool tried the default number of memory scans (50/500) which was not enough.
    In this case you can pass larger values:
        > c:\ws\offset-finder\bin>dtfinder.exe 100 1000
    and wait for the result.

------
Files:
./bin:
    dtfiner.exe - the tool binary file. It is made not dependent from Visual Studio runtime, instead it imports msvcrt.dll which is there on every Windows box.
        Also, dtfinder.exe contains helper binary files embedded in its resources. These are some .dlls from Debugging Tools for Windows, and the helper driver files.
        This is done for simplicity of use on different Windows machines.

./make:
    ./sign-driver/ - folder contains the script that is used during build, that signs the helper driver component with the test certificate. (Needed for x64bit version.)
    msbuild.bat and offset-finder.proj - files to build with MSbuild.exe the following three components: x64 and x86 drivers, and x86 user-mode component (dtfinder.exe itself).
    vcbuild.bat - file that sets vital environment variables for project build and launches Visual Studio.

./redist:
    dbghelp.dll and symsrv.dll - files from Debugging Tools for Windows that are embedded into dtfinder.exe and are used to get symbols information for several binaries.

./src:
    ./inc/common.h - header file with definitions common for kernel-mode (KM) component and user-mode (UM) component.
    ./km/ - folder containing KM component's logic.
    ./um/ - folder containing UM component's logic.

./readme.txt - this file.

-------------
How to build:
    1. Make sure you have Windows Driver Kit and Visual Studio available on your machine.
    2. Edit ./make/msbuild.bat according to your WDK and VS locations.
    3. Run msbuild.bat.
    ==>
Note, that the solution was developed on VS 2005 and DDK for WinXP.

-----------------
How does it work:
    The idea is based on the fact that DDI table of functions is by default filled with pointers to standard functions, implemented in win32k.sys.
    Functions, like win32k!SpTextOut, win32k!SpLineTo, win32k!SpBitBlt, etc. Considering the information from Feng Yuan,
    each GDI handle represents an index in the GDI handle table, the index that points to a related device context object structure in the kernel - DCOBJ structure.
    (refer to https://books.google.com.ua/books?id=-O92IIF1Bj4C&lpg=PP1&hl=en&pg=PA194#v=onepage&q&f=false for DCOBJ details.)
    This DCOBJ structure contains a pointer to a DDI table on some undocumented offset from its begninning.
    The alogrithm is the following:
        0. Obtain from debugging symbols information the relative addresses of win32k!SpTextOut, win32k!SpLineTo, win32k!SpBitBlt, etc.
        1. Set current DCOBJ offset to 0.
        2. Assume that pointer at the current offset of DCOBJ structure is a pointer to DDI table.
            a. Check if this pointer is a 'valid' pointer, i.e. points somewhere inside kernel's address space.
            b. Check that this pointer points to existing memory, i.e. perform virtual to physical address translation.
        3. If the address is 'valid' and VA=>PA translates successfully, then go to p.4, else increment DCOBJ offset by a pointer suze and proceed with p.2.
        4. Take the win32k.sys!Sp* functions' relative adresses, normalize them by kernel image base and compare them by appropriate indices (from public DDI interface)
           with the addresses from alleged DDI table. Alleged addresses are, of course, thoroughly validated as in p.2.
        5. If we have a match for at least two functions inside DDI table, then we assume this is indeed a DDI table.
           Now you can take an offset and test it within the product.

    For more on DDI interface take a look at:
        https://msdn.microsoft.com/en-us/library/windows/hardware/ff557277(v=vs.85).aspx

-----------------------
Implementation details:
    UM component (./src/um/um.cpp):
        1. Extract dbghelp.dll and symsrv.dll to the current directory from dtfinder.exe's resources. See um.cpp!main().
        2. Try to download debugging symbols information from Microsoft Symbols Server for particular win32k.sys and gdi32.dll on the current machine.
        3. Fetch from PDB files the relative addresses of win32k!SpTextOut, win32k!SpLineTo, win32k!SpBitBlt, etc. functions. See um.cpp!FillDDIPointers().
        4. Fetch from PDB files the address of gdi32!pGdiSharedHandleTable and use some GDI handle (its index) to obtain the DCOBJ address in the kernel. See um.cpp!GetKernelDcObjPointer().
        5. Extract km32.sys or km64.sys helper driver from resources depending on the platform and install this driver. See um.cpp!InstallDriver().
        6. Pass to the driver the context info buffer with obtained earlier pointers to win32k!Sp* functions and the address of DCOBJ structure in the kernel. See in um.cpp!main() the call to DeviceIoControl().
        7. Wait for the result returned in a buffer by the driver and display it to the console.
        8. Uninstall the driver.
    KM component (./src/km/km.c):
        1. UM component at p.6 passes control to the code in km.c!TmplDispatchDeviceControl().
        2. Obtain image base of win32k.sys in kernel's address space and normalize win32k!Sp* functions relative pointers by adding the base to RVAs. See km.c!NormalizeDDIpointers().
        3. Perform the actual scan of kernel addresses to find a match with win32k!Sp* functions. See km.c!ScanDCOBJ(), km.c!ScanPDEV() and km.c!ScanDDITable().
        4. The actual decision whether DDI table is found, is made in km.c!IsDDITable() function.
           The Virtual Address to Physical Address translation is made in km.c!IsAddressValid() function. 
           Note that 32-bit, 64-bit paging is handled and Physical Address Extention (PAE) is also handled properly.

    Useful links on VA to PA translation that I really enjoyed during this development are:
        http://technet.microsoft.com/en-us/library/cc736309(WS.10).aspx
        http://blogs.msdn.com/b/ntdebugging/archive/2010/02/05/understanding-pte-part-1-let-s-get-physical.aspx
