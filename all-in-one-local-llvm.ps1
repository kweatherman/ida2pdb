#requires -Version 5.1
<#
	Download and build the local LLVM PDB SDK.
	
	.DESCRIPTION
	Download the LLVM source build files with: .\all-in-one-local-llvm.ps1 -Download
	Then VS2026 build the source with:  .\all-in-one-local-llvm.ps1 -Build

	The default destination is the llvm folder beside this script, regardless
	of the current directory. Use the same -Root for both stages if overridden.

	Prerequisites (installed separately; this script does not install them):
	  * Windows x64, Windows PowerShell 5.1 or PowerShell 7.
	  * Git for Windows 2.25+ for the download and source checks.
	  * Visual Studio 2026 minimal Community or Build Tools with Desktop development
		with C++, the Windows SDK, and C++ CMake tools for Windows (CMake/Ninja).
	  * Python 3.8+; CMake 3.20+ (a newer CMake is fine).

	Official installers:
	  https://git-scm.com/downloads/win
	  https://visualstudio.microsoft.com/downloads/
	  https://www.python.org/downloads/windows/
	  https://cmake.org/download/

	The build is x64 Release, static LLVM component .lib files, and /MD CRT.
	It builds LLVMDebugInfoPDB and its dependencies, plus llvm-config,
	llvm-pdbutil, and llvm-readobj. LLVM's necessary build generators are also
	built as dependencies. No Clang, LLDB, runtimes, tests, examples, benchmarks,
	or documentation are built. Optional external libraries, including zlib,
	zstd, libxml2, and DIA, are disabled; no separate dependency build is needed.

	Prepared project layout:
	  llvm\src\                  pinned source checkout
	  llvm\build\Release-MD\     incremental build tree
	  llvm\include\              source + generated headers
	  llvm\lib\                  debuginfopdb library dependency list
	  llvm\bin\                  the three diagnostic tools
	  llvm\licenses\             upstream license/notice files
	  llvm\SDK_CONFIG.txt         version, commit, paths, link dependencies
	  llvm\logs\                 stage transcripts

	Keep /llvm/ and /LocalData/ in .gitignore. This script does not edit project
	files, package a plugin, or replace the project's combined LICENSES.txt.
	Use Release /MD and _ITERATOR_DEBUG_LEVEL=0 when linking these libraries.
	These Release archives are not Debug /MDd libraries.

	Build reruns are incremental. Existing prepared SDK directories are backed
	up before replacement; failures during replacement attempt to restore them.
	Backups remain under llvm\.sdk-backup-* for manual removal after verification.
	Neither stage deletes an existing source checkout or build tree.
	.EXAMPLE
	.\all-in-one-local-llvm.ps1 -Build -Jobs 8
	.EXAMPLE
	.\all-in-one-local-llvm.ps1 -Download -Root 'D:\ida2pdb-llvm'
	.\all-in-one-local-llvm.ps1 -Build -Root 'D:\ida2pdb-llvm'
#>
[CmdletBinding(DefaultParameterSetName = 'Download')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Download')]
    [switch]$Download,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')]
    [switch]$Build,
    [string]$Root = '',
    [Parameter(ParameterSetName = 'Build')]
    [ValidateRange(1, 64)][int]$Jobs = 8,
    [Parameter(ParameterSetName = 'Build')]
    [string]$VsPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Run this script in 64-bit PowerShell on Windows x64.'
}
if (($PSCmdlet.ParameterSetName -eq 'Download' -and -not $Download) -or
    ($PSCmdlet.ParameterSetName -eq 'Build' -and -not $Build)) {
    throw 'Specify either -Download or -Build, without :$false.'
}
$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDirectory)) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Join-Path $scriptDirectory 'llvm' }
$Root = [IO.Path]::GetFullPath($Root)
$source = Join-Path $Root 'src'
$buildDirectory = Join-Path $Root 'build\Release-MD'
$llvmVersion = '23.1.2'
$tag = 'llvmorg-' + $llvmVersion
$repository = 'https://github.com/llvm/llvm-project.git'

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    Write-Host ('> ' + $Program + ' ' + ($Arguments -join ' '))
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "${Program} failed: exit code $LASTEXITCODE." }
}

function Find-Tool {
    param([string]$Name, [string[]]$Candidates = @())
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { return $command.Source }
    foreach ($path in $Candidates) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }
    throw "Missing $Name. Install the prerequisites listed in this script's help."
}

function Check-Source {
    param([string]$Path, [string]$Git)
    if (-not (Test-Path -LiteralPath (Join-Path $Path '.git'))) {
        throw "Expected a Git checkout at $Path. Existing files were not changed."
    }
    $head = (@(Invoke-Checked $Git @('-C', $Path, 'rev-parse', 'HEAD')) -join '').Trim()
    $pin = (@(Invoke-Checked $Git @('-C', $Path, 'rev-parse', "$tag^{commit}")) -join '').Trim()
    if ($head -ne $pin) { throw "Source must be at $tag; this script will not reset your checkout." }
    $dirty = @(Invoke-Checked $Git @('-C', $Path, 'status', '--porcelain', '--untracked-files=no'))
    if ($dirty.Count -ne 0) { throw 'LLVM source has tracked modifications. Existing checkout was not changed.' }
    foreach ($relative in @('llvm\CMakeLists.txt', 'llvm\include\llvm\BinaryFormat\COFF.h')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Path $relative) -PathType Leaf)) {
            throw "Source checkout is incomplete: $relative. Rerun -Download for a new checkout."
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Path 'cmake') -PathType Container)) {
        throw 'The shared cmake source directory is missing. Source checkout is incomplete.'
    }
    return $head
}

function Initialize-BuildTools {
    if ([string]::IsNullOrWhiteSpace($VsPath)) {
        $vswhere = Find-Tool 'vswhere.exe' @((Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'))
        $found = @(Invoke-Checked $vswhere @('-latest', '-products', '*', '-requires',
            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'))
        if ($found.Count -ne 1 -or [string]::IsNullOrWhiteSpace($found[0])) {
            throw 'No Visual Studio installation with x64 C++ tools was found.'
        }
        $VsPath = $found[0].Trim()
    }
    $VsPath = [IO.Path]::GetFullPath($VsPath)
    $module = Join-Path $VsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (-not (Test-Path -LiteralPath $module -PathType Leaf)) { throw "Developer PowerShell module missing: $module" }
    Import-Module $module
    $null = Enter-VsDevShell -VsInstallPath $VsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
    if ($env:VSCMD_ARG_TGT_ARCH -ne 'x64' -or $env:VSCMD_ARG_HOST_ARCH -ne 'x64') {
        throw 'Visual Studio did not initialize the x64 host and target compiler.'
    }
    $cmake = Find-Tool 'cmake.exe' @(
        (Join-Path $VsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'),
        (Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe'))
    $ninja = Find-Tool 'ninja.exe' @((Join-Path $VsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'))
    $compiler = Find-Tool 'cl.exe'
    $dumpbin = Find-Tool 'dumpbin.exe'
    $null = Find-Tool 'link.exe'
    $null = Find-Tool 'rc.exe'
    $null = Find-Tool 'robocopy.exe'
    $launcher = Get-Command 'py.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $pythonArguments = @('-c', 'import json,sys; print(json.dumps({"version":list(sys.version_info[:3]),"executable":sys.executable}))')
    if ($null -ne $launcher) {
        $pythonInfo = @(Invoke-Checked $launcher.Source (@('-3') + $pythonArguments))
    } else {
        $pythonInfo = @(Invoke-Checked (Find-Tool 'python.exe') $pythonArguments)
    }
    $pythonInfo = ($pythonInfo -join '') | ConvertFrom-Json
    if ($pythonInfo.version[0] -lt 3 -or ($pythonInfo.version[0] -eq 3 -and $pythonInfo.version[1] -lt 8)) {
        throw 'Python 3.8 or newer is required.'
    }
    $cmakeOutput = (@(Invoke-Checked $cmake @('--version')) -join "`n")
    if ($cmakeOutput -notmatch 'cmake version (\d+\.\d+\.\d+)') { throw 'Cannot read the CMake version.' }
    if ([version]$Matches[1] -lt [version]'3.20.0') { throw 'CMake 3.20 or newer is required.' }
    Invoke-Checked $ninja @('--version') | Out-Host
    return @{ CMake = $cmake; Ninja = $ninja; Compiler = $compiler; Python = $pythonInfo.executable; Dumpbin = $dumpbin }
}

function Copy-Headers {
    param([string]$From, [string]$To)
    # Generated headers must overlay source headers regardless of timestamps.
    & robocopy.exe $From $To /E /IS /IT /COPY:DAT /R:2 /W:1 /NFL /NDL /NP | Out-Host
    if ($LASTEXITCODE -ge 8) { throw "Header copy failed: $From" }
}

function Prepare-Sdk {
    param([hashtable]$Tools, [string]$Commit)
    $config = Join-Path $buildDirectory 'bin\llvm-config.exe'
    $actualVersion = (@(Invoke-Checked $config @('--version')) -join '').Trim()
    if ($actualVersion -ne $llvmVersion) { throw "Expected LLVM $llvmVersion; found $actualVersion." }
    $hostTarget = (@(Invoke-Checked $config @('--host-target')) -join '').Trim()
    if ($hostTarget -notmatch '^x86_64-.*windows-msvc') { throw "Unexpected LLVM host: $hostTarget" }
    $libraryOutput = @(Invoke-Checked $config @('--link-static', '--libnames', 'debuginfopdb'))
    $systemOutput = @(Invoke-Checked $config @('--link-static', '--system-libs', 'debuginfopdb'))
    $libraries = @(($libraryOutput -join ' ') -split '\s+' | Where-Object { $_ })
    $systemLibraries = @(($systemOutput -join ' ') -split '\s+' | Where-Object { $_ })
    if ($libraries.Count -eq 0) { throw 'llvm-config reported no PDB libraries.' }
    foreach ($name in $libraries) {
        if ($name -notmatch '^LLVM[A-Za-z0-9_]+\.lib$' -or
            -not (Test-Path -LiteralPath (Join-Path $buildDirectory "lib\$name") -PathType Leaf)) {
            throw "Missing or unexpected LLVM component archive: $name"
        }
    }
    foreach ($name in $systemLibraries) {
        if ($name -notmatch '^[A-Za-z0-9_]+\.lib$' -or $name -match '(?i)^(zs|zlib.*|zstd.*|.*xml2.*)\.lib$') {
            throw "Unexpected external library/path: $name. SDK was not replaced."
        }
    }
    $directives = (@(Invoke-Checked $Tools.Dumpbin @('/directives', (Join-Path $buildDirectory 'lib\LLVMSupport.lib'))) -join "`n")
    $runtimes = @([regex]::Matches($directives, 'RuntimeLibrary=([A-Za-z0-9_]+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    $iterators = @([regex]::Matches($directives, '_ITERATOR_DEBUG_LEVEL=(\d+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    if ($runtimes.Count -ne 1 -or $runtimes[0] -ne 'MD_DynamicRelease' -or
        $iterators.Count -ne 1 -or $iterators[0] -ne '0') {
        throw 'LLVMSupport.lib did not pass the Release /MD and iterator-level-0 check.'
    }
    $token = [Guid]::NewGuid().ToString('N')
    $stage = Join-Path $Root ('.sdk-stage-' + $token)
    $backup = Join-Path $Root ('.sdk-backup-' + $token)
    $directories = @('include', 'lib', 'bin', 'licenses')
    $entries = $directories + @('LLVM_LICENSE.TXT', 'SDK_CONFIG.txt')
    $saved = @(); $published = @()
    try {
        foreach ($name in $directories) { $null = New-Item -ItemType Directory -Path (Join-Path $stage $name) -Force }
        Copy-Headers (Join-Path $source 'llvm\include') (Join-Path $stage 'include')
        Copy-Headers (Join-Path $buildDirectory 'include') (Join-Path $stage 'include')
        foreach ($name in $libraries) {
            Copy-Item -LiteralPath (Join-Path $buildDirectory "lib\$name") -Destination (Join-Path $stage 'lib')
        }
        foreach ($name in @('llvm-config.exe', 'llvm-pdbutil.exe', 'llvm-readobj.exe')) {
            Copy-Item -LiteralPath (Join-Path $buildDirectory "bin\$name") -Destination (Join-Path $stage 'bin')
        }
        foreach ($name in @('llvm\BinaryFormat\COFF.h', 'llvm\Config\llvm-config.h', 'llvm\DebugInfo\PDB\Native\PDBFileBuilder.h')) {
            if (-not (Test-Path -LiteralPath (Join-Path $stage "include\$name") -PathType Leaf)) {
                throw "Staged header missing: $name"
            }
        }
        # Preserve licenses/notices from the source directories actually downloaded.
        $notices = @(Get-ChildItem -LiteralPath $source -File -Recurse -Force |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' -and $_.Name -match '^(?i:LICENSE(?:\..*)?|NOTICE(?:\..*)?|COPYING(?:\..*)?)$' })
        foreach ($notice in $notices) {
            $relative = $notice.FullName.Substring($source.Length).TrimStart([char[]]'\/')
            $destination = Join-Path (Join-Path $stage 'licenses') $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
            Copy-Item -LiteralPath $notice.FullName -Destination $destination
        }
        $license = Join-Path $source 'llvm\LICENSE.TXT'
        if (-not (Test-Path -LiteralPath $license -PathType Leaf)) { $license = Join-Path $source 'LICENSE.TXT' }
        Copy-Item -LiteralPath $license -Destination (Join-Path $stage 'LLVM_LICENSE.TXT')
        $manifest = @(
            "LLVM $llvmVersion PDB SDK; x64 Release; static LLVM libraries; /MD CRT",
            "Source tag: $tag", "Source commit: $Commit", "Source: $source", "Build: $buildDirectory",
            "Prepared: $(Get-Date -Format o)", "Host: $hostTarget", 'Iterator debug level: 0',
            ('LLVM libraries: ' + ($libraries -join ';')), ('System libraries: ' + ($systemLibraries -join ';')),
            'Optional external libraries disabled; no zlib/zstd/libxml2/DIA dependency package.',
            'Use upstream notices when distributing incorporated code; project LICENSES.txt was not edited.'
        )
        Set-Content -LiteralPath (Join-Path $stage 'SDK_CONFIG.txt') -Value $manifest -Encoding UTF8
        $null = New-Item -ItemType Directory -Path $backup
        try {
            foreach ($name in $entries) {
                $target = Join-Path $Root $name
                if (Test-Path -LiteralPath $target) {
                    Move-Item -LiteralPath $target -Destination (Join-Path $backup $name)
                    $saved += $name
                }
            }
            foreach ($name in $entries) {
                Move-Item -LiteralPath (Join-Path $stage $name) -Destination (Join-Path $Root $name)
                $published += $name
            }
        } catch {
            foreach ($name in $published) { Move-Item -LiteralPath (Join-Path $Root $name) -Destination (Join-Path $stage $name) }
            foreach ($name in $saved) { Move-Item -LiteralPath (Join-Path $backup $name) -Destination (Join-Path $Root $name) }
            throw
        }
        if ($saved.Count -eq 0) { Remove-Item -LiteralPath $backup } else { Write-Host "Previous SDK retained at $backup" }
        Write-Host "Ready: $Root\include, $Root\lib, $Root\bin"
        Write-Host ('Additional Dependencies: ' + (($libraries + $systemLibraries) -join ';'))
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}

Write-Host "ida2pdb local LLVM setup: $llvmVersion"
Write-Host "Root: $Root"
if ($Download) {
    Write-Host "DOWNLOAD: fetch the official $tag source into $source."
    Write-Host 'Uses a shallow, filtered Git checkout of LLVM, shared CMake, and third-party source directories.'
    Write-Host 'Skips LLVM test, unit-test, documentation, example, and benchmark source directories.'
    Write-Host 'No compilation, optional dependency downloads, or prepared SDK changes occur in this stage.'
    Write-Host 'An existing clean checkout at the correct tag is reused without fetching or resetting it.'
} else {
    Write-Host "BUILD: use existing source to build x64 Release /MD with $Jobs parallel jobs."
    Write-Host 'Initializes the Visual Studio x64 environment and builds the PDB libraries and three tools.'
    Write-Host "Build directory: $buildDirectory"
    Write-Host 'Stages headers, component libraries, tools, and notices in the top-level llvm directories.'
    Write-Host 'Existing prepared SDK directories are backed up before replacement. No source download is performed.'
}
$null = Read-Host 'Press Enter to continue, or press Ctrl+C to exit'

$git = Find-Tool 'git.exe'
$gitVersion = (@(Invoke-Checked $git @('--version')) -join '')
if ($gitVersion -notmatch 'git version (\d+\.\d+\.\d+)' -or [version]$Matches[1] -lt [version]'2.25.0') {
    throw 'Git 2.25 or newer is required.'
}
$null = New-Item -ItemType Directory -Path (Join-Path $Root 'logs') -Force
$log = Join-Path $Root ('logs\' + $PSCmdlet.ParameterSetName.ToLowerInvariant() + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
Start-Transcript -Path $log | Out-Null
try {
    if ($Download) {
        if (-not (Test-Path -LiteralPath $source)) {
            $temporarySource = Join-Path $Root ('.src-download-' + [Guid]::NewGuid().ToString('N'))
            # Leave a failed/interrupted download for inspection; never publish it as src.
            Write-Host "Download staging directory: $temporarySource"
            Invoke-Checked $git @('clone', '--config', 'core.longpaths=true', '--depth', '1', '--filter=blob:none',
                '--sparse', '--branch', $tag, $repository, $temporarySource) | Out-Host
            Invoke-Checked $git @('-C', $temporarySource, 'sparse-checkout', 'set', '--no-cone',
                '/*', '!/*/', '/llvm/', '/cmake/', '/third-party/',
                '!/llvm/test/', '!/llvm/unittests/', '!/llvm/docs/', '!/llvm/examples/', '!/llvm/benchmarks/') | Out-Host
            $null = Check-Source $temporarySource $git
            Move-Item -LiteralPath $temporarySource -Destination $source
        }
        $commit = Check-Source $source $git
        Write-Host "Source ready: $tag ($commit). Next: .\all-in-one-local-llvm.ps1 -Build"
        if ($Root -ne (Join-Path $scriptDirectory 'llvm')) { Write-Host "Use the same -Root '$Root' for -Build." }
    } else {
        $commit = Check-Source $source $git
        $tools = Initialize-BuildTools
        $cachePath = Join-Path $buildDirectory 'CMakeCache.txt'
        if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
            $cache = Get-Content -LiteralPath $cachePath -Raw
            $expectedSource = (Join-Path $source 'llvm').Replace('\', '/').TrimEnd('/')
            $expectedBuild = $buildDirectory.Replace('\', '/').TrimEnd('/')
            foreach ($entry in @(@('CMAKE_HOME_DIRECTORY', $expectedSource), @('CMAKE_CACHEFILE_DIR', $expectedBuild))) {
                if ($cache -notmatch ("(?m)^" + $entry[0] + ':[^=\r\n]+=(.+)\r?$') -or
                    $Matches[1].Trim().Replace('\', '/').TrimEnd('/') -ne $entry[1]) {
                    throw "CMake cache belongs to another location. Move only '$buildDirectory' aside, then rerun -Build. Source and prepared SDK are unchanged."
                }
            }
        }
        $configureArguments = @(
            '-S', (Join-Path $source 'llvm'), '-B', $buildDirectory, '-G', 'Ninja',
            '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL',
            ('-DCMAKE_C_COMPILER:FILEPATH=' + $tools.Compiler.Replace('\', '/')),
            ('-DCMAKE_CXX_COMPILER:FILEPATH=' + $tools.Compiler.Replace('\', '/')),
            ('-DCMAKE_MAKE_PROGRAM:FILEPATH=' + $tools.Ninja.Replace('\', '/')),
            ('-DPython3_EXECUTABLE:FILEPATH=' + $tools.Python.Replace('\', '/')),
            '-DBUILD_SHARED_LIBS=OFF', '-DLLVM_BUILD_LLVM_DYLIB=OFF', '-DLLVM_LINK_LLVM_DYLIB=OFF',
            '-DLLVM_ENABLE_LTO=OFF', '-DLLVM_ENABLE_PROJECTS=', '-DLLVM_ENABLE_RUNTIMES=',
            '-DLLVM_ENABLE_BINDINGS=OFF', '-DLLVM_EXTERNAL_PROJECTS=',
            '-DLLVM_TARGETS_TO_BUILD=X86', '-DLLVM_INCLUDE_TESTS=OFF', '-DLLVM_INCLUDE_EXAMPLES=OFF',
            '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_DOCS=OFF', '-DLLVM_BUILD_TOOLS=OFF',
            '-DLLVM_ENABLE_ASSERTIONS=OFF', '-DLLVM_ENABLE_EH=OFF', '-DLLVM_ENABLE_RTTI=OFF',
            '-DLLVM_ENABLE_DIA_SDK=OFF', '-DLLVM_ENABLE_ZLIB=OFF', '-DLLVM_ENABLE_ZSTD=OFF',
            '-DLLVM_ENABLE_LIBXML2=OFF', '-DLLVM_ENABLE_CURL=OFF', '-DLLVM_ENABLE_ICU=OFF',
            '-DLLVM_ENABLE_WINDOWS_ICU=OFF', '-DLLVM_ENABLE_ICONV=OFF', '-DLLVM_ENABLE_HTTPLIB=OFF',
            '-DLLVM_ENABLE_RPMALLOC=OFF', '-DLLVM_ENABLE_LIBEDIT=OFF', '-DLLVM_ENABLE_LIBPFM=OFF',
            '-DLLVM_ENABLE_FFI=OFF'
        )
        Invoke-Checked $tools.CMake $configureArguments | Out-Host
        Invoke-Checked $tools.CMake @('--build', $buildDirectory, '--target', 'LLVMDebugInfoPDB',
            'llvm-config', 'llvm-pdbutil', 'llvm-readobj', '--parallel', "$Jobs") | Out-Host
        Prepare-Sdk $tools $commit
        Write-Host 'Completed. Configure Release /MD, iterator level 0, include llvm\include, and link llvm\lib.'
    }
} finally {
    Stop-Transcript | Out-Null
    Write-Host "Log: $log"
}
