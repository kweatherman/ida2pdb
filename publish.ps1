#requires -Version 5.1
<#
	Packages a local ida2pdb Release DLL and optionally creates a GitHub Release.
	Synchronizes ida-plugin.json with MY_VERSION in StdAfx.h and includes it in the ZIP.
	
	-Commit stages all non-ignored changes, commits them, tags the release, and pushes
	the current branch and version tag to GitRemote (origin by default).
	-Upload creates a GitHub Release. Add -Draft to keep that release unpublished.
	-Upload alone does not commit, tag, or push, and does not update an existing release.
	-Draft requires -Upload; -Upload does not require -Draft.

	.EXAMPLE
	.\publish.ps1
	Updates the manifest version and packages the existing Release DLL locally.
	Does not rebuild the DLL or upload anything.

	.EXAMPLE
	.\publish.ps1 -Rebuild
	Updates the manifest version, rebuilds Release|x64, and packages the new DLL locally.
	Does not upload anything.

	.EXAMPLE
	.\publish.ps1 -Commit
	Packages the existing Release DLL, synchronizes the manifest, stages all non-ignored
	changes, commits as "Release <version>", creates v<version>, and pushes to origin.
	Does not create a GitHub Release. Use after building in Visual Studio.

	.EXAMPLE
	.\publish.ps1 -Rebuild -Commit -Upload -Draft -NotesFile .\release-notes.md
	Updates the manifest version, rebuilds Release|x64, packages the DLL and manifest,
	commits and pushes the current branch and version tag, then uploads the ZIP
	to a new unpublished GitHub draft release. Uses the specified
	Markdown file as the release notes; publish the draft on GitHub when ready.
	Requires Git push access and gh authentication. release/ must be gitignored.
	Without -Commit, commit and push the matching tag yourself before -Upload.
#>
[CmdletBinding()]
param(
    [switch]$Rebuild,
    [switch]$Commit,
    [switch]$Upload,
    [switch]$Draft,
    [switch]$VersionedZip,
    [string]$Repository = 'kweatherman/ida2pdb',
    [string]$GitRemote = 'origin',
    [string]$NotesFile,
    [string]$VersionHeader = 'StdAfx.h',
    [string]$DllPath = 'x64\Release\ida2pdb.dll',
    [string]$ProjectPath = 'ida2pdb.vcxproj'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = $PSScriptRoot

function Resolve-ProjectPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $RepoRoot $Path)
}

function Require-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is missing: $Path"
    }
}

if ($Draft -and -not $Upload) { throw '-Draft requires -Upload.' }

$Header = Resolve-ProjectPath $VersionHeader
Require-File $Header
$HeaderText = Get-Content -LiteralPath $Header -Raw
# Strip comments, then accept exactly one numeric MY_VERSION definition.
$HeaderText = [regex]::Replace($HeaderText, '(?s)/\*.*?\*/|//[^\r\n]*', '')
$VersionPattern = '(?m)^\s*#\s*define\s+MY_VERSION\s+MAKE_SEMANTIC_VERSION\s*\(\s*[^,()\r\n]+\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)\s*$'
$Definitions = [regex]::Matches($HeaderText, $VersionPattern)
if ($Definitions.Count -ne 1) {
    throw 'Expected one MY_VERSION MAKE_SEMANTIC_VERSION(status, major, minor, patch) definition.'
}
$Definition = $Definitions[0]
$Version = '{0}.{1}.{2}' -f ([int]$Definition.Groups[1].Value), ([int]$Definition.Groups[2].Value), ([int]$Definition.Groups[3].Value)

# Keep the repository manifest and packaged metadata aligned with MY_VERSION.
# Leave the file untouched when its version already matches (important for -Upload).
$ManifestPath = Join-Path $RepoRoot 'ida-plugin.json'
Require-File $ManifestPath
$ManifestText = [IO.File]::ReadAllText($ManifestPath)
try {
    $Manifest = $ManifestText | ConvertFrom-Json
} catch {
    throw "Invalid JSON in ${ManifestPath}: $($_.Exception.Message)"
}
if ($null -eq $Manifest -or
    $null -eq $Manifest.PSObject.Properties['plugin'] -or
    $null -eq $Manifest.plugin -or
    $null -eq $Manifest.plugin.PSObject.Properties['version'] -or
    $Manifest.plugin.version -isnot [string]) {
    throw 'ida-plugin.json must contain a plugin object with a string version property.'
}
if ($Manifest.plugin.version -cne $Version) {
    $Manifest.plugin.version = $Version
    $UpdatedManifestText = ($Manifest | ConvertTo-Json -Depth 32) + [Environment]::NewLine
    [IO.File]::WriteAllText($ManifestPath, $UpdatedManifestText, [Text.UTF8Encoding]::new($false))
    Write-Host "Updated ida-plugin.json version to $Version"
}

$Tag = "v$Version"
$PackageName = "ida2pdb-$Version"
$ReleaseRoot = Join-Path $RepoRoot 'release'
$PackageDirectory = Join-Path $ReleaseRoot $PackageName
$ArchiveName = 'ida2pdb.zip'
if ($VersionedZip) { $ArchiveName = "$PackageName.zip" }
$ArchivePath = Join-Path $ReleaseRoot $ArchiveName
$SourceDll = Resolve-ProjectPath $DllPath
$Resources = Join-Path $RepoRoot 'res'

$Documents = @('LICENSES.txt', 'README.md', 'ida-plugin.json')
foreach ($Name in $Documents) { Require-File (Join-Path $RepoRoot $Name) }
if (-not (Test-Path -LiteralPath $Resources -PathType Container)) {
    throw "README resource directory is missing: $Resources"
}

if ($Rebuild) {
    $Project = Resolve-ProjectPath $ProjectPath
    Require-File $Project
    $MSBuildCommand = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($null -ne $MSBuildCommand) {
        $MSBuild = $MSBuildCommand.Source
    } else {
        $Vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        Require-File $Vswhere
        $BuildTools = @(& $Vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe')
        if ($LASTEXITCODE -ne 0 -or $BuildTools.Count -eq 0) { throw 'MSBuild was not found.' }
        $MSBuild = $BuildTools[0]
    }
    & $MSBuild $Project /t:Rebuild /m /p:Configuration=Release /p:Platform=x64 /nologo
    if ($LASTEXITCODE -ne 0) { throw "Release build failed: exit code $LASTEXITCODE" }
}
Require-File $SourceDll
if ((Get-Item -LiteralPath $SourceDll).Length -eq 0) { throw 'The Release DLL is empty.' }

# Build the new package and ZIP before replacing the previous local outputs.
New-Item -ItemType Directory -Path $ReleaseRoot -Force | Out-Null
$WorkDirectory = Join-Path $ReleaseRoot ('.publish-' + [guid]::NewGuid().ToString('N'))
$StagedPackage = Join-Path $WorkDirectory $PackageName
$StagedArchive = Join-Path $WorkDirectory $ArchiveName
New-Item -ItemType Directory -Path $StagedPackage -Force | Out-Null
try {
    Copy-Item -LiteralPath $SourceDll -Destination (Join-Path $StagedPackage 'ida2pdb.dll')
    foreach ($Name in $Documents) {
        Copy-Item -LiteralPath (Join-Path $RepoRoot $Name) -Destination $StagedPackage
    }
    Copy-Item -LiteralPath $Resources -Destination (Join-Path $StagedPackage 'res') -Recurse
    $SourceHash = (Get-FileHash -LiteralPath $SourceDll -Algorithm SHA256).Hash
    $CopiedHash = (Get-FileHash -LiteralPath (Join-Path $StagedPackage 'ida2pdb.dll') -Algorithm SHA256).Hash
    if ($SourceHash -ne $CopiedHash) { throw 'The packaged DLL does not match the Release build.' }
    Compress-Archive -LiteralPath $StagedPackage -DestinationPath $StagedArchive -CompressionLevel Optimal

    # Retain the previous same-version directory if moving the replacement fails.
    $BackupDirectory = Join-Path $WorkDirectory 'previous-package'
    if (Test-Path -LiteralPath $PackageDirectory) {
        Move-Item -LiteralPath $PackageDirectory -Destination $BackupDirectory
    }
    try {
        Move-Item -LiteralPath $StagedPackage -Destination $PackageDirectory
    } catch {
        if (Test-Path -LiteralPath $BackupDirectory) {
            Move-Item -LiteralPath $BackupDirectory -Destination $PackageDirectory
        }
        throw
    }
    # Both paths are on the same volume; replace an existing ZIP atomically.
    if (Test-Path -LiteralPath $ArchivePath -PathType Leaf) {
        [IO.File]::Replace($StagedArchive, $ArchivePath, [NullString]::Value)
    } else {
        [IO.File]::Move($StagedArchive, $ArchivePath)
    }
} finally {
    if (Test-Path -LiteralPath $WorkDirectory) {
        Remove-Item -LiteralPath $WorkDirectory -Recurse -Force
    }
}

Write-Host "Package: $PackageDirectory"
Write-Host "Archive: $ArchivePath"
Write-Host "DLL SHA256: $CopiedHash"

if ($Commit -or $Upload) {
    Get-Command git -ErrorAction Stop | Out-Null
}
if ($Upload) {
    Get-Command gh -ErrorAction Stop | Out-Null
    if ($NotesFile) {
        $NotesFile = Resolve-ProjectPath $NotesFile
        Require-File $NotesFile
    }
}

if ($Commit) {
    Push-Location $RepoRoot
    try {
        $GitRoot = (& git rev-parse --show-toplevel | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'The script must run from a Git repository.' }
        if ([IO.Path]::GetFullPath($GitRoot) -ne [IO.Path]::GetFullPath($RepoRoot)) {
            throw 'publish.ps1 must be in the Git repository root when using -Commit.'
        }
        $Branch = (& git symbolic-ref --quiet --short HEAD | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $Branch) { throw '-Commit requires a checked-out branch, not detached HEAD.' }
        & git remote get-url $GitRemote | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Git remote '$GitRemote' was not found." }
        & git check-ignore --quiet -- release/
        if ($LASTEXITCODE -ne 0) { throw 'release/ must be gitignored before using -Commit.' }
        $TrackedReleaseFiles = @(& git ls-files -- release/)
        if ($LASTEXITCODE -ne 0) { throw 'Could not check tracked release files.' }
        if ($TrackedReleaseFiles.Count -ne 0) { throw 'release/ contains tracked files; remove them from Git tracking before using -Commit.' }

        $HeadCommit = (& git rev-parse HEAD | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw '-Commit requires an existing initial commit.' }
        $Changes = @(& git status --porcelain)
        if ($LASTEXITCODE -ne 0) { throw 'Could not read git status.' }
        $LocalTags = @(& git tag --list $Tag)
        if ($LASTEXITCODE -ne 0) { throw 'Could not check the version tag.' }
        $RemoteTags = @(& git ls-remote --tags $GitRemote "refs/tags/$Tag" "refs/tags/$Tag^{}")
        if ($LASTEXITCODE -ne 0) { throw "Could not check tags on '$GitRemote'; no commit was made." }

        # Allow a clean retry after a push/upload failure, but never move a release tag.
        if ($LocalTags.Count -ne 0 -or $RemoteTags.Count -ne 0) {
            if ($Changes.Count -ne 0) { throw "Tag $Tag already exists. Bump MY_VERSION before committing new release changes." }
            if ($LocalTags.Count -ne 0) {
                $LocalTagCommit = (& git rev-parse "refs/tags/$Tag^{commit}" | Out-String).Trim()
                if ($LASTEXITCODE -ne 0 -or $LocalTagCommit -ne $HeadCommit) { throw "Local tag $Tag does not point to HEAD." }
            }
            if ($RemoteTags.Count -ne 0) {
                $RemoteTagCommit = ($RemoteTags[-1] -split '\s+')[0]
                if ($RemoteTagCommit -ne $HeadCommit) { throw "Remote tag $Tag does not point to HEAD." }
            }
        }

        & git add -A
        if ($LASTEXITCODE -ne 0) { throw 'Could not stage project changes.' }
        & git diff --cached --quiet
        $DiffExit = $LASTEXITCODE
        if ($DiffExit -eq 1) {
            & git commit -m "Release $Version"
            if ($LASTEXITCODE -ne 0) { throw 'Release commit failed; staged changes were left intact.' }
        } elseif ($DiffExit -ne 0) {
            throw 'Could not inspect staged changes.'
        } else {
            Write-Host 'No changes to commit; using the current HEAD.'
        }
        if ($LocalTags.Count -eq 0) {
            & git tag $Tag
            if ($LASTEXITCODE -ne 0) { throw "Could not create tag $Tag." }
        }
        & git push $GitRemote "HEAD:refs/heads/$Branch"
        if ($LASTEXITCODE -ne 0) { throw "Branch push failed. The local commit/tag remain; rerun -Commit after resolving the push failure." }
        & git push $GitRemote "refs/tags/${Tag}:refs/tags/$Tag"
        if ($LASTEXITCODE -ne 0) { throw "Tag push failed. The local commit/tag remain; rerun -Commit after resolving the push failure." }
        Write-Host "Pushed branch $Branch and tag $Tag to $GitRemote"
    } finally {
        Pop-Location
    }
}

if ($Upload) {
    Push-Location $RepoRoot
    try {
        $Changes = @(& git status --porcelain)
        if ($LASTEXITCODE -ne 0) { throw 'Could not read git status.' }
        if ($Changes.Count -ne 0) { throw 'Commit project changes before uploading a release; release/ must be gitignored.' }
        $HeadCommit = (& git rev-parse HEAD | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Could not determine HEAD.' }
        # Resolve the remote tag to a commit, including annotated tags.
        $RemoteCommit = (& gh api "repos/$Repository/commits/$Tag" --jq '.sha' | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Push tag $Tag to $Repository before uploading." }
        if ($RemoteCommit -ne $HeadCommit) { throw "Remote tag $Tag does not point to the current HEAD." }
        $GhArguments = @('release', 'create', $Tag, $ArchivePath, '--repo', $Repository, '--verify-tag', '--title', "ida2pdb $Version")
        if ($NotesFile) { $GhArguments += @('--notes-file', $NotesFile) }
        else { $GhArguments += '--generate-notes' }
        if ($Draft) { $GhArguments += '--draft' }
        & gh @GhArguments
        if ($LASTEXITCODE -ne 0) { throw "GitHub Release creation failed. Local package remains at $ArchivePath" }
    } finally {
        Pop-Location
    }
}
