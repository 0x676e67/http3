param(
    [switch]$Execute,
    [string]$Registry = "crates-io",
    [string]$Token,
    [int]$DelaySeconds = 30
)

$ErrorActionPreference = "Stop"

$crateManifests = @(
    "interop/crates/nghttp3-sys/Cargo.toml",
    "interop/crates/ngtcp2-sys/Cargo.toml",
    "interop/crates/ngtcp2/Cargo.toml",
    "interop/crates/tokio-ngtcp2/Cargo.toml"
)

function Copy-WorkspaceForPublish {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        if ($_.Name -eq ".git" -or $_.Name -eq "target") {
            return
        }

        $nextDestination = Join-Path $Destination $_.Name
        if ($_.PSIsContainer) {
            Copy-WorkspaceForPublish -Source $_.FullName -Destination $nextDestination
        } else {
            Copy-Item -LiteralPath $_.FullName -Destination $nextDestination -Force
        }
    }
}

function Enable-PublishInManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Manifest,
        [Parameter(Mandatory = $true)][string]$Registry
    )

    $content = Get-Content -Raw -LiteralPath $Manifest
    $replacement = "publish = [`"$Registry`"]"
    $updated = $content -replace "(?m)^publish = false\r?$", $replacement
    if ($updated -eq $content) {
        throw "publish = false not found in $Manifest"
    }

    Set-Content -LiteralPath $Manifest -Value $updated -NoNewline -Encoding utf8
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "http3-rs-publish-$([System.Guid]::NewGuid().ToString('N'))"

try {
    $dirty = git -C $repoRoot status --porcelain
    if ($dirty) {
        Write-Warning "Working tree is not clean. Review changes before publishing."
    }

    Write-Host "Preparing temporary publish workspace: $tempRoot"
    Copy-WorkspaceForPublish -Source $repoRoot -Destination $tempRoot

    foreach ($manifest in $crateManifests) {
        Enable-PublishInManifest -Manifest (Join-Path $tempRoot $manifest) -Registry $Registry
    }

    Push-Location $tempRoot
    for ($index = 0; $index -lt $crateManifests.Count; $index++) {
        $manifest = $crateManifests[$index]
        $args = @("publish", "--manifest-path", $manifest, "--registry", $Registry)
        if (-not $Execute) {
            $args += "--dry-run"
        }
        if ($Token) {
            $args += @("--token", $Token)
        }

        Write-Host "cargo $($args -join ' ')"
        & cargo @args

        if ($LASTEXITCODE -ne 0) {
            throw "cargo publish failed for $manifest"
        }

        if ($Execute -and $index -lt $crateManifests.Count - 1 -and $DelaySeconds -gt 0) {
            Write-Host "Waiting $DelaySeconds seconds for registry index propagation..."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    Pop-Location
}
finally {
    if ((Get-Location).Path -eq $tempRoot) {
        Pop-Location
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
