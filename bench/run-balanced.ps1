<#
.SYNOPSIS
Runs the HTTP/3 Client comparison with explicit topology and body-size cases.

.DESCRIPTION
Runs http3, h3, and nghttp3 once in that fixed order. Body sizes use IEC units;
the default cases are 0 B, 1 KiB, 10 KiB, 64 KiB, 128 KiB, 1 MiB, 2 MiB,
4 MiB, and 100 MiB.

Cargo builds the native nghttp3/ngtcp2 Client automatically before Criterion;
no separately prepared executable is required. Building it requires CMake,
LLVM/libclang, NASM, and the Visual Studio 2022 MSVC C/C++ build tools.
The ngtcp2 and nghttp3 sources are Git submodules; clone with
--recurse-submodules or run `git submodule update --init --recursive` from the
repository root before the first build.

The Rust Clients use a Tokio current-thread runtime, while the nghttp3 Client
uses one synchronous event-loop thread. This script intentionally sets no CPU
affinity: the operating system may migrate those threads, so results describe
single-threaded Client throughput rather than strict single-core performance.
The benchmark Server is a separate, unpinned 8-worker process.

Each sample starts after local HTTP/3 setup and ends when the last complete
response has been validated. Task aggregation, extra receive draining, final
result checks, and connection shutdown are outside the measured interval.

.PARAMETER Topologies
Comma-separated connections/sockets pairs. The default is 1/1,4/1. The native
comparison currently accepts one shared socket and 1-4 connections; generated
request and in-flight totals must divide evenly across the connection count.

.PARAMETER BodySizes
Optional comma-separated response sizes such as 0B,64KiB,1MiB. Omitting this
parameter uses the default cases listed above. The maximum size is 100 MiB.

.PARAMETER CriterionArgs
Arguments forwarded to Criterion after Cargo's -- separator. This includes
--sample-size and --measurement-time; when present they override the per-case
defaults used by the harness.

.PARAMETER Help
Shows this complete parameter and example reference without building the benchmark.

.EXAMPLE
.\bench\run-balanced.ps1

.EXAMPLE
.\bench\run-balanced.ps1 `
  -Topologies '4/1' `
  -BodySizes '0B,64KiB,1MiB' `
  -CriterionArgs @('--sample-size', '20', '--measurement-time', '60', '--noplot')
#>

[CmdletBinding()]
param(
    [string]$Topologies = '1/1,4/1',
    [string]$BodySizes = '',
    [string[]]$CriterionArgs = @(),
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Help -or ($CriterionArgs.Count -eq 1 -and $CriterionArgs[0] -eq '--help')) {
    Get-Help -Name $PSCommandPath -Full
    return
}

$savedBodySizes = $env:HTTP3_BENCH_BODY_SIZES
$savedTopologies = $env:HTTP3_BENCH_TOPOLOGIES
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location -Path $repoRoot
try {
    $env:HTTP3_BENCH_TOPOLOGIES = $Topologies
    if ([string]::IsNullOrWhiteSpace($BodySizes)) {
        Remove-Item Env:HTTP3_BENCH_BODY_SIZES -ErrorAction SilentlyContinue
    }
    else {
        $env:HTTP3_BENCH_BODY_SIZES = $BodySizes
    }

    $rustcVersion = & rustc --version
    if ($LASTEXITCODE -ne 0) {
        throw "rustc --version failed with exit code $LASTEXITCODE"
    }
    if ($rustcVersion -match '^rustc 1\.(97|98)\.') {
        Write-Host 'Note: Rust 1.97/1.98 may label localized MSVC progress as linker warnings.'
        Write-Host 'Those "creating library" lines are harmless when Cargo continues; Rust 1.99 fixes the diagnostic.'
    }

    Write-Host 'Running HTTP/3 Clients in fixed order: http3, h3, nghttp3'
    & cargo bench -p http3-bench --bench clients -- @CriterionArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Criterion failed with exit code $LASTEXITCODE"
    }
}
finally {
    $env:HTTP3_BENCH_BODY_SIZES = $savedBodySizes
    $env:HTTP3_BENCH_TOPOLOGIES = $savedTopologies
    Pop-Location
}
