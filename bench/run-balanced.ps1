<#
.SYNOPSIS
Runs the HTTP/3 Client comparison with explicit body-size cases.

.DESCRIPTION
For each selected body size, runs http3, then h3, then nghttp3. Body sizes use
IEC units; the default cases are 0 B, 1 KiB, 10 KiB, 64 KiB, 128 KiB, 1 MiB,
2 MiB, 4 MiB, and 100 MiB.

Every Client uses one HTTP/3 connection and one UDP socket. Concurrent requests
use streams on that connection, matching RFC 9114 Section 3.3 guidance against
opening multiple same-configuration connections to one IP address and UDP port:
https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3

Cargo builds the native nghttp3/ngtcp2 Client automatically before Criterion;
no separately prepared executable is required. Building it requires CMake,
LLVM/libclang, NASM, and the Visual Studio 2022 MSVC C/C++ build tools.
The published ngtcp2-sys and nghttp3-sys crates include the required C sources,
so repository submodules are not needed for this benchmark.

The Rust Clients use a Tokio current-thread runtime, while the nghttp3 Client
uses one synchronous event-loop thread. This script intentionally sets no CPU
affinity: the operating system may migrate those threads, so results describe
single-threaded Client throughput rather than strict single-core performance.
The benchmark Server is a separate, unpinned 8-worker process.

Each sample starts after local HTTP/3 setup and ends when the last complete
response has been validated. Task aggregation, extra receive draining, final
result checks, and connection shutdown are outside the measured interval.

.PARAMETER BodySizes
Optional comma-separated response sizes such as 0B,64KiB,1MiB. Omitting this
parameter uses the default cases listed above. The maximum size is 100 MiB.

.PARAMETER Requests
Optional request count per Criterion iteration. Omitting it uses the
body-size-adaptive default. The supported range is 1-20000.

.PARAMETER Concurrency
Optional maximum number of concurrent request streams on the single HTTP/3
connection. Omitting it uses the body-size-adaptive default selected by the
benchmark. The supported range is 1-100, and it cannot exceed the generated
request count for any selected case. The Server advertises a fixed 1000-stream
bidirectional credit window, leaving headroom above the supported Client load.

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
  -BodySizes '0B,64KiB,1MiB' `
  -Requests 20000 `
  -Concurrency 32 `
  -CriterionArgs @('--sample-size', '20', '--measurement-time', '60', '--noplot')
#>

[CmdletBinding()]
param(
    [string]$BodySizes = '',
    [Nullable[int]]$Requests = $null,
    [Nullable[int]]$Concurrency = $null,
    [string[]]$CriterionArgs = @(),
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Help) {
    Get-Help -Name $PSCommandPath -Full
    return
}

$savedBodySizes = $env:HTTP3_BENCH_BODY_SIZES
$savedRequests = $env:HTTP3_BENCH_REQUESTS
$savedConcurrency = $env:HTTP3_BENCH_CONCURRENCY
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location -Path $repoRoot
try {
    if ([string]::IsNullOrWhiteSpace($BodySizes)) {
        Remove-Item Env:HTTP3_BENCH_BODY_SIZES -ErrorAction SilentlyContinue
    }
    else {
        $env:HTTP3_BENCH_BODY_SIZES = $BodySizes
    }
    if ($null -eq $Requests) {
        Remove-Item Env:HTTP3_BENCH_REQUESTS -ErrorAction SilentlyContinue
    }
    elseif ($Requests -le 0) {
        throw 'Requests must be greater than zero'
    }
    elseif ($Requests -gt 20000) {
        throw 'Requests cannot exceed 20000'
    }
    else {
        $env:HTTP3_BENCH_REQUESTS = $Requests.ToString()
    }
    if ($null -eq $Concurrency) {
        Remove-Item Env:HTTP3_BENCH_CONCURRENCY -ErrorAction SilentlyContinue
    }
    elseif ($Concurrency -le 0) {
        throw 'Concurrency must be greater than zero'
    }
    elseif ($Concurrency -gt 100) {
        throw 'Concurrency cannot exceed 100'
    }
    else {
        $env:HTTP3_BENCH_CONCURRENCY = $Concurrency.ToString()
    }

    $rustcVersion = & rustc --version
    if ($LASTEXITCODE -ne 0) {
        throw "rustc --version failed with exit code $LASTEXITCODE"
    }
    if ($rustcVersion -match '^rustc 1\.(97|98)\.') {
        Write-Host 'Note: Rust 1.97/1.98 may label localized MSVC progress as linker warnings.'
        Write-Host 'Those "creating library" lines are harmless when Cargo continues; Rust 1.99 fixes the diagnostic.'
    }

    Write-Host 'Running each selected case in fixed Client order: http3, h3, nghttp3'
    & cargo bench -p bench --bench clients --locked -- @CriterionArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Criterion failed with exit code $LASTEXITCODE"
    }
}
finally {
    $env:HTTP3_BENCH_BODY_SIZES = $savedBodySizes
    $env:HTTP3_BENCH_REQUESTS = $savedRequests
    $env:HTTP3_BENCH_CONCURRENCY = $savedConcurrency
    Pop-Location
}
