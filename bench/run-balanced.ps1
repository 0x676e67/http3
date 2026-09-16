<#
.SYNOPSIS
Runs the HTTP/3 Client comparison with explicit body-size cases.

.DESCRIPTION
For each selected body size, runs the selected QPACK modes against the native
nghttp3/ngtcp2 Server. With -Qpack all, modes run in order: none, request,
response, both. Static cases run Clients in order: http3, h3, nghttp3; dynamic
cases run http3, nghttp3 because the pinned h3 Client only supports static QPACK.
Result names begin with the Client and include server-nghttp3-native-4,
the body size, and /qpack-MODE. Body sizes use
IEC units; the default cases are 0 B, 1 KiB, 10 KiB, 64 KiB, 128 KiB, 1 MiB,
2 MiB, 4 MiB, and 100 MiB.

Each batch uses one timer covering request-state allocation, connection
establishment, all response validation and normal task aggregation. Runtime,
certificate trust/TLS configuration, UDP endpoint/socket and address preparation
happen before timing. Shutdown and result serialization are excluded.
Each batch starts with a fresh QPACK table.

Every Client uses one HTTP/3 connection and one UDP socket. Concurrent requests
use streams on that connection, matching RFC 9114 Section 3.3 guidance against
opening multiple same-configuration connections to one IP address and UDP port:
https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3

Cargo builds the native nghttp3/ngtcp2 Client and Server before Criterion;
no separately prepared executable is required. Building it requires CMake,
LLVM/libclang, NASM, and the Visual Studio 2022 MSVC C/C++ build tools.
The published ngtcp2-sys and nghttp3-sys crates include the required C sources,
so repository submodules are not needed for this benchmark.

The Rust Clients use a Tokio current-thread runtime, while the nghttp3 Client
uses one synchronous event-loop thread. This script intentionally sets no CPU
affinity: the operating system may migrate those threads, so results describe
single-threaded Client throughput rather than strict single-core performance.
The native Server is a separate, unpinned process with one event-loop thread.
All Clients use the same Server, validation, response content, and transport
settings. Results describe complete Client stacks against this Server, whose
single worker may limit throughput; they do not establish a Client-only ceiling.

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

.PARAMETER Headers
Header template direction: none, request, response, or both (default).
The request template has 12 Chrome navigation fields and 5 custom fields;
the response template has 12 designed response fields. Every field appears
once and is validated after decoding. Pseudo-headers, status, and content-length
are not part of these template counts. Use request or response to isolate the
direction of added QPACK work; both exercises Client encoding and decoding.

.PARAMETER Qpack
Dynamic QPACK direction: none, request, response, both, or all (default).
This is independent of -Headers: Headers selects field templates, while Qpack
selects dynamic compression. Request enables Client encoding; response enables
Client decoding. Dynamic capacity is 4096 bytes with 100 permitted blocked
streams. The fixed h3 Client runs only none; other modes explicitly skip it.
The Server verifies actual dynamic references, so use enough requests to reuse
the table after setup; -Requests 128 -Concurrency 4 is a small smoke case.

.PARAMETER CriterionArgs
Arguments forwarded to Criterion after Cargo's -- separator. This includes
--sample-size and --measurement-time; when present they override the per-case
defaults used by the harness.

.PARAMETER Help
Shows this complete parameter and example reference without building the benchmark.

.EXAMPLE
.\bench\run-balanced.ps1

.EXAMPLE
.\bench\run-balanced.ps1 -BodySizes '0B,1KiB' -Headers response -Qpack response -CriterionArgs @('--noplot')

.EXAMPLE
.\bench\run-balanced.ps1 -BodySizes '0B,1KiB,100KiB' -Requests 128 -Concurrency 4 -Qpack all -CriterionArgs @('--test')

.EXAMPLE
.\bench\run-balanced.ps1 `
  -BodySizes '0B,64KiB,1MiB' `
  -Requests 20000 `
  -Concurrency 32 `
  -Headers both `
  -Qpack all `
  -CriterionArgs @('--sample-size', '20', '--measurement-time', '60', '--noplot')
#>

[CmdletBinding()]
param(
    [string]$BodySizes = '',
    [Nullable[int]]$Requests = $null,
    [Nullable[int]]$Concurrency = $null,
    [ValidateSet('none', 'request', 'response', 'both')]
    [string]$Headers = 'both',
    [ValidateSet('none', 'request', 'response', 'both', 'all')]
    [string]$Qpack = 'all',
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
$savedHeaders = $env:HTTP3_BENCH_HEADERS
$savedQpack = $env:HTTP3_BENCH_QPACK
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
    $env:HTTP3_BENCH_HEADERS = $Headers.ToLowerInvariant()
    $env:HTTP3_BENCH_QPACK = $Qpack.ToLowerInvariant()

    $rustcVersion = & rustc --version
    if ($LASTEXITCODE -ne 0) {
        throw "rustc --version failed with exit code $LASTEXITCODE"
    }
    if ($rustcVersion -match '^rustc 1\.(97|98)\.') {
        Write-Host 'Note: Rust 1.97/1.98 may label localized MSVC progress as linker warnings.'
        Write-Host 'Those "creating library" lines are harmless when Cargo continues; Rust 1.99 fixes the diagnostic.'
    }

    Write-Host 'Server: nghttp3/ngtcp2, one native event loop; static Clients: http3, h3, nghttp3; dynamic Clients: http3, nghttp3'
    & cargo bench -p bench --bench clients --locked -- @CriterionArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Criterion failed with exit code $LASTEXITCODE"
    }
}
finally {
    $env:HTTP3_BENCH_BODY_SIZES = $savedBodySizes
    $env:HTTP3_BENCH_REQUESTS = $savedRequests
    $env:HTTP3_BENCH_CONCURRENCY = $savedConcurrency
    $env:HTTP3_BENCH_HEADERS = $savedHeaders
    $env:HTTP3_BENCH_QPACK = $savedQpack
    Pop-Location
}
