//! Criterion group construction and environment-driven benchmark selection.

use std::{env, path::Path};

use anyhow::{Context, Result, bail};
use bytesize::ByteSize;
use criterion::{BenchmarkId, Criterion, SamplingMode, Throughput};
use http3_bench::{
    case::{Case, DEFAULT_BODY_BYTES, Http3Library, MAX_BODY_BYTES, MAX_REQUESTS},
    result::MEASUREMENT_PROFILE,
};

use super::child::{ClientRunner, ServerGuard};

const BODY_SIZES_ENV: &str = "HTTP3_BENCH_BODY_SIZES";
const REQUESTS_ENV: &str = "HTTP3_BENCH_REQUESTS";
const CONCURRENCY_ENV: &str = "HTTP3_BENCH_CONCURRENCY";
const MAX_CONCURRENCY: usize = 100;
const BANDWIDTH_BODY_THRESHOLD: usize = 64 * 1024;
const TEST_REQUESTS: usize = 4;
const TEST_IN_FLIGHT: usize = 2;

struct Config {
    cases: Vec<Case>,
    requests: Option<usize>,
    concurrency: Option<usize>,
    test_mode: bool,
    sample_size_from_cli: bool,
    measurement_time_from_cli: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        let cases = match env::var(BODY_SIZES_ENV) {
            Ok(value) => parse_cases(&value)?,
            Err(env::VarError::NotPresent) => DEFAULT_BODY_BYTES.map(Case::for_body).to_vec(),
            Err(error) => return Err(error).context("could not read benchmark body sizes"),
        };
        let requests = match env::var(REQUESTS_ENV) {
            Ok(value) => {
                let requests = parse_positive(&value, REQUESTS_ENV)?;
                if requests > MAX_REQUESTS {
                    bail!("{REQUESTS_ENV} cannot exceed {MAX_REQUESTS}");
                }
                Some(requests)
            }
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("could not read benchmark request count"),
        };
        let concurrency = match env::var(CONCURRENCY_ENV) {
            Ok(value) => {
                let concurrency = parse_positive(&value, CONCURRENCY_ENV)?;
                if concurrency > MAX_CONCURRENCY {
                    bail!("{CONCURRENCY_ENV} cannot exceed {MAX_CONCURRENCY}");
                }
                Some(concurrency)
            }
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("could not read benchmark concurrency"),
        };

        Ok(Self {
            cases,
            requests,
            concurrency,
            test_mode: criterion_arg_present("--test"),
            sample_size_from_cli: criterion_arg_present("--sample-size"),
            measurement_time_from_cli: criterion_arg_present("--measurement-time"),
        })
    }
}

pub(crate) fn run(criterion: &mut Criterion) -> Result<()> {
    let config = Config::from_env()?;
    let executable = env::current_exe().context("could not locate the benchmark executable")?;
    run_groups(criterion, &config, &executable)
}

fn run_groups(criterion: &mut Criterion, config: &Config, executable: &Path) -> Result<()> {
    let runners = [
        ClientRunner {
            executable,
            library: Http3Library::Http3,
        },
        ClientRunner {
            executable,
            library: Http3Library::H3,
        },
        ClientRunner {
            executable,
            library: Http3Library::Nghttp3,
        },
    ];

    for &default_case in &config.cases {
        // RFC 9114 Section 3.3 recommends against opening multiple HTTP/3
        // connections with the same configuration to one IP address and UDP
        // port. This same-authority harness therefore expresses concurrency as
        // request streams on one connection. Each compared direct Client owns
        // that connection's one UDP socket; shared multi-target endpoints are a
        // separate QUIC transport scenario. The child Server advertises a fixed
        // stream-credit window above the supported Client concurrency, avoiding
        // an unrelated transport-default or MAX_STREAMS bottleneck.
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3
        let mut case = if config.test_mode {
            Case {
                body_bytes: default_case.body_bytes,
                requests: TEST_REQUESTS,
                in_flight: TEST_IN_FLIGHT,
            }
        } else {
            default_case
        };
        if let Some(requests) = config.requests {
            case.requests = requests;
            case.in_flight = case.in_flight.min(requests);
        }
        if let Some(concurrency) = config.concurrency {
            if concurrency > case.requests {
                bail!(
                    "concurrency {concurrency} exceeds the {} requests in the {case} batch",
                    case.requests
                );
            }
            case.in_flight = concurrency;
        }
        let group_name = format!(
            "http3-client/{MEASUREMENT_PROFILE}/{case}/requests-{}/concurrency-{}",
            case.requests, case.in_flight
        );
        let mut group = criterion.benchmark_group(&group_name);
        group.sampling_mode(SamplingMode::Flat);
        if !config.test_mode && !config.sample_size_from_cli {
            group.sample_size(10);
        }
        if !config.test_mode && !config.measurement_time_from_cli {
            group.measurement_time(case.measurement_time());
        }
        group.throughput(throughput(case)?);

        for runner in &runners {
            let library = runner.library;
            let mut server = None;
            let benchmark_id = BenchmarkId::from_parameter(library.name());
            group.bench_with_input(benchmark_id, &case, |bencher, &case| {
                server.get_or_insert_with(|| {
                    ServerGuard::start(executable, case.body_bytes).unwrap_or_else(|error| {
                        panic!("could not start {library} benchmark server: {error:#}")
                    })
                });
                bencher.iter_custom(|iterations| {
                    runner
                        .run_iterations(iterations, case)
                        .unwrap_or_else(|error| {
                            panic!("{library} benchmark sample failed: {error:#}")
                        })
                });
            });
            if let Some(mut server) = server {
                server.finish()?;
            }
        }
        group.finish();
    }
    Ok(())
}

fn criterion_arg_present(name: &str) -> bool {
    env::args().any(|argument| argument == name || argument.starts_with(&format!("{name}=")))
}

fn throughput(case: http3_bench::case::Case) -> Result<Throughput> {
    if case.body_bytes < BANDWIDTH_BODY_THRESHOLD {
        Ok(Throughput::Elements(case.requests.try_into()?))
    } else {
        Ok(Throughput::Bytes(case.expected_bytes()?.try_into()?))
    }
}

fn parse_cases(value: &str) -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    for input in value.split(',').map(str::trim) {
        if input.is_empty() {
            bail!("{BODY_SIZES_ENV} contains an empty body size");
        }
        let size = input.parse::<ByteSize>().map_err(|error| {
            anyhow::anyhow!("invalid body size {input:?} in {BODY_SIZES_ENV}: {error}")
        })?;
        let body_bytes = usize::try_from(size.as_u64())
            .with_context(|| format!("body size {input:?} does not fit usize"))?;
        if body_bytes > MAX_BODY_BYTES {
            bail!("response body cannot exceed 100 MiB");
        }
        let case = Case::for_body(body_bytes);
        if cases
            .iter()
            .any(|existing: &Case| existing.body_bytes == body_bytes)
        {
            bail!("{BODY_SIZES_ENV} contains duplicate body size {case}");
        }
        cases.push(case);
    }
    if cases.is_empty() {
        bail!("{BODY_SIZES_ENV} must contain at least one body size");
    }
    Ok(cases)
}

fn parse_positive(value: &str, name: &str) -> Result<usize> {
    let value = value
        .parse::<usize>()
        .with_context(|| format!("invalid positive integer {value:?} in {name}"))?;
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}
