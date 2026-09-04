//! Criterion group construction and environment-driven benchmark selection.

use std::env;

use anyhow::{Context, Result, bail};
use bytesize::ByteSize;
use criterion::{BenchmarkId, Criterion, SamplingMode, Throughput};
use http3_bench::{
    case::{Http3Library, Topology, Workload},
    result::MEASUREMENT_PROFILE,
};

use super::child::{ClientRunner, ServerGuard};

const BODY_SIZES_ENV: &str = "HTTP3_BENCH_BODY_SIZES";
const TOPOLOGIES_ENV: &str = "HTTP3_BENCH_TOPOLOGIES";
const BANDWIDTH_BODY_THRESHOLD: usize = 64 * 1024;

struct Config {
    topologies: Vec<Topology>,
    workloads: Vec<Workload>,
    sample_size_from_cli: bool,
    measurement_time_from_cli: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        let topologies = match env::var(TOPOLOGIES_ENV) {
            Ok(value) => value
                .split(',')
                .map(str::trim)
                .map(parse_topology)
                .collect::<Result<Vec<_>>>()?,
            Err(env::VarError::NotPresent) => Topology::ALL.to_vec(),
            Err(error) => return Err(error).context("could not read benchmark topologies"),
        };
        if topologies.is_empty() {
            bail!("{TOPOLOGIES_ENV} must contain at least one connections/sockets pair");
        }
        for (index, topology) in topologies.iter().enumerate() {
            if topologies[..index].contains(topology) {
                bail!("{TOPOLOGIES_ENV} contains duplicate topology {topology}");
            }
        }
        for topology in &topologies {
            if topology.connections > 4 || topology.sockets != 1 {
                bail!("nghttp3 supports at most 4 connections on 1 shared socket, got {topology}");
            }
        }

        let workloads = match env::var(BODY_SIZES_ENV) {
            Ok(value) => parse_workloads(&value)?,
            Err(env::VarError::NotPresent) => Workload::DEFAULT.to_vec(),
            Err(error) => return Err(error).context("could not read benchmark body sizes"),
        };

        Ok(Self {
            topologies,
            workloads,
            sample_size_from_cli: criterion_arg_present("--sample-size"),
            measurement_time_from_cli: criterion_arg_present("--measurement-time"),
        })
    }
}

pub(crate) fn run(criterion: &mut Criterion) -> Result<()> {
    let config = Config::from_env()?;
    run_groups(criterion, &config)
}

fn run_groups(criterion: &mut Criterion, config: &Config) -> Result<()> {
    let runners = [
        (
            Http3Library::Http3,
            ClientRunner::rust(Http3Library::Http3)?,
        ),
        (Http3Library::H3, ClientRunner::rust(Http3Library::H3)?),
        (Http3Library::Nghttp3, ClientRunner::nghttp3()?),
    ];

    for &workload in &config.workloads {
        for &topology in &config.topologies {
            let case = workload.for_topology(topology)?;
            let group_name = format!("http3-client/{MEASUREMENT_PROFILE}/{topology}/{workload}");
            let mut group = criterion.benchmark_group(&group_name);
            group.sampling_mode(SamplingMode::Flat);
            if !config.sample_size_from_cli {
                group.sample_size(10);
            }
            if !config.measurement_time_from_cli {
                group.measurement_time(workload.measurement_time());
            }
            group.throughput(throughput(case)?);

            for (library, runner) in &runners {
                let mut server = None;
                let benchmark_id = BenchmarkId::from_parameter(library.name());
                group.bench_with_input(benchmark_id, &case, |bencher, &case| {
                    server.get_or_insert_with(|| {
                        ServerGuard::start(workload.body_bytes).unwrap_or_else(|error| {
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
    }
    Ok(())
}

fn criterion_arg_present(name: &str) -> bool {
    env::args().any(|argument| argument == name || argument.starts_with(&format!("{name}=")))
}

fn throughput(case: http3_bench::case::Case) -> Result<Throughput> {
    if case.workload.body_bytes < BANDWIDTH_BODY_THRESHOLD {
        Ok(Throughput::Elements(case.expected_requests()?.try_into()?))
    } else {
        Ok(Throughput::Bytes(case.expected_bytes()?.try_into()?))
    }
}

fn parse_workloads(value: &str) -> Result<Vec<Workload>> {
    let mut workloads = Vec::new();
    for input in value.split(',').map(str::trim) {
        if input.is_empty() {
            bail!("{BODY_SIZES_ENV} contains an empty body size");
        }
        let size = input.parse::<ByteSize>().map_err(|error| {
            anyhow::anyhow!("invalid body size {input:?} in {BODY_SIZES_ENV}: {error}")
        })?;
        let body_bytes = usize::try_from(size.as_u64())
            .with_context(|| format!("body size {input:?} does not fit usize"))?;
        let workload = Workload::new(body_bytes)?;
        if workloads
            .iter()
            .any(|existing: &Workload| existing.body_bytes == body_bytes)
        {
            bail!("{BODY_SIZES_ENV} contains duplicate body size {workload}");
        }
        workloads.push(workload);
    }
    if workloads.is_empty() {
        bail!("{BODY_SIZES_ENV} must contain at least one body size");
    }
    Ok(workloads)
}

fn parse_topology(value: &str) -> Result<Topology> {
    let (connections, sockets) = value
        .split_once('/')
        .with_context(|| format!("invalid topology {value:?}; expected connections/sockets"))?;
    Topology::new(
        connections
            .parse::<usize>()
            .with_context(|| format!("invalid connection count in topology {value:?}"))?,
        sockets
            .parse::<usize>()
            .with_context(|| format!("invalid socket count in topology {value:?}"))?,
    )
}
