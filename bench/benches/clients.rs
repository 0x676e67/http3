//! Criterion harness for the isolated HTTP/3 Client comparison.

use criterion::{Criterion, criterion_group, criterion_main};

mod child;
mod runner;

fn clients(criterion: &mut Criterion) {
    runner::run(criterion)
        .unwrap_or_else(|error| panic!("HTTP/3 Client benchmark failed: {error:#}"));
}

criterion_group!(benches, clients);
criterion_main!(benches);
