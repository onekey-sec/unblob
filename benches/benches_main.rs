#![allow(clippy::identity_op)]
#![allow(non_snake_case, non_upper_case_globals)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::prelude::*;

const kB: usize = 1024;
const MB: usize = 1024 * kB;

fn shannon_entropy(c: &mut Criterion) {
    let mut sample = vec![0u8; 1 * MB];
    StdRng::seed_from_u64(5).fill(&mut sample[..]);

    let mut group = c.benchmark_group("Shannon entropy");

    for sample_size in [256, 1 * kB, 64 * kB, 256 * kB, 1 * MB] {
        group.throughput(Throughput::Bytes(sample_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(sample_size),
            &sample_size,
            |b, &size| {
                b.iter(|| unblob_native::shannon_entropy(&sample[0..size]));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, shannon_entropy);

criterion_main!(benches);
