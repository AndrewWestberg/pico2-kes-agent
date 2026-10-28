use criterion::{Criterion, criterion_group, criterion_main};

fn pending_host_workloads(_criterion: &mut Criterion) {
    panic!("host benchmark workloads are pending T034/T038/T039; a skeleton baseline is forbidden");
}

criterion_group! {
    name = host;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(std::time::Duration::from_secs(5))
        .measurement_time(std::time::Duration::from_secs(10));
    targets = pending_host_workloads
}
criterion_main!(host);
