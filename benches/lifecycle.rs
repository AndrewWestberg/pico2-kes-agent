use criterion::{Criterion, criterion_group, criterion_main};

fn pending_lifecycle_workloads(_criterion: &mut Criterion) {
    panic!(
        "lifecycle benchmark workloads are pending T028/T026/T029/T033; a skeleton baseline is forbidden"
    );
}

criterion_group! {
    name = lifecycle;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(std::time::Duration::from_secs(5))
        .measurement_time(std::time::Duration::from_secs(10));
    targets = pending_lifecycle_workloads
}
criterion_main!(lifecycle);
