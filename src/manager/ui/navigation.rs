use super::{backup, lifecycle, producer, provisioning, releases, service, setup};
use crate::manager::model::InstallationRole;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum View {
    Overview,
    Pools,
    Details,
    PoolActions,
    Device,
    Host,
    Releases,
    Activity,
    DeviceSecurity,
    ProducerHardening,
    Recipients,
    Restore,
    Evidence,
    Help,
}

impl View {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Pools => "Pools",
            Self::Details => "Pool Detail",
            Self::PoolActions => "Pool & Recipient Actions",
            Self::Device => "Device",
            Self::Host => "Host",
            Self::Releases => "Software",
            Self::Activity => "Activity",
            Self::DeviceSecurity => "Device / OTP Security",
            Self::ProducerHardening => "Host / Producer Hardening",
            Self::Recipients => "Recipients",
            Self::Restore => "Restore",
            Self::Evidence => "Evidence",
            Self::Help => "Help",
        }
    }

    pub(super) fn root(self) -> Self {
        match self {
            Self::Details | Self::PoolActions => Self::Pools,
            Self::DeviceSecurity => Self::Device,
            Self::ProducerHardening => Self::Host,
            _ => self,
        }
    }
}

pub(super) fn roots(role: InstallationRole) -> &'static [View] {
    if role == InstallationRole::Primary {
        &[
            View::Overview,
            View::Pools,
            View::Device,
            View::Host,
            View::Releases,
            View::Activity,
        ]
    } else {
        &[
            View::Overview,
            View::Recipients,
            View::Restore,
            View::Releases,
            View::Activity,
        ]
    }
}

#[derive(Clone, Copy)]
pub(super) enum Action {
    Open(View),
    Setup(usize),
    SetupWizard,
    AddPool,
    RotateKes,
    Release(releases::Action),
    Lifecycle(usize),
    Service(usize),
    Security(usize),
    Producer(usize),
    Backup(usize),
    Uninstall,
}

pub(super) struct Entry {
    pub label: &'static str,
    pub action: Action,
}
impl Entry {
    fn new(label: &'static str, action: Action) -> Self {
        Self { label, action }
    }
}

fn setup_step(action: setup::Action, label: &'static str) -> Entry {
    Entry::new(
        label,
        Action::Setup(
            setup::ACTIONS
                .iter()
                .position(|(candidate, _)| *candidate == action)
                .expect("setup action"),
        ),
    )
}

pub(super) fn lifecycle_index(target: lifecycle::Action) -> usize {
    lifecycle::ACTIONS
        .iter()
        .position(|(candidate, _)| *candidate == target)
        .expect("lifecycle action")
}

fn lifecycle_entry(target: lifecycle::Action) -> Entry {
    let idx = lifecycle_index(target);
    Entry::new(lifecycle::ACTIONS[idx].1, Action::Lifecycle(idx))
}

pub(super) fn entries(view: View, role: InstallationRole) -> Vec<Entry> {
    use Action as A;
    use View as V;
    let primary = role == InstallationRole::Primary;
    match view {
        V::Device => vec![
            Entry::new("Set up my Pico 2", A::SetupWizard),
            Entry::new(
                "Preview firmware transfer (read-only)",
                A::Release(releases::Action::FirmwarePreview),
            ),
            Entry::new(
                "Update pinned Pico 2 firmware",
                A::Release(releases::Action::FirmwareUpdate),
            ),
            Entry::new(
                "Device security / OTP provisioning (advanced)",
                A::Open(V::DeviceSecurity),
            ),
        ],
        V::Host => {
            let mut entries = vec![Entry::new("Set up my Pico 2", A::SetupWizard)];
            entries.extend(
                service::ACTIONS
                    .iter()
                    .enumerate()
                    .map(|(i, (_, label))| Entry::new(label, A::Service(i))),
            );
            entries.push(Entry::new(
                "Producer systemd memory hardening",
                A::Open(V::ProducerHardening),
            ));
            entries
        }
        V::Details => vec![
            Entry::new("Rotate KES key", A::RotateKes),
            lifecycle_entry(lifecycle::Action::Artifact),
            lifecycle_entry(lifecycle::Action::Recipient),
            lifecycle_entry(lifecycle::Action::Discard),
            lifecycle_entry(lifecycle::Action::Delete),
        ],
        V::PoolActions => vec![
            Entry::new("Add a pool", A::AddPool),
            lifecycle_entry(lifecycle::Action::Recipient),
        ],
        V::Releases => {
            let actions = if primary {
                releases::PRIMARY_ACTIONS
            } else {
                releases::BACKUP_ACTIONS
            };
            let mut entries: Vec<_> = actions
                .iter()
                .filter(|a| {
                    matches!(
                        a,
                        releases::Action::TupleUpgrade
                            | releases::Action::Refresh
                            | releases::Action::Browse
                            | releases::Action::Reexec
                            | releases::Action::Select
                            | releases::Action::Prerelease
                            | releases::Action::Offline
                            | releases::Action::Remove
                    )
                })
                .map(|a| Entry::new(a.label(), A::Release(*a)))
                .collect();
            entries.push(setup_step(
                setup::Action::Install,
                "Install / repair authenticated host bundle",
            ));
            entries.push(Entry::new(
                "Uninstall managed components (advanced)",
                A::Uninstall,
            ));
            entries
        }
        V::DeviceSecurity => provisioning::ACTIONS
            .iter()
            .enumerate()
            .map(|(i, (_, label))| Entry::new(label, A::Security(i)))
            .collect(),
        V::ProducerHardening => producer::ACTIONS
            .iter()
            .enumerate()
            .map(|(i, (_, label))| Entry::new(label, A::Producer(i)))
            .collect(),
        V::Recipients | V::Restore => backup::ACTIONS
            .iter()
            .enumerate()
            .filter(|(_, (a, _))| {
                if view == V::Restore {
                    matches!(a, backup::Action::Restore)
                } else {
                    !matches!(a, backup::Action::Restore)
                }
            })
            .map(|(i, (_, label))| Entry::new(label, A::Backup(i)))
            .collect(),
        _ => Vec::new(),
    }
}
