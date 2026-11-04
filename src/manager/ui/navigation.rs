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
    ActivityManual,
    Setup,
    SetupExisting,
    SetupNew,
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
            Self::ActivityManual => "Activity / Manual Recovery",
            Self::Setup => "Guided Setup",
            Self::SetupExisting => "Setup / Existing Pico 2",
            Self::SetupNew => "Setup / Blank Pico 2",
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
            Self::Setup | Self::SetupExisting | Self::SetupNew | Self::ProducerHardening => {
                Self::Host
            }
            Self::ActivityManual => Self::Activity,
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
    Release(releases::Action),
    Lifecycle(usize),
    BindSelectedPool,
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
        V::Setup => vec![
            Entry::new(
                "Set up a new blank Pico 2 (step-by-step commissioning)",
                A::Open(V::SetupNew),
            ),
            Entry::new(
                "Connect an existing commissioned Pico 2 (preserve state)",
                A::Open(V::SetupExisting),
            ),
            Entry::new("Inspect raw host & USB evidence", A::Open(V::Evidence)),
        ],
        V::SetupExisting => vec![
            setup_step(
                setup::Action::NormalConfig,
                "1. Build or import normal pinned configuration",
            ),
            setup_step(
                setup::Action::StartNormal,
                "2. Start normal pico2-kes-agentd service",
            ),
            Entry::new(
                "3. Edit configuration candidate in /usr/bin/editor (optional)",
                A::Service(
                    service::ACTIONS
                        .iter()
                        .position(|(a, _)| matches!(a, service::Action::Edit))
                        .unwrap(),
                ),
            ),
            Entry::new("4. Open Pools to verify & bind sockets", A::Open(V::Pools)),
        ],
        V::SetupNew => vec![
            setup_step(
                setup::Action::FirstInstall,
                "1. Flash factory firmware (BOOTSEL only; skip if app installed)",
            ),
            setup_step(
                setup::Action::CommissionConfig,
                "2. Build & install commissioning configuration",
            ),
            setup_step(
                setup::Action::StartCommission,
                "3. Start restricted commissioning service",
            ),
            Entry::new(
                "   [Optional] Device security / OTP stages",
                A::Open(V::DeviceSecurity),
            ),
            setup_step(
                setup::Action::Commission,
                "4. Commission blank Pico 2 (exports device.json)",
            ),
            setup_step(
                setup::Action::StopCommission,
                "5. Stop restricted commissioning service",
            ),
            setup_step(
                setup::Action::NormalConfig,
                "6. Build & install normal pinned configuration",
            ),
            setup_step(
                setup::Action::StartNormal,
                "7. Start normal pico2-kes-agentd service",
            ),
            Entry::new(
                "8. Install HPKE backup recipient & enroll first pool",
                A::Open(V::PoolActions),
            ),
            Entry::new(
                "   Interrupted step? Open Activity & Original Records",
                A::Open(V::Activity),
            ),
        ],
        V::Device => vec![
            Entry::new("Guided device setup (blank or existing)", A::Open(V::Setup)),
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
            let mut entries = vec![Entry::new("Guided setup checklist", A::Open(V::Setup))];
            entries.extend(
                service::ACTIONS
                    .iter()
                    .enumerate()
                    .filter(|(_, (a, _))| {
                        matches!(
                            a,
                            service::Action::Start
                                | service::Action::Stop
                                | service::Action::Restart
                                | service::Action::Configuration
                                | service::Action::Edit
                        )
                    })
                    .map(|(i, (_, label))| Entry::new(label, A::Service(i))),
            );
            entries.push(Entry::new(
                "Producer systemd memory hardening",
                A::Open(V::ProducerHardening),
            ));
            entries
        }
        V::Details => vec![
            lifecycle_entry(lifecycle::Action::Generate),
            lifecycle_entry(lifecycle::Action::VerificationKey),
            lifecycle_entry(lifecycle::Action::Artifact),
            lifecycle_entry(lifecycle::Action::Certificate),
            Entry::new(
                "Bind pool in host config.json (and restart agentd)",
                A::BindSelectedPool,
            ),
            lifecycle_entry(lifecycle::Action::Detail),
            lifecycle_entry(lifecycle::Action::Discard),
            lifecycle_entry(lifecycle::Action::Delete),
        ],
        V::PoolActions => vec![
            lifecycle_entry(lifecycle::Action::Enroll),
            lifecycle_entry(lifecycle::Action::Recipient),
            lifecycle_entry(lifecycle::Action::List),
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
        V::ActivityManual => {
            let mut entries = vec![
                setup_step(
                    setup::Action::InspectPlan,
                    "Inspect original host plan file (read-only)",
                ),
                Entry::new(
                    "Recover original host component update",
                    A::Release(releases::Action::Fallback),
                ),
            ];
            if primary {
                entries.extend(
                    service::ACTIONS
                        .iter()
                        .enumerate()
                        .filter(|(_, (a, _))| {
                            matches!(
                                a,
                                service::Action::Diagnostics
                                    | service::Action::Export
                                    | service::Action::Inspect
                                    | service::Action::Reconcile
                            )
                        })
                        .map(|(i, (_, label))| Entry::new(label, A::Service(i))),
                );
                entries.extend(
                    lifecycle::ACTIONS
                        .iter()
                        .enumerate()
                        .filter(|(_, (a, _))| {
                            matches!(
                                a,
                                lifecycle::Action::Receipts | lifecycle::Action::Reconcile
                            )
                        })
                        .map(|(i, (_, label))| Entry::new(label, A::Lifecycle(i))),
                );
                entries.push(Entry::new(
                    "Recover original firmware update by ID",
                    A::Release(releases::Action::RecoverFirmware),
                ));
                entries.push(setup_step(
                    setup::Action::ReconcileFirstInstall,
                    "Associate & reconcile original first firmware install",
                ));
                entries.extend(
                    producer::ACTIONS
                        .iter()
                        .enumerate()
                        .filter(|(_, (a, _))| matches!(a, producer::Action::Recover))
                        .map(|(i, (_, label))| Entry::new(label, A::Producer(i))),
                );
            }
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
