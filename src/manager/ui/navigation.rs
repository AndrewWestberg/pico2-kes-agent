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
            Self::Details => "Pool",
            Self::PoolActions => "Pool actions",
            Self::Device => "Device",
            Self::Host => "Host",
            Self::Releases => "Software",
            Self::Activity => "Activity",
            Self::Setup => "Setup",
            Self::SetupExisting => "Setup / Existing device",
            Self::SetupNew => "Setup / Blank device",
            Self::DeviceSecurity => "Device / Security",
            Self::ProducerHardening => "Host / Producer policy",
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

pub(super) fn entries(view: View, role: InstallationRole) -> Vec<Entry> {
    use Action as A;
    use View as V;
    let primary = role == InstallationRole::Primary;
    match view {
        V::Setup => vec![
            Entry::new("Connect an existing device", A::Open(V::SetupExisting)),
            Entry::new("Set up a new blank device", A::Open(V::SetupNew)),
            Entry::new("Inspect only", A::Open(V::Evidence)),
        ],
        V::SetupExisting => vec![
            Entry::new(
                "Create a configuration candidate",
                A::Service(
                    service::ACTIONS
                        .iter()
                        .position(|(a, _)| matches!(a, service::Action::Edit))
                        .unwrap(),
                ),
            ),
            setup_step(
                setup::Action::NormalConfig,
                "Install / restore configuration",
            ),
            setup_step(setup::Action::StartNormal, "Start normal service"),
            Entry::new("Inspect device and host evidence", A::Open(V::Evidence)),
        ],
        V::SetupNew => vec![
            setup_step(
                setup::Action::FirstInstall,
                "1. Install firmware (BOOTSEL only; skip compatible app)",
            ),
            setup_step(
                setup::Action::CommissionConfig,
                "2. Install commissioning configuration",
            ),
            setup_step(
                setup::Action::StartCommission,
                "3. Start commissioning service",
            ),
            setup_step(setup::Action::Commission, "4. Commission blank device"),
            setup_step(
                setup::Action::StopCommission,
                "5. Stop commissioning service",
            ),
            setup_step(
                setup::Action::NormalConfig,
                "6. Install normal configuration and identity pin",
            ),
            setup_step(setup::Action::StartNormal, "7. Start normal service"),
            Entry::new(
                "Interrupted operation / original records",
                A::Open(V::Activity),
            ),
        ],
        V::Device => vec![
            Entry::new("Connect / set up device", A::Open(V::Setup)),
            Entry::new(
                "Preview firmware update",
                A::Release(releases::Action::FirmwarePreview),
            ),
            Entry::new(
                "Update firmware",
                A::Release(releases::Action::FirmwareUpdate),
            ),
            Entry::new("Security / OTP (advanced)", A::Open(V::DeviceSecurity)),
        ],
        V::Host => {
            let mut entries = vec![Entry::new("Continue setup", A::Open(V::Setup))];
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
                "Producer memory policy",
                A::Open(V::ProducerHardening),
            ));
            entries
        }
        V::Details | V::PoolActions => lifecycle::ACTIONS
            .iter()
            .enumerate()
            .filter(|(_, (a, _))| {
                let targeted = matches!(
                    a,
                    lifecycle::Action::Detail
                        | lifecycle::Action::Delete
                        | lifecycle::Action::Generate
                        | lifecycle::Action::Discard
                        | lifecycle::Action::VerificationKey
                        | lifecycle::Action::Artifact
                        | lifecycle::Action::Certificate
                );
                if view == V::Details {
                    targeted
                } else {
                    matches!(
                        a,
                        lifecycle::Action::List
                            | lifecycle::Action::Enroll
                            | lifecycle::Action::Recipient
                    )
                }
            })
            .map(|(i, (_, label))| Entry::new(label, A::Lifecycle(i)))
            .collect(),
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
                        releases::Action::Browse
                            | releases::Action::Refresh
                            | releases::Action::Prerelease
                            | releases::Action::Offline
                            | releases::Action::Select
                            | releases::Action::Reexec
                            | releases::Action::Remove
                    )
                })
                .map(|a| Entry::new(a.label(), A::Release(*a)))
                .collect();
            entries.push(setup_step(
                setup::Action::Install,
                "Install authenticated bundle",
            ));
            entries.push(Entry::new(
                "Uninstall managed components (advanced)",
                A::Uninstall,
            ));
            entries
        }
        V::Activity => {
            let mut entries = vec![
                setup_step(
                    setup::Action::InspectPlan,
                    "Inspect original installation / maintenance plan",
                ),
                Entry::new(
                    "Recover original host update",
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
                    "Recover original firmware update",
                    A::Release(releases::Action::RecoverFirmware),
                ));
                entries.push(setup_step(
                    setup::Action::ReconcileFirstInstall,
                    "Reconcile original first firmware install",
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
