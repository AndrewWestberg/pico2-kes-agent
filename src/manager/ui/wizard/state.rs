use crate::manager::model::DeviceMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SetupStep {
    Activity,
    Detect,
    UnplugOthers,
    PickBoard,
    FlashFactory,
    CommissionConfig,
    StartCommission,
    InspectApp,
    AlreadyCommissioned,
    Commission,
    StopCommission,
    NormalConfig,
    StartAgent,
    ConfiguredChoice,
    Done,
}

#[derive(Default)]
pub(super) struct Observed {
    pub unresolved: bool,
    pub apps: usize,
    pub bootsel: usize,
    pub selected: bool,
    pub config_serial_matches: bool,
    pub commission_running: bool,
    pub identity: Option<bool>,
    pub trusted_device: bool,
    pub normal_config: bool,
    pub agent_running: bool,
    pub configured_kept: bool,
    pub configured_wipe: bool,
}

pub(super) fn next_setup_step(o: &Observed) -> SetupStep {
    if o.unresolved {
        return SetupStep::Activity;
    }
    if o.bootsel > 1 || (o.bootsel > 0 && o.apps > 0) {
        return SetupStep::UnplugOthers;
    }
    if o.bootsel == 1 {
        return SetupStep::FlashFactory;
    }
    if o.apps == 0 {
        return SetupStep::Detect;
    }
    if o.apps > 1 && !o.selected {
        return SetupStep::PickBoard;
    }
    if o.normal_config && o.config_serial_matches && !o.configured_kept {
        if !o.configured_wipe {
            return SetupStep::ConfiguredChoice;
        }
        return if o.identity.is_none() {
            SetupStep::InspectApp
        } else {
            SetupStep::AlreadyCommissioned
        };
    }
    if o.trusted_device {
        if o.commission_running {
            return SetupStep::StopCommission;
        }
        if !o.normal_config {
            return SetupStep::NormalConfig;
        }
        return if o.agent_running {
            SetupStep::Done
        } else {
            SetupStep::StartAgent
        };
    }
    if !o.config_serial_matches {
        return SetupStep::CommissionConfig;
    }
    if !o.commission_running {
        return SetupStep::StartCommission;
    }
    match o.identity {
        None => SetupStep::InspectApp,
        Some(false) => SetupStep::Commission,
        Some(true) if !o.trusted_device => SetupStep::AlreadyCommissioned,
        Some(true) => SetupStep::StopCommission,
    }
}

pub(super) fn wipe_available(security: &serde_json::Value) -> bool {
    security["profile"] == "unlocked"
        && security["redundancy_ok"] == true
        && security["critical"] == 0
        && security["bootkey0"]
            .as_str()
            .is_some_and(|key| key.len() == 64 && key.bytes().all(|b| b == b'0'))
}

pub(super) fn count_modes(modes: impl Iterator<Item = DeviceMode>) -> (usize, usize) {
    modes.fold((0, 0), |(apps, bootsel), mode| match mode {
        DeviceMode::Application => (apps + 1, bootsel),
        DeviceMode::Bootloader => (apps, bootsel + 1),
        _ => (apps, bootsel),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resumes_from_observations() {
        let cases = [
            (Observed::default(), SetupStep::Detect),
            (
                Observed {
                    unresolved: true,
                    ..Default::default()
                },
                SetupStep::Activity,
            ),
            (
                Observed {
                    bootsel: 1,
                    ..Default::default()
                },
                SetupStep::FlashFactory,
            ),
            (
                Observed {
                    apps: 1,
                    bootsel: 1,
                    ..Default::default()
                },
                SetupStep::UnplugOthers,
            ),
            (
                Observed {
                    apps: 2,
                    ..Default::default()
                },
                SetupStep::PickBoard,
            ),
            (
                Observed {
                    apps: 1,
                    ..Default::default()
                },
                SetupStep::CommissionConfig,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    ..Default::default()
                },
                SetupStep::StartCommission,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    commission_running: true,
                    ..Default::default()
                },
                SetupStep::InspectApp,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    commission_running: true,
                    identity: Some(false),
                    ..Default::default()
                },
                SetupStep::Commission,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    commission_running: true,
                    identity: Some(true),
                    ..Default::default()
                },
                SetupStep::AlreadyCommissioned,
            ),
            (
                Observed {
                    apps: 1,
                    trusted_device: true,
                    commission_running: true,
                    ..Default::default()
                },
                SetupStep::StopCommission,
            ),
            (
                Observed {
                    apps: 1,
                    trusted_device: true,
                    ..Default::default()
                },
                SetupStep::NormalConfig,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    normal_config: true,
                    ..Default::default()
                },
                SetupStep::ConfiguredChoice,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    normal_config: true,
                    configured_wipe: true,
                    ..Default::default()
                },
                SetupStep::InspectApp,
            ),
            (
                Observed {
                    apps: 1,
                    config_serial_matches: true,
                    normal_config: true,
                    configured_wipe: true,
                    identity: Some(true),
                    ..Default::default()
                },
                SetupStep::AlreadyCommissioned,
            ),
            (
                Observed {
                    apps: 1,
                    trusted_device: true,
                    config_serial_matches: true,
                    normal_config: true,
                    configured_kept: true,
                    ..Default::default()
                },
                SetupStep::StartAgent,
            ),
            (
                Observed {
                    apps: 1,
                    trusted_device: true,
                    config_serial_matches: true,
                    normal_config: true,
                    configured_kept: true,
                    agent_running: true,
                    ..Default::default()
                },
                SetupStep::Done,
            ),
        ];
        for (observed, expected) in cases {
            assert_eq!(next_setup_step(&observed), expected);
        }
    }

    #[test]
    fn wipe_requires_unlocked_otp() {
        let mut security = serde_json::json!({
            "profile": "unlocked", "redundancy_ok": true, "critical": 0, "bootkey0": "0".repeat(64)
        });
        assert!(wipe_available(&security));
        security["profile"] = "locked".into();
        assert!(!wipe_available(&security));
        security["profile"] = "unlocked".into();
        security["bootkey0"] = "1".repeat(64).into();
        assert!(!wipe_available(&security));
        security["bootkey0"] = "0".repeat(64).into();
        security["redundancy_ok"] = false.into();
        assert!(!wipe_available(&security));
    }
}
