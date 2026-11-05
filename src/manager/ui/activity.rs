use super::{
    lifecycle, producer, releases, review, safe, service, setup, uninstall,
    widgets::{ConfirmMode, review_details, tone},
};
use crate::manager::{
    host::{self, HostPlan},
    lifecycle as mgr_lifecycle,
    model::{InstallationRole, MaintenanceRecord},
    observe::Worker,
    records::{Record, RecordStore},
    terminal::TerminalOwner,
    workspace::{self, WorkspaceKind},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use serde_json::Value;
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

#[derive(Clone, Debug)]
pub(super) enum ActivityItem {
    Unavailable {
        source: &'static str,
        error: String,
    },
    HostRecord {
        record: Box<MaintenanceRecord>,
        needs_reconcile: bool,
        timestamp_us: u64,
    },
    BackupRecord {
        record: Box<MaintenanceRecord>,
        needs_reconcile: bool,
        timestamp_us: u64,
    },
    UnknownRecord {
        value: Value,
    },
    LifecycleRef {
        reference: PathBuf,
        receipt_path: PathBuf,
        action: String,
        op_id: String,
        pending: bool,
        timestamp_us: u64,
    },
    RetainedPlan {
        path: PathBuf,
        plan_id: String,
        stem: String,
        summary: String,
        approved_digest: String,
        timestamp_us: u64,
    },
}

impl ActivityItem {
    pub fn needs_reconcile(&self) -> bool {
        match self {
            Self::Unavailable { .. } => true,
            Self::HostRecord {
                needs_reconcile, ..
            }
            | Self::BackupRecord {
                needs_reconcile, ..
            } => *needs_reconcile,
            Self::UnknownRecord { .. } => true,
            Self::LifecycleRef { pending, .. } => *pending,
            Self::RetainedPlan { .. } => false,
        }
    }

    fn timestamp_us(&self) -> u64 {
        match self {
            Self::Unavailable { .. } => u64::MAX,
            Self::HostRecord { timestamp_us, .. }
            | Self::BackupRecord { timestamp_us, .. }
            | Self::LifecycleRef { timestamp_us, .. }
            | Self::RetainedPlan { timestamp_us, .. } => *timestamp_us,
            Self::UnknownRecord { .. } => u64::MAX,
        }
    }

    fn badge_and_color(&self) -> (&'static str, Color) {
        match self {
            Self::Unavailable { .. } => ("[CHECK]    ", Color::Yellow),
            Self::HostRecord {
                record,
                needs_reconcile,
                ..
            }
            | Self::BackupRecord {
                record,
                needs_reconcile,
                ..
            } => {
                if *needs_reconcile {
                    ("[CHECK]    ", Color::Yellow)
                } else if record.outcome.contains("fail") {
                    ("[FAILED]   ", Color::Red)
                } else {
                    ("[DONE]     ", Color::Green)
                }
            }
            Self::UnknownRecord { .. } => ("[SCHEMA!]  ", Color::Red),
            Self::LifecycleRef { pending, .. } => {
                if *pending {
                    ("[PENDING]  ", Color::Yellow)
                } else {
                    ("[RECEIPT]  ", Color::Green)
                }
            }
            Self::RetainedPlan { .. } => ("[PLAN]     ", Color::Cyan),
        }
    }

    fn summary_text(&self) -> String {
        match self {
            Self::Unavailable { source, .. } => format!("{source}: could not read saved history"),
            Self::HostRecord { record, .. } | Self::BackupRecord { record, .. } => {
                format!(
                    "{} · {}",
                    safe(action_label(&record.action)),
                    workspace::short_id(&record.operation_id.to_string()),
                )
            }
            Self::UnknownRecord { value } => {
                let v = value
                    .get("schema_version")
                    .and_then(Value::as_u64)
                    .map_or_else(|| "?".to_owned(), |n| n.to_string());
                format!("unknown record schema v{}", safe(&v))
            }
            Self::LifecycleRef {
                action,
                op_id,
                pending,
                ..
            } => {
                let op_short = workspace::short_id(op_id);
                let state = if *pending {
                    "needs checking"
                } else {
                    "recorded"
                };
                format!("cli/{:<19} {} · {state}", safe(action), safe(&op_short))
            }
            Self::RetainedPlan {
                stem,
                plan_id,
                summary,
                ..
            } => {
                let short = workspace::short_id(plan_id);
                let mut text = format!(
                    "plan/{:<18} {} · {}",
                    safe(stem),
                    safe(&short),
                    safe(summary)
                );
                if text.chars().count() > 64 {
                    text = format!("{}…", text.chars().take(63).collect::<String>());
                }
                text
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ActivityInventory {
    pub items: Vec<ActivityItem>,
    pub unresolved_count: usize,
}

fn file_mtime_us(path: &Path) -> u64 {
    std::fs::symlink_metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

pub(crate) fn first_install_needs_postcheck(record: &MaintenanceRecord) -> bool {
    record.action == "firmware_transfer"
        && !(matches!(record.outcome.as_str(), "failed-known" | "cancelled")
            && host::maintenance_record_allows_new_action(record))
        && !record
            .checkpoints
            .iter()
            .any(|checkpoint| checkpoint.name == "application-blank-attended")
}

fn action_label(action: &str) -> &str {
    match action {
        "install" => "Install software",
        "update" => "Update host software",
        "upgrade" => "Update software and firmware",
        "firmware_transfer" => "Install device firmware",
        "firmware-update" => "Update device firmware",
        "commission_service" => "Prepare device setup",
        "config" => "Save configuration",
        "service" => "Change agent service",
        "host-security" => "Protect host memory",
        "producer-hardening" => "Protect block producer memory",
        "provisioning" => "Configure device security",
        "wipe-board" => "Erase device keys and pools",
        "uninstall" => "Remove host software",
        _ => action,
    }
}

fn maintenance_lines(record: &MaintenanceRecord, needs_reconcile: bool) -> Vec<String> {
    let action = record
        .approved_scope
        .first()
        .and_then(|scope| serde_json::from_str::<host::HostAction>(scope).ok())
        .map_or_else(
            || action_label(&record.action).to_owned(),
            |action| action.summary(),
        );
    let status = if needs_reconcile {
        "Needs checking before another attempt"
    } else {
        match record.outcome.as_str() {
            "completed" => "Completed",
            "cancelled" => "Cancelled",
            "failed-known" => "Stopped; no recovery pending",
            _ => "Recorded",
        }
    };
    let mut lines = vec![format!("Action: {action}"), format!("Status: {status}")];
    if let Some(message) = record.post_observations.last()
        && !message.trim_start().starts_with(['{', '['])
    {
        lines.push(format!(
            "Last result: {}",
            message.chars().take(512).collect::<String>()
        ));
    }
    if needs_reconcile {
        lines.push("Continue below to check the saved operation safely. p2kesup will ask before making changes; do not start a replacement operation.".into());
    }
    lines
}

pub(super) fn discover(role: InstallationRole) -> ActivityInventory {
    let mut items = Vec::new();

    let host_records = RecordStore::list_host_readonly();
    if let Err(error) = &host_records {
        items.push(ActivityItem::Unavailable {
            source: "Host history",
            error: error.to_string(),
        });
    }
    if let Ok(records) = host_records {
        for rec in records {
            match rec {
                Record::Supported(record) => {
                    let needs_reconcile = !host::maintenance_record_allows_new_action(&record)
                        || first_install_needs_postcheck(&record);
                    let timestamp_us = record
                        .checkpoints
                        .last()
                        .map_or(0, |c| c.observed_at_unix_us);
                    items.push(ActivityItem::HostRecord {
                        record,
                        needs_reconcile,
                        timestamp_us,
                    });
                }
                Record::Unknown(value) => {
                    items.push(ActivityItem::UnknownRecord { value });
                }
            }
        }
    }

    let backup_records = (role == InstallationRole::Backup).then(RecordStore::list_backup_readonly);
    if let Some(Err(error)) = &backup_records {
        items.push(ActivityItem::Unavailable {
            source: "Backup history",
            error: error.to_string(),
        });
    }
    if let Some(Ok(records)) = backup_records {
        for rec in records {
            match rec {
                Record::Supported(record) => {
                    let needs_reconcile = !host::maintenance_record_allows_new_action(&record);
                    let timestamp_us = record
                        .checkpoints
                        .last()
                        .map_or(0, |c| c.observed_at_unix_us);
                    items.push(ActivityItem::BackupRecord {
                        record,
                        needs_reconcile,
                        timestamp_us,
                    });
                }
                Record::Unknown(value) => {
                    items.push(ActivityItem::UnknownRecord { value });
                }
            }
        }
    }

    if role == InstallationRole::Primary
        && let Ok(refs) = workspace::list_files(WorkspaceKind::References)
    {
        for reference in refs.into_iter().take(64) {
            if let Ok(receipt_path) = mgr_lifecycle::load_reference(&reference) {
                let timestamp_us = file_mtime_us(&receipt_path).max(file_mtime_us(&reference));
                match mgr_lifecycle::load_public_receipt(&receipt_path) {
                    Ok(receipt) => {
                        let action = receipt
                            .request
                            .get("action")
                            .and_then(Value::as_str)
                            .unwrap_or("lifecycle")
                            .to_owned();
                        let op_id = receipt
                            .request
                            .get("operation_id")
                            .and_then(Value::as_str)
                            .unwrap_or("receipt")
                            .to_owned();
                        let pending = receipt.response.is_none();
                        items.push(ActivityItem::LifecycleRef {
                            reference,
                            receipt_path,
                            action,
                            op_id,
                            pending,
                            timestamp_us,
                        });
                    }
                    Err(_) => {
                        items.push(ActivityItem::LifecycleRef {
                            reference,
                            receipt_path,
                            action: "unreadable-receipt".into(),
                            op_id: "unknown".into(),
                            pending: true,
                            timestamp_us,
                        });
                    }
                }
            }
        }
    }

    if let Ok(plans) = workspace::list_files(WorkspaceKind::Plans) {
        for path in plans.into_iter().take(32) {
            if let Ok(file) = crate::files::open_owner_controlled_file(&path) {
                let mut bytes = Vec::new();
                if file.take(256 * 1024 + 1).read_to_end(&mut bytes).is_ok()
                    && bytes.len() <= 256 * 1024
                    && let Ok(plan) = serde_json::from_slice::<HostPlan>(&bytes)
                {
                    items.push(ActivityItem::RetainedPlan {
                        timestamp_us: file_mtime_us(&path),
                        plan_id: plan.plan_id,
                        stem: plan.action.stem().into(),
                        summary: plan.action.summary(),
                        approved_digest: plan.approved_digest,
                        path,
                    });
                }
            }
        }
    }

    items.sort_by(|a, b| {
        b.needs_reconcile()
            .cmp(&a.needs_reconcile())
            .then_with(|| b.timestamp_us().cmp(&a.timestamp_us()))
    });

    let unresolved_count = items.iter().filter(|i| i.needs_reconcile()).count();
    ActivityInventory {
        items,
        unresolved_count,
    }
}

pub(super) fn render_activity(
    frame: &mut Frame<'_>,
    area: Rect,
    inventory: &ActivityInventory,
    selected: usize,
    _role: InstallationRole,
) {
    let parts = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(area);
    let (status_line, status_color) = if inventory.unresolved_count > 0 {
        (
            format!(
                "[!] {} item(s) need checking — select an item and press Enter to continue safely",
                inventory.unresolved_count
            ),
            Color::Yellow,
        )
    } else {
        (
            format!(
                "[OK] No interrupted operations pending ({} saved item(s))",
                inventory.items.len()
            ),
            Color::Green,
        )
    };
    let sub_line = "Enter: view result or continue safely · r: refresh";
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(status_line, tone(status_color).add_modifier(Modifier::BOLD)),
            Line::styled(sub_line, tone(Color::DarkGray)),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        parts[0],
    );

    if inventory.items.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("No saved operations yet."),
                Line::default(),
                Line::styled(
                    "Interrupted operations appear here automatically. Use Host for diagnostics.",
                    tone(Color::DarkGray),
                ),
            ])
            .block(Block::default().title(" Activity ").borders(Borders::ALL)),
            parts[1],
        );
        return;
    }

    let list_items: Vec<ListItem<'_>> = inventory
        .items
        .iter()
        .map(|item| {
            let (badge, color) = item.badge_and_color();
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{badge} "),
                    tone(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(item.summary_text()),
            ]))
        })
        .collect();

    let mut state =
        ListState::default().with_selected((selected < inventory.items.len()).then_some(selected));
    frame.render_stateful_widget(
        List::new(list_items)
            .block(
                Block::default()
                    .title(format!(
                        " Activity ({} saved items) ",
                        inventory.items.len()
                    ))
                    .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL),
            )
            .highlight_symbol("> ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        parts[1],
        &mut state,
    );
}

pub(super) fn open_item(
    item: &ActivityItem,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    launched_bundle: Option<&PathBuf>,
) -> io::Result<()> {
    match item {
        ActivityItem::Unavailable { source, error } => {
            review(terminal, source, vec![
                "p2kesup cannot read the saved operation history, so it cannot establish whether an earlier action finished.".into(),
                format!("Reason: {error}"),
                "If you just installed p2kesup, log out and back in to refresh your access, then reopen it. Otherwise request support with the reason above. Do not reset or delete records.".into(),
            ])?;
            Ok(())
        }
        ActivityItem::HostRecord {
            record,
            needs_reconcile,
            ..
        } => {
            let op_id = record.operation_id.to_string();
            let digest = record.plan_digest.to_string();
            let mut lines = maintenance_lines(record, *needs_reconcile);
            let details = serde_json::to_string_pretty(record)
                .map_err(io::Error::other)?
                .lines()
                .map(str::to_owned)
                .collect();
            if !*needs_reconcile {
                review_details(
                    terminal,
                    "Operation result",
                    lines,
                    details,
                    ConfirmMode::None,
                )?;
                return Ok(());
            }
            let prompt_label = match record.action.as_str() {
                "upgrade" => Some("check the software and firmware update"),
                "update" => Some("check the host software update"),
                "install"
                    if record
                        .checkpoints
                        .iter()
                        .any(|c| c.name == "precommission-update") =>
                {
                    Some("check the setup software update")
                }
                "firmware-update" => Some("check the device firmware update"),
                "firmware_transfer" => Some("check whether firmware installation started"),
                "wipe-board" => Some("check the interrupted device erase"),
                "provisioning" => Some("check the device security step"),
                "service" | "config" | "commission_service" => {
                    Some("check the service and configuration")
                }
                "host-security" => Some("check the host security changes"),
                "producer-hardening" => Some("check the producer memory protection"),
                "uninstall" => Some("check software removal"),
                _ => None,
            };
            let Some(label) = prompt_label else {
                lines.push("Automatic recovery is unavailable for this record. Keep it and use its technical details when requesting support; do not delete it or repeat the action.".into());
                review_details(
                    terminal,
                    "Operation needs checking",
                    lines,
                    details,
                    ConfirmMode::None,
                )?;
                return Ok(());
            };
            if !review_details(
                terminal,
                "Continue interrupted operation",
                lines,
                details,
                ConfirmMode::Enter(label),
            )? {
                return Ok(());
            }
            match record.action.as_str() {
                "upgrade" => {
                    releases::recover_upgrade_record(terminal, worker, socket, &op_id, &digest)
                }
                "update" => releases::recover_update_record(terminal, worker, socket, record),
                "install"
                    if record
                        .checkpoints
                        .iter()
                        .any(|c| c.name == "precommission-update") =>
                {
                    releases::recover_update_record(terminal, worker, socket, record)
                }
                "firmware-update" => {
                    releases::recover_firmware_record(terminal, worker, socket, record)
                }
                "firmware_transfer" => {
                    setup::reconcile_first_install_record(terminal, worker, socket, &op_id, &digest)
                }
                "wipe-board" => setup::apply(
                    terminal,
                    worker,
                    socket,
                    host::HostAction::WipeRecovery {
                        operation_id: op_id,
                        original_plan_digest: digest,
                    },
                    None,
                ),
                "provisioning" => super::provisioning::recover_record(
                    terminal,
                    worker,
                    socket,
                    launched_bundle,
                    record,
                ),
                "service" | "config" | "commission_service" => {
                    service::reconcile_record(terminal, worker, socket, op_id, digest)
                }
                "host-security" => setup::apply(
                    terminal,
                    worker,
                    socket,
                    host::HostAction::HostSecurityRecovery {
                        operation_id: op_id,
                        original_plan_digest: digest,
                        bootstrap: None,
                        bootstrap_manifest_digest: None,
                        candidate_accepted: false,
                    },
                    None,
                ),
                "producer-hardening" => {
                    producer::recover_record(terminal, worker, socket, &op_id, &digest)
                }
                "uninstall" => uninstall::recover_record(
                    terminal,
                    worker,
                    socket,
                    launched_bundle,
                    &op_id,
                    &digest,
                ),
                _ => Ok(()),
            }
        }
        ActivityItem::BackupRecord {
            record,
            needs_reconcile,
            ..
        } => {
            let mut lines = maintenance_lines(record, *needs_reconcile);
            if *needs_reconcile {
                lines.push(
                    "Keep any files already created on this backup host. Do not create a replacement recipient or restore until the original destination files have been checked."
                        .into(),
                );
            }
            let details = serde_json::to_string_pretty(record)
                .map_err(io::Error::other)?
                .lines()
                .map(str::to_owned)
                .collect();
            review_details(
                terminal,
                "Backup operation",
                lines,
                details,
                ConfirmMode::None,
            )?;
            Ok(())
        }
        ActivityItem::UnknownRecord { value } => {
            let lines = vec![
                "This saved record was written in a format this version cannot understand.".into(),
                "Use the installed p2kesup version that created it, or request support with the technical details. Keep the original record; do not delete it or repeat the action.".into(),
            ];
            let details = serde_json::to_string_pretty(value)
                .map_err(io::Error::other)?
                .lines()
                .map(str::to_owned)
                .collect();
            review_details(
                terminal,
                "Unrecognized record format",
                lines,
                details,
                ConfirmMode::None,
            )?;
            Ok(())
        }
        ActivityItem::LifecycleRef {
            reference,
            receipt_path,
            action,
            pending,
            ..
        } => {
            if *pending {
                return lifecycle::reconcile_reference(terminal, worker, socket, reference);
            }
            let lines = vec![
                format!("Action: {action}"),
                "The saved result is available. You can check it against the agent without repeating the original change.".into(),
                format!("Saved result: {}", receipt_path.display()),
            ];
            let details = match mgr_lifecycle::load_public_receipt(receipt_path) {
                Ok(receipt) => serde_json::to_string_pretty(&receipt)
                    .map_err(io::Error::other)?
                    .lines()
                    .map(str::to_owned)
                    .collect(),
                Err(error) => vec![format!("Could not read saved result: {error}")],
            };
            if review_details(
                terminal,
                "Saved operation result",
                lines,
                details,
                ConfirmMode::Enter("check the saved result with the agent"),
            )? {
                lifecycle::reconcile_reference(terminal, worker, socket, reference)?;
            }
            Ok(())
        }
        ActivityItem::RetainedPlan {
            path,
            plan_id,
            summary,
            approved_digest,
            ..
        } => {
            let lines = vec![
                format!("Planned action: {summary}"),
                "This is a saved plan, not proof that the action ran. Check the current host without making changes.".into(),
            ];
            let details = vec![
                format!("Plan file: {}", path.display()),
                format!("Plan ID: {plan_id}"),
                format!("Plan digest: {approved_digest}"),
            ];
            if review_details(
                terminal,
                "Saved plan",
                lines,
                details,
                ConfirmMode::Enter("check current host state (read-only)"),
            )? {
                setup::inspect_plan_file(terminal, worker, socket, path)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_history_routes_to_activity_not_new_setup() {
        let items = [ActivityItem::Unavailable {
            source: "Host history",
            error: "Permission denied".into(),
        }];
        let unresolved = items.iter().filter(|item| item.needs_reconcile()).count();
        assert_eq!(
            super::super::status::next_step(None, unresolved),
            super::super::status::NextStep::Activity,
        );
    }

    #[test]
    fn completed_transfer_still_needs_attended_application_postcheck() {
        let mut record: MaintenanceRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "operation_id": "11".repeat(16),
            "action": "firmware_transfer",
            "plan_digest": "22".repeat(32),
            "selected": null,
            "approved_scope": [],
            "previous_service_state": null,
            "pre_observations": [],
            "checkpoints": [],
            "post_observations": [],
            "outcome": "completed",
            "bundle_digest": null,
            "image_digest": null,
            "physical_selection": null
        }))
        .unwrap();
        assert!(first_install_needs_postcheck(&record));
        record.outcome = "cancelled".into();
        assert!(first_install_needs_postcheck(&record));
        let path = PathBuf::from(format!(
            "/var/lib/p2kesup/firmware/{}.json",
            "44".repeat(16)
        ));
        record.bundle_digest = Some("33".repeat(32));
        record.approved_scope = vec![
            serde_json::to_string(&host::HostAction::FirmwareFirstInstall {
                bundle: "/bundle".into(),
                manifest_digest: "33".repeat(32),
                candidate_accepted: true,
                record: path.clone(),
                apply: true,
            })
            .unwrap(),
        ];
        record.checkpoints = vec![
            crate::manager::model::MaintenanceCheckpoint {
                name: "intent-durable".into(),
                observed_at_unix_us: 1,
                evidence: record.plan_digest.to_string(),
            },
            crate::manager::model::MaintenanceCheckpoint {
                name: "first-install-not-started".into(),
                observed_at_unix_us: 2,
                evidence: path.display().to_string(),
            },
        ];
        assert!(!first_install_needs_postcheck(&record));
        record.checkpoints.clear();
        record.outcome = "completed".into();
        record
            .checkpoints
            .push(crate::manager::model::MaintenanceCheckpoint {
                name: "application-blank-attended".into(),
                observed_at_unix_us: 1,
                evidence: "blank observed".into(),
            });
        assert!(!first_install_needs_postcheck(&record));
    }
}
