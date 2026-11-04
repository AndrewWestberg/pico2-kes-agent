use super::{
    lifecycle, producer, releases, review, safe, service, setup, uninstall,
    widgets::{ConfirmMode, review_mode, tone},
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
            Self::HostRecord { timestamp_us, .. }
            | Self::BackupRecord { timestamp_us, .. }
            | Self::LifecycleRef { timestamp_us, .. }
            | Self::RetainedPlan { timestamp_us, .. } => *timestamp_us,
            Self::UnknownRecord { .. } => u64::MAX,
        }
    }

    fn badge_and_color(&self) -> (&'static str, Color) {
        match self {
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
                    ("[RECONCILE]", Color::Yellow)
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
            Self::HostRecord { record, .. } => {
                let op_short = workspace::short_id(&record.operation_id.to_string());
                format!(
                    "host/{:<18} {} · {}",
                    safe(&record.action),
                    safe(&op_short),
                    safe(&record.outcome)
                )
            }
            Self::BackupRecord { record, .. } => {
                let op_short = workspace::short_id(&record.operation_id.to_string());
                format!(
                    "backup/{:<16} {} · {}",
                    safe(&record.action),
                    safe(&op_short),
                    safe(&record.outcome)
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
                    "needs CLI reconcile"
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
        && !matches!(record.outcome.as_str(), "failed-known" | "cancelled")
        && !record
            .checkpoints
            .iter()
            .any(|checkpoint| checkpoint.name == "application-blank-attended")
}

pub(super) fn discover(role: InstallationRole) -> ActivityInventory {
    let mut items = Vec::new();

    if let Ok(records) = RecordStore::list_host_readonly() {
        for rec in records {
            match rec {
                Record::Supported(record) => {
                    let needs_reconcile =
                        !host::maintenance_outcome_allows_new_action(&record.outcome)
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

    if role == InstallationRole::Backup
        && let Ok(records) = RecordStore::list_backup_readonly()
    {
        for rec in records {
            match rec {
                Record::Supported(record) => {
                    let needs_reconcile =
                        !host::maintenance_outcome_allows_new_action(&record.outcome);
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
                "[!] {} operation(s) need reconciliation — press Enter on a highlighted item to reconcile its original ID",
                inventory.unresolved_count
            ),
            Color::Yellow,
        )
    } else {
        (
            format!(
                "[OK] No interrupted operations pending ({} retained record/plan/receipt item(s))",
                inventory.items.len()
            ),
            Color::Green,
        )
    };
    let sub_line = "Enter: inspect / resume selected operation · r: refresh";
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
                Line::from("No retained maintenance records, lifecycle receipts, or host plans discovered yet."),
                Line::default(),
                Line::styled(
                    "Interrupted operations appear here automatically. Use Host for diagnostics.",
                    tone(Color::DarkGray),
                ),
            ])
            .block(
                Block::default()
                    .title(" Activity & Original Records ")
                    .borders(Borders::ALL),
            ),
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
                        " Activity & Original Records ({} total) ",
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
        ActivityItem::HostRecord {
            record,
            needs_reconcile,
            ..
        } => {
            let op_id = record.operation_id.to_string();
            let digest = record.plan_digest.to_string();
            let mut lines = vec![
                format!("Operation ID : {op_id}"),
                format!("Action       : {}", record.action),
                format!("Outcome      : {}", record.outcome),
                format!("Plan SHA-256 : {digest}"),
                String::new(),
            ];
            lines.extend(
                serde_json::to_string_pretty(record)
                    .map_err(io::Error::other)?
                    .lines()
                    .map(str::to_owned),
            );
            if !*needs_reconcile {
                review(terminal, "Retained host maintenance record", lines)?;
                return Ok(());
            }
            let prompt_label = match record.action.as_str() {
                "upgrade" => Some("reconcile original tuple upgrade"),
                "update" => Some("recover original host component update"),
                "firmware-update" => Some("reconcile original firmware update"),
                "firmware_transfer" => Some("associate & reconcile factory firmware install"),
                "wipe-board" => Some("resume original wipe forward"),
                "provisioning" => Some("inspect or resume original security stage"),
                "service" | "config" | "commission_service" => {
                    Some("reconcile original service/config state")
                }
                "host-security" => Some("recover original host security changes"),
                "producer-hardening" => Some("recover original producer drop-in batch"),
                "uninstall" => Some("recover original uninstall record"),
                _ => None,
            };
            let Some(label) = prompt_label else {
                lines.insert(
                    4,
                    "Guidance     : Inspect the retained original plan; never create a replacement retry."
                        .into(),
                );
                review(terminal, "Unresolved maintenance record (inspect)", lines)?;
                return Ok(());
            };
            if !review_mode(
                terminal,
                "Reconcile unresolved maintenance record",
                lines,
                ConfirmMode::Enter(label),
            )? {
                return Ok(());
            }
            match record.action.as_str() {
                "upgrade" => {
                    releases::recover_upgrade_record(terminal, worker, socket, &op_id, &digest)
                }
                "update" => releases::recover_update_record(terminal, worker, socket, record),
                "firmware-update" => {
                    releases::recover_firmware_record(terminal, worker, socket, record)
                }
                "firmware_transfer" => {
                    setup::reconcile_first_install_record(terminal, worker, socket, &op_id)
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
            let mut lines = vec![
                format!("Backup operation ID : {}", record.operation_id),
                format!("Action              : {}", record.action),
                format!("Outcome             : {}", record.outcome),
            ];
            if *needs_reconcile {
                lines.push(
                    "Guidance            : Inspect the destination path(s) on this backup host before creating a new recipient or restore."
                        .into(),
                );
            }
            lines.push(String::new());
            lines.extend(
                serde_json::to_string_pretty(record)
                    .map_err(io::Error::other)?
                    .lines()
                    .map(str::to_owned),
            );
            review(terminal, "Retained backup record", lines)?;
            Ok(())
        }
        ActivityItem::UnknownRecord { value } => {
            let mut lines = vec![
                "Record uses an unrecognized schema version; p2kesup displays it read-only and blocks conflicting mutations until upgraded."
                    .into(),
                String::new(),
            ];
            lines.extend(
                serde_json::to_string_pretty(value)
                    .map_err(io::Error::other)?
                    .lines()
                    .map(str::to_owned),
            );
            review(terminal, "Unknown-schema maintenance record", lines)?;
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
            let mut lines = vec![
                format!("Reference file : {}", reference.display()),
                format!("Receipt file   : {}", receipt_path.display()),
                format!("Action         : {action}"),
                String::new(),
            ];
            if let Ok(rec) = mgr_lifecycle::load_public_receipt(receipt_path) {
                lines.extend(
                    serde_json::to_string_pretty(&rec)
                        .map_err(io::Error::other)?
                        .lines()
                        .map(str::to_owned),
                );
            }
            if review_mode(
                terminal,
                "Retained lifecycle receipt",
                lines,
                ConfirmMode::Enter(
                    "re-verify / reconcile receipt against daemon (or Esc to close)",
                ),
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
                format!("Plan file    : {}", path.display()),
                format!("Plan ID      : {plan_id}"),
                format!("Summary      : {summary}"),
                format!("Plan SHA-256 : {approved_digest}"),
                String::new(),
                "Inspection is strictly read-only: host-inspect checks current host state against this plan without replaying it."
                    .into(),
            ];
            if review_mode(
                terminal,
                "Retained host plan",
                lines,
                ConfirmMode::Enter("run read-only privileged host-inspect"),
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
        assert!(!first_install_needs_postcheck(&record));
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
