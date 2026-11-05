use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use super::{TerminalOwner, safe};

pub(super) fn tone(color: Color) -> Style {
    static NO_COLOR: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| std::env::var_os("NO_COLOR").is_some());
    if *NO_COLOR {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FieldKind<'a> {
    Text,
    Select(&'a [(&'a str, &'a str)]),
    File(&'a [crate::manager::discovery::files::FileKind]),
    MultiSelect(&'a [(&'a str, &'a str)]),
    ReadOnly,
}

#[derive(Clone, Copy)]
pub(crate) struct FieldSpec<'a> {
    pub label: &'a str,
    pub initial: &'a str,
    pub hint: Option<&'a str>,
    pub kind: FieldKind<'a>,
}

impl<'a> FieldSpec<'a> {
    pub const fn text(label: &'a str, initial: &'a str) -> Self {
        Self {
            label,
            initial,
            hint: None,
            kind: FieldKind::Text,
        }
    }

    pub const fn text_hint(label: &'a str, initial: &'a str, hint: &'a str) -> Self {
        Self {
            label,
            initial,
            hint: Some(hint),
            kind: FieldKind::Text,
        }
    }

    pub const fn select(
        label: &'a str,
        initial: &'a str,
        options: &'a [(&'a str, &'a str)],
    ) -> Self {
        Self {
            label,
            initial,
            hint: None,
            kind: FieldKind::Select(options),
        }
    }
    pub const fn file(
        label: &'a str,
        initial: &'a str,
        kinds: &'a [crate::manager::discovery::files::FileKind],
    ) -> Self {
        Self {
            label,
            initial,
            hint: None,
            kind: FieldKind::File(kinds),
        }
    }

    pub const fn multiselect(
        label: &'a str,
        initial: &'a str,
        options: &'a [(&'a str, &'a str)],
    ) -> Self {
        Self {
            label,
            initial,
            hint: None,
            kind: FieldKind::MultiSelect(options),
        }
    }

    pub const fn readonly(label: &'a str, value: &'a str) -> Self {
        Self {
            label,
            initial: value,
            hint: None,
            kind: FieldKind::ReadOnly,
        }
    }

    fn editable(&self) -> bool {
        !matches!(self.kind, FieldKind::ReadOnly)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ConfirmMode<'a> {
    None,
    Enter(&'a str),
    YesNo { danger: bool },
}

#[cfg(test)]
fn value_tail(value: &str, width: u16) -> String {
    let value = safe(value);
    let width = usize::from(width);
    if Line::from(value.as_str()).width() <= width {
        return value;
    }
    if width == 0 {
        return String::new();
    }
    let mut start = value.len();
    for (i, _) in value.char_indices().rev() {
        if Line::from(&value[i..]).width() > width - 1 {
            break;
        }
        start = i;
    }
    format!("…{}", &value[start..])
}

fn label_lines(label: &str, width: u16, style: Style) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    for c in label.chars() {
        current.push(c);
        if Line::from(current.as_str()).width() > width {
            current.pop();
            if !current.is_empty() {
                lines.push(Line::from(std::mem::take(&mut current)).style(style));
            }
            current.push(c);
        }
    }
    if !current.is_empty() {
        lines.push(Line::from(current).style(style));
    }
    lines
}

fn prev_char_boundary(s: &str, cursor: usize) -> usize {
    let cursor = cursor.min(s.len());
    s[..cursor]
        .char_indices()
        .next_back()
        .map(|(idx, _)| idx)
        .unwrap_or(0)
}

fn next_char_boundary(s: &str, cursor: usize) -> usize {
    let cursor = cursor.min(s.len());
    let mut iter = s[cursor..].char_indices();
    let _ = iter.next();
    iter.next()
        .map(|(offset, _)| cursor + offset)
        .unwrap_or(s.len())
}

fn prev_word_or_segment(s: &str, cursor: usize) -> usize {
    let cursor = cursor.min(s.len());
    let mut idx = cursor;
    while idx > 0 {
        let prev = prev_char_boundary(s, idx);
        let ch = s[prev..idx].chars().next().unwrap_or(' ');
        if ch.is_alphanumeric() {
            break;
        }
        idx = prev;
    }
    while idx > 0 {
        let prev = prev_char_boundary(s, idx);
        let ch = s[prev..idx].chars().next().unwrap_or(' ');
        if !ch.is_alphanumeric() {
            break;
        }
        idx = prev;
    }
    idx
}

pub(super) fn edit_text_key(value: &mut String, cursor: &mut usize, key: KeyEvent) -> bool {
    *cursor = (*cursor).min(value.len());
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Left => {
            *cursor = prev_char_boundary(value, *cursor);
            true
        }
        KeyCode::Right => {
            *cursor = next_char_boundary(value, *cursor);
            true
        }
        KeyCode::Home => {
            *cursor = 0;
            true
        }
        KeyCode::End => {
            *cursor = value.len();
            true
        }
        KeyCode::Char('a') if ctrl => {
            *cursor = 0;
            true
        }
        KeyCode::Char('e') if ctrl => {
            *cursor = value.len();
            true
        }
        KeyCode::Char('b') if ctrl => {
            *cursor = prev_char_boundary(value, *cursor);
            true
        }
        KeyCode::Char('f') if ctrl => {
            *cursor = next_char_boundary(value, *cursor);
            true
        }
        KeyCode::Char('u') if ctrl => {
            if *cursor > 0 {
                value.replace_range(..*cursor, "");
                *cursor = 0;
            }
            true
        }
        KeyCode::Char('k') if ctrl => {
            if *cursor < value.len() {
                value.truncate(*cursor);
            }
            true
        }
        KeyCode::Char('w') if ctrl => {
            let start = prev_word_or_segment(value, *cursor);
            if start < *cursor {
                value.replace_range(start..*cursor, "");
                *cursor = start;
            }
            true
        }
        KeyCode::Backspace => {
            if *cursor > 0 {
                let prev = prev_char_boundary(value, *cursor);
                value.replace_range(prev..*cursor, "");
                *cursor = prev;
            }
            true
        }
        KeyCode::Delete => {
            if *cursor < value.len() {
                let next = next_char_boundary(value, *cursor);
                value.replace_range(*cursor..next, "");
            }
            true
        }
        KeyCode::Char(c)
            if !c.is_control()
                && value.len() + c.len_utf8() <= 4096
                && !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            value.insert(*cursor, c);
            *cursor += c.len_utf8();
            true
        }
        _ => false,
    }
}

fn render_cursor_line(value: &str, cursor: usize, active: bool, width: u16) -> Line<'static> {
    let avail = usize::from(width).saturating_sub(4);
    if avail == 0 {
        return Line::default();
    }
    let cursor = cursor.min(value.len());
    if !active {
        let escaped = safe(value);
        if escaped.is_empty() {
            return Line::from(vec![
                Span::raw("  "),
                Span::styled("(empty)", tone(Color::DarkGray)),
            ]);
        }
        if Line::from(escaped.as_str()).width() <= avail {
            return Line::from(format!("  {escaped}"));
        }
        let mut end = 0;
        for (i, ch) in escaped.char_indices() {
            let next = i + ch.len_utf8();
            if Line::from(&escaped[..next]).width() + 1 > avail {
                break;
            }
            end = next;
        }
        return Line::from(format!("  {}…", &escaped[..end]));
    }

    let before = safe(&value[..cursor]);
    let (at_char, after) = if cursor < value.len() {
        let next = next_char_boundary(value, cursor);
        (safe(&value[cursor..next]), safe(&value[next..]))
    } else {
        (" ".to_owned(), String::new())
    };

    let before_chars: Vec<char> = before.chars().collect();
    let after_chars: Vec<char> = after.chars().collect();
    let cursor_w = Line::from(at_char.as_str()).width().max(1);
    let budget = avail.saturating_sub(cursor_w + 2);
    let target_left = (budget * 2) / 3;

    let mut left_start = before_chars.len();
    let mut left_w = 0usize;
    while left_start > 0 {
        let ch_s = before_chars[left_start - 1].to_string();
        let w = Line::from(ch_s.as_str()).width();
        if left_w + w > target_left && left_start < before_chars.len() {
            break;
        }
        if left_w + w > budget {
            break;
        }
        left_w += w;
        left_start -= 1;
    }
    let rem_right = budget.saturating_sub(left_w);
    let mut right_end = 0usize;
    let mut right_w = 0usize;
    while right_end < after_chars.len() {
        let ch_s = after_chars[right_end].to_string();
        let w = Line::from(ch_s.as_str()).width();
        if right_w + w > rem_right {
            break;
        }
        right_w += w;
        right_end += 1;
    }
    while left_start > 0 {
        let ch_s = before_chars[left_start - 1].to_string();
        let w = Line::from(ch_s.as_str()).width();
        if left_w + right_w + w > budget {
            break;
        }
        left_w += w;
        left_start -= 1;
    }

    let left_ellipsis = if left_start > 0 { "…" } else { "" };
    let right_ellipsis = if right_end < after_chars.len() {
        "…"
    } else {
        ""
    };
    let visible_left: String = before_chars[left_start..].iter().collect();
    let visible_right: String = after_chars[..right_end].iter().collect();

    Line::from(vec![
        Span::raw("  "),
        Span::styled(left_ellipsis, tone(Color::DarkGray)),
        Span::raw(visible_left),
        Span::styled(
            at_char,
            Style::default().add_modifier(Modifier::REVERSED | Modifier::UNDERLINED),
        ),
        Span::raw(visible_right),
        Span::styled(right_ellipsis, tone(Color::DarkGray)),
    ])
}

fn step_editable(specs: &[FieldSpec<'_>], current: usize, forward: bool) -> usize {
    if specs.is_empty() {
        return 0;
    }
    let len = specs.len();
    for offset in 1..=len {
        let candidate = if forward {
            (current + offset) % len
        } else {
            (current + len - (offset % len)) % len
        };
        if specs[candidate].editable() {
            return candidate;
        }
    }
    current
}

fn last_editable(specs: &[FieldSpec<'_>]) -> Option<usize> {
    specs.iter().rposition(FieldSpec::editable)
}

pub(crate) fn form_validated<T>(
    terminal: &mut TerminalOwner,
    title: &str,
    specs: &[FieldSpec<'_>],
    mut validate: impl FnMut(&[String]) -> Result<T, (Option<usize>, String)>,
) -> io::Result<Option<T>> {
    let mut values: Vec<String> = specs
        .iter()
        .map(|spec| match spec.kind {
            FieldKind::Select(options) if spec.initial.is_empty() && !options.is_empty() => {
                options[0].0.to_owned()
            }
            _ => spec.initial.to_owned(),
        })
        .collect();
    if specs.is_empty() {
        return validate(&values)
            .map(Some)
            .map_err(|(_, msg)| io::Error::new(io::ErrorKind::InvalidInput, msg));
    }
    let mut cursors: Vec<usize> = values.iter().map(String::len).collect();
    let mut selected = specs.iter().position(FieldSpec::editable).unwrap_or(0);
    let mut error_banner: Option<String> = None;
    let mut state = ListState::default();
    let mut redraw = true;

    loop {
        let size = terminal.terminal()?.size()?;
        let small = size.width < 80 || size.height < 24;
        if redraw {
            terminal.terminal()?.draw(|frame| {
                if small {
                    frame.render_widget(
                        Paragraph::new("Resize to 80×24 · Esc/q cancel"),
                        frame.area(),
                    );
                } else {
                    let footer_len = if error_banner.is_some() { 3 } else { 2 };
                    let areas = Layout::vertical([Constraint::Min(1), Constraint::Length(footer_len)])
                        .split(frame.area());
                    let inner_w = areas[0].width.saturating_sub(2);
                    let items: Vec<ListItem> = specs
                        .iter()
                        .enumerate()
                        .map(|(i, spec)| {
                            let active = i == selected && spec.editable();
                            let marker = if active { ">" } else { " " };
                            let style = if active {
                                tone(Color::Cyan).add_modifier(Modifier::BOLD)
                            } else if !spec.editable() {
                                tone(Color::DarkGray)
                            } else {
                                Style::default()
                            };
                            let mut lines = label_lines(
                                &format!("{marker} {}", safe(spec.label)),
                                inner_w,
                                style,
                            );
                            match spec.kind {
                                FieldKind::Text | FieldKind::File(_) | FieldKind::MultiSelect(_) => {
                                    lines.push(render_cursor_line(
                                        &values[i],
                                        cursors[i],
                                        active,
                                        inner_w,
                                    ));
                                }
                                FieldKind::Select(options) => {
                                    let desc = options
                                        .iter()
                                        .find(|(val, _)| *val == values[i])
                                        .map(|(_, d)| *d)
                                        .unwrap_or("");
                                    let val_disp = safe(&values[i]);
                                    let detail = if desc.is_empty() {
                                        format!("  ◀ {val_disp} ▶")
                                    } else {
                                        format!("  ◀ {val_disp} ▶  ({})", safe(desc))
                                    };
                                    let line_style = if active {
                                        Style::default().add_modifier(Modifier::BOLD)
                                    } else {
                                        Style::default()
                                    };
                                    lines.push(Line::from(detail).style(line_style));
                                }
                                FieldKind::ReadOnly => {
                                    lines.push(
                                        Line::from(format!("  {}", safe(&values[i])))
                                            .style(tone(Color::DarkGray)),
                                    );
                                }
                            }
                            if let Some(hint) = spec.hint
                                && active
                            {
                                lines.push(
                                    Line::from(format!("  hint: {}", safe(hint)))
                                        .style(tone(Color::DarkGray)),
                                );
                            }
                            ListItem::new(lines)
                        })
                        .collect();
                    state.select(Some(selected));
                    frame.render_stateful_widget(
                        List::new(items).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(format!(" {} ", safe(title)))
                                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD)),
                        ),
                        areas[0],
                        &mut state,
                    );
                    let mut footer = Vec::new();
                    if let Some(err) = &error_banner {
                        footer.push(
                            Line::from(format!("[!] {}", safe(err)))
                                .style(tone(Color::Red).add_modifier(Modifier::BOLD)),
                        );
                    } else {
                        footer.push(
                            Line::from("Public inputs only · Never enter private keys or passphrases")
                                .style(tone(Color::Yellow)),
                        );
                    }
                    let key_help = match specs[selected].kind {
                        FieldKind::Select(_) => {
                            "←/→/Space choose · ↑/↓/Tab field · Enter next/submit · Esc cancel"
                        }
                        FieldKind::File(_) | FieldKind::MultiSelect(_) => {
                            "Space opens picker · ↑/↓/Tab field · Enter next/submit · Esc cancel"
                        }
                        _ => {
                            "←/→/Home/End/Ctrl+W edit · ↑/↓/Tab field · Enter next/submit · Esc cancel"
                        }
                    };
                    footer.push(Line::from(key_help));
                    frame.render_widget(Paragraph::new(footer), areas[1]);
                }
            })?;
            redraw = false;
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        redraw = true;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.code == KeyCode::Esc || (small && key.code == KeyCode::Char('q')) {
            return Ok(None);
        }
        if small {
            continue;
        }
        let submit_now = (key.code == KeyCode::Char('s')
            && key.modifiers.contains(KeyModifiers::CONTROL))
            || (key.code == KeyCode::Enter && Some(selected) == last_editable(specs));
        if submit_now {
            match validate(&values) {
                Ok(parsed) => return Ok(Some(parsed)),
                Err((bad_idx, msg)) => {
                    if let Some(idx) = bad_idx.filter(|&i| i < specs.len() && specs[i].editable()) {
                        selected = idx;
                    }
                    error_banner = Some(msg);
                    continue;
                }
            }
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                selected = step_editable(specs, selected, true);
                continue;
            }
            KeyCode::BackTab | KeyCode::Up => {
                selected = step_editable(specs, selected, false);
                continue;
            }
            KeyCode::Enter => {
                selected = step_editable(specs, selected, true);
                continue;
            }
            _ => {}
        }
        if key.code == KeyCode::Char(' ') {
            let picked = match specs[selected].kind {
                FieldKind::File(kinds) => pick_file(terminal, specs[selected].label, kinds)?
                    .map(|p| p.to_string_lossy().into_owned()),
                FieldKind::MultiSelect(options) => {
                    multi_select(terminal, specs[selected].label, options, &values[selected])?
                }
                _ => None,
            };
            if let Some(value) = picked {
                values[selected] = value;
                cursors[selected] = values[selected].len();
                error_banner = None;
                continue;
            }
        }
        match specs[selected].kind {
            FieldKind::Text => {
                if edit_text_key(&mut values[selected], &mut cursors[selected], key) {
                    error_banner = None;
                }
            }
            FieldKind::Select(options) if !options.is_empty() => {
                let cur_pos = options
                    .iter()
                    .position(|(val, _)| *val == values[selected])
                    .unwrap_or(0);
                let next_pos = match key.code {
                    KeyCode::Right | KeyCode::Char(' ') => Some((cur_pos + 1) % options.len()),
                    KeyCode::Left => Some((cur_pos + options.len() - 1) % options.len()),
                    _ => None,
                };
                if let Some(pos) = next_pos {
                    values[selected] = options[pos].0.to_owned();
                    cursors[selected] = values[selected].len();
                    error_banner = None;
                }
            }
            FieldKind::Select(_)
            | FieldKind::ReadOnly
            | FieldKind::File(_)
            | FieldKind::MultiSelect(_) => {}
        }
    }
}

pub(crate) fn progress_steps(labels: &[&str], current: usize) -> Vec<String> {
    labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            format!(
                "{} {label}",
                if i < current {
                    "✓"
                } else if i == current {
                    "▶"
                } else {
                    "·"
                }
            )
        })
        .collect()
}

pub(crate) fn multi_select(
    terminal: &mut TerminalOwner,
    title: &str,
    options: &[(&str, &str)],
    initial: &str,
) -> io::Result<Option<String>> {
    let mut selected: Vec<&str> = initial.split(',').filter(|s| !s.is_empty()).collect();
    loop {
        let labels: Vec<String> = options
            .iter()
            .map(|(value, description)| {
                format!(
                    "[{}] {} {}",
                    if selected.contains(value) { "x" } else { " " },
                    value,
                    description
                )
            })
            .chain(std::iter::once("Done".to_owned()))
            .collect();
        let indices: Vec<String> = (0..labels.len()).map(|i| i.to_string()).collect();
        let choices: Vec<(&str, &str)> = indices
            .iter()
            .zip(&labels)
            .map(|(i, label)| (i.as_str(), label.as_str()))
            .collect();
        let specs = [FieldSpec::select(
            "Toggle an item, or select Done",
            "0",
            &choices,
        )];
        let Some(index) = form_validated(terminal, title, &specs, |v| {
            v[0].parse::<usize>()
                .map_err(|_| (Some(0), "Invalid selection".into()))
        })?
        else {
            return Ok(None);
        };
        if index == options.len() {
            return Ok(Some(selected.join(",")));
        }
        let value = options[index].0;
        if let Some(pos) = selected.iter().position(|v| *v == value) {
            selected.remove(pos);
        } else {
            selected.push(value);
        }
    }
}

pub(crate) fn pick_file(
    terminal: &mut TerminalOwner,
    title: &str,
    kinds: &[crate::manager::discovery::files::FileKind],
) -> io::Result<Option<PathBuf>> {
    use crate::manager::discovery::files::find_candidates;
    let mut candidates = Vec::new();
    for kind in kinds {
        for path in find_candidates(*kind) {
            if !candidates.contains(&path) {
                candidates.push(path);
            }
        }
    }
    let mut directory: Option<PathBuf> = None;
    loop {
        let mut paths = if let Some(dir) = &directory {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect();
            entries.sort();
            entries
        } else {
            candidates.clone()
        };
        if let Some(dir) = &directory
            && let Some(parent) = dir.parent()
        {
            paths.insert(0, parent.to_path_buf());
        }
        let mut labels: Vec<String> = paths
            .iter()
            .map(|p| format!("{}{}", p.display(), if p.is_dir() { "/" } else { "" }))
            .collect();
        labels.push("Browse…".into());
        labels.push("Enter path…".into());
        let indices: Vec<String> = (0..labels.len()).map(|i| i.to_string()).collect();
        let choices: Vec<(&str, &str)> = indices
            .iter()
            .zip(&labels)
            .map(|(i, label)| (i.as_str(), label.as_str()))
            .collect();
        let specs = [FieldSpec::select("Choose a file", "0", &choices)];
        let Some(index) = form_validated(terminal, title, &specs, |v| {
            v[0].parse::<usize>()
                .map_err(|_| (Some(0), "Invalid selection".into()))
        })?
        else {
            return Ok(None);
        };
        if index < paths.len() {
            if paths[index].is_dir() {
                directory = Some(paths[index].clone());
                continue;
            }
            return Ok(Some(paths[index].clone()));
        }
        if index == paths.len() {
            directory = Some(std::env::current_dir()?);
            continue;
        }
        let specs = [FieldSpec::text("Path", "")];
        return form_validated(terminal, title, &specs, |v| {
            let path = Path::new(v[0].trim());
            if path.as_os_str().is_empty() {
                return Err((Some(0), "Enter a path".into()));
            }
            if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                std::env::current_dir()
                    .map(|dir| dir.join(path))
                    .map_err(|e| (Some(0), e.to_string()))
            }
        });
    }
}

pub(super) fn review_paragraph(title: &str, lines: Vec<String>) -> io::Result<Paragraph<'_>> {
    let lines: Vec<Line> = lines
        .into_iter()
        .map(|line| Line::from(safe(&line)))
        .collect();
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(safe(title))
            .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD)),
    );
    if paragraph.line_count(78) > usize::from(u16::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "review exceeds the terminal scroll range; reformat public inputs before approval",
        ));
    }
    Ok(paragraph)
}

#[cfg(test)]
fn max_scroll(paragraph: &Paragraph<'_>, width: u16, height: u16) -> u16 {
    paragraph
        .line_count(width.saturating_sub(2))
        .saturating_sub(usize::from(height))
        .min(usize::from(u16::MAX)) as u16
}

pub(crate) fn review_mode(
    terminal: &mut TerminalOwner,
    title: &str,
    lines: Vec<String>,
    mode: ConfirmMode<'_>,
) -> io::Result<bool> {
    review_inner(terminal, title, lines, mode, None)
}

pub(crate) fn review_details(
    terminal: &mut TerminalOwner,
    title: &str,
    summary: Vec<String>,
    details: Vec<String>,
    mode: ConfirmMode<'_>,
) -> io::Result<bool> {
    review_inner(terminal, title, summary, mode, Some(details))
}

fn review_inner(
    terminal: &mut TerminalOwner,
    title: &str,
    lines: Vec<String>,
    mode: ConfirmMode<'_>,
    details: Option<Vec<String>>,
) -> io::Result<bool> {
    let base_paragraph = review_paragraph(title, lines.clone())?;
    let _ = base_paragraph;
    let mut safe_lines: Vec<Line<'static>> = lines
        .into_iter()
        .map(|line| Line::from(safe(&line)))
        .collect();
    let detail_lines = details.map(|lines| {
        lines
            .into_iter()
            .map(|line| Line::from(safe(&line)))
            .collect::<Vec<_>>()
    });
    let summary_lines = safe_lines.clone();
    let mut showing_details = false;
    let mut scroll = 0u16;
    let mut redraw = true;
    loop {
        let size = terminal.terminal()?.size()?;
        let small = size.width < 80 || size.height < 24;
        let pane_h = size.height.saturating_sub(2);
        let content_h = pane_h.saturating_sub(2).max(1);
        let temp = Paragraph::new(safe_lines.clone()).wrap(Wrap { trim: false });
        let total_lines = temp.line_count(size.width.saturating_sub(2)).max(1);
        let limit = total_lines
            .saturating_sub(usize::from(content_h))
            .min(usize::from(u16::MAX)) as u16;
        if !small {
            scroll = scroll.min(limit);
        }
        if redraw {
            let start_line = usize::from(scroll) + 1;
            let end_line = (usize::from(scroll) + usize::from(content_h)).min(total_lines);
            let title_with_pos = if total_lines > usize::from(content_h) {
                format!(
                    " {} [lines {start_line}-{end_line} of {total_lines}] ",
                    safe(title)
                )
            } else {
                format!(" {} ", safe(title))
            };
            let danger = matches!(mode, ConfirmMode::YesNo { danger: true });
            let paragraph = Paragraph::new(safe_lines.clone())
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(if danger {
                            format!(" DESTRUCTIVE — {title_with_pos}")
                        } else {
                            title_with_pos
                        })
                        .title_style(
                            tone(if danger { Color::Red } else { Color::Cyan })
                                .add_modifier(Modifier::BOLD),
                        ),
                )
                .scroll((scroll, 0));
            terminal.terminal()?.draw(|frame| {
                let areas = Layout::vertical([Constraint::Min(1), Constraint::Length(2)])
                    .split(frame.area());
                if small {
                    frame.render_widget(Paragraph::new("Resize to 80×24 · Esc/q cancel"), areas[0]);
                } else {
                    frame.render_widget(paragraph, areas[0]);
                }
                let footer = match mode {
                    ConfirmMode::None => vec![
                        Line::from(if detail_lines.is_some() {
                            "d: technical details · ↑↓/PgUp/PgDn scroll · Enter/Esc/q return"
                        } else {
                            "↑↓/PgUp/PgDn/Home/End scroll · Enter/Esc/q return"
                        })
                        .style(tone(Color::DarkGray)),
                    ],
                    ConfirmMode::Enter(action_label) => vec![
                        Line::from(format!("Enter: {} · Esc/q: cancel", safe(action_label)))
                            .style(tone(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Line::from(if detail_lines.is_some() {
                            "d: technical details · ↑↓/PgUp/PgDn scroll"
                        } else {
                            "↑↓/j k/PgUp/PgDn/g/G scroll"
                        })
                        .style(tone(Color::DarkGray)),
                    ],
                    ConfirmMode::YesNo { danger } => vec![
                        Line::from(if detail_lines.is_some() {
                            "Proceed? [y/N] · d: details · Esc/q: cancel"
                        } else {
                            "Proceed? [y/N] · Esc/q: cancel"
                        })
                        .style(
                            tone(if danger { Color::Red } else { Color::Yellow })
                                .add_modifier(Modifier::BOLD),
                        ),
                        Line::from("↑↓/j k/PgUp/PgDn/g/G scroll").style(tone(Color::DarkGray)),
                    ],
                };
                frame.render_widget(Paragraph::new(footer), areas[1]);
            })?;
            redraw = false;
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        redraw = true;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            return Ok(false);
        }
        if small {
            continue;
        }
        let page = content_h.saturating_sub(1).max(1);
        match key.code {
            KeyCode::Char('d') if detail_lines.is_some() => {
                showing_details = !showing_details;
                safe_lines = if showing_details {
                    detail_lines.as_ref().unwrap().clone()
                } else {
                    summary_lines.clone()
                };
                scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                scroll = scroll.saturating_add(1).min(limit);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                scroll = scroll.saturating_sub(1);
            }
            KeyCode::PageDown | KeyCode::Char(' ') => {
                scroll = scroll.saturating_add(page).min(limit);
            }
            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                scroll = scroll.saturating_add(page).min(limit);
            }
            KeyCode::PageUp => {
                scroll = scroll.saturating_sub(page);
            }
            KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                scroll = scroll.saturating_sub(page);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                scroll = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                scroll = limit;
            }
            KeyCode::Char('y' | 'Y') if matches!(mode, ConfirmMode::YesNo { .. }) => {
                return Ok(true);
            }
            KeyCode::Char('n' | 'N') if matches!(mode, ConfirmMode::YesNo { .. }) => {
                return Ok(false);
            }
            KeyCode::Enter => match mode {
                ConfirmMode::None => return Ok(false),
                ConfirmMode::Enter(_) => return Ok(true),
                ConfirmMode::YesNo { .. } => {}
            },
            _ => {}
        }
    }
}

pub(super) fn review(
    terminal: &mut TerminalOwner,
    title: &str,
    lines: Vec<String>,
) -> io::Result<bool> {
    review_mode(terminal, title, lines, ConfirmMode::None)
}

#[cfg(test)]
mod tests {
    use super::{
        FieldSpec, edit_text_key, label_lines, max_scroll, render_cursor_line, review_paragraph,
        step_editable, value_tail,
    };
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::style::Style;

    #[test]
    fn tail_is_safe_and_keeps_end() {
        assert_eq!(value_tail("ab\u{1b}漢字", 9), "…{1b}漢字");
        assert_eq!(value_tail("abcdef", 4), "…def");
        assert_eq!(value_tail("abc", 1), "…");
        assert_eq!(value_tail("abc", 0), "");
        assert_eq!(value_tail("ok", 20), "ok");
    }

    #[test]
    fn long_confirmation_label_wraps_without_losing_text() {
        let label = format!("> Type exactly {}", "a".repeat(64));
        let lines = label_lines(&label, 78, Style::default());
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.width() <= 78));
        assert_eq!(
            lines.iter().map(ToString::to_string).collect::<String>(),
            label
        );
    }

    #[test]
    fn review_scroll_stops_at_content() {
        let paragraph = review_paragraph("Review", vec!["x".into(); 30]).unwrap();
        assert_eq!(max_scroll(&paragraph, 80, 22), 10);
        assert_eq!(max_scroll(&paragraph, 80, 40), 0);
    }

    #[test]
    fn text_editor_supports_cursor_navigation_and_segment_deletion() {
        let mut text = "/var/lib/p2kesup/exports/pool.vkey".to_owned();
        let mut cursor = text.len();

        // Ctrl+W deletes "vkey", then "pool"
        assert!(edit_text_key(
            &mut text,
            &mut cursor,
            KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
        ));
        assert_eq!(text, "/var/lib/p2kesup/exports/pool.");
        assert!(edit_text_key(
            &mut text,
            &mut cursor,
            KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
        ));
        assert_eq!(text, "/var/lib/p2kesup/exports/");

        // Home, Right x4 ("/var"), insert "-test"
        edit_text_key(
            &mut text,
            &mut cursor,
            KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        );
        for _ in 0..4 {
            edit_text_key(
                &mut text,
                &mut cursor,
                KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
            );
        }
        for c in "-test".chars() {
            edit_text_key(
                &mut text,
                &mut cursor,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            );
        }
        assert_eq!(text, "/var-test/lib/p2kesup/exports/");
    }

    #[test]
    fn cursor_viewport_stays_within_terminal_width() {
        let long_path = format!("/home/operator/{}/artifact.kes-backup", "sub".repeat(30));
        for pos in [0, long_path.len() / 2, long_path.len()] {
            let line = render_cursor_line(&long_path, pos, true, 78);
            assert!(line.width() <= 78);
        }
    }

    #[test]
    fn step_editable_skips_readonly_fields() {
        let specs = [
            FieldSpec::readonly("Pool", "abc"),
            FieldSpec::text("Output", "/tmp/out"),
            FieldSpec::readonly("Revision", "3"),
            FieldSpec::text("Receipt", "/tmp/rec"),
        ];
        assert_eq!(step_editable(&specs, 1, true), 3);
        assert_eq!(step_editable(&specs, 3, true), 1);
        assert_eq!(step_editable(&specs, 1, false), 3);
    }
}
