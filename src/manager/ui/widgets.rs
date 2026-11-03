use std::{io, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
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

pub(super) fn public_fields(
    terminal: &mut TerminalOwner,
    title: &str,
    fields: &[(&str, &str)],
) -> io::Result<Option<Vec<String>>> {
    let mut values: Vec<String> = fields
        .iter()
        .map(|(_, value)| (*value).to_owned())
        .collect();
    if fields.is_empty() {
        return Ok(Some(values));
    }
    let mut selected = 0;
    let mut state = ListState::default();
    let mut redraw = true;
    loop {
        let size = terminal.terminal()?.size()?;
        let small = size.width < 80 || size.height < 24;
        if redraw {
            terminal.terminal()?.draw(|frame| {
                if small {
                    frame.render_widget(Paragraph::new("Resize to 80×24 · Esc/q cancel"), frame.area());
                } else {
                    let areas = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(frame.area());
                    let items: Vec<ListItem> = fields.iter().enumerate().map(|(i, (label, _))| {
                        let active = i == selected;
                        let marker = if active { ">" } else { " " };
                        let style = if active {
                            tone(Color::Cyan).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        let mut lines = label_lines(
                            &format!("{marker} {}", safe(label)), areas[0].width.saturating_sub(2), style,
                        );
                        lines.push(Line::from(format!("  {}", value_tail(&values[i], areas[0].width.saturating_sub(4)))));
                        ListItem::new(lines)
                    }).collect();
                    state.select(Some(selected));
                    frame.render_stateful_widget(
                        List::new(items).block(Block::default().borders(Borders::ALL)
                            .title(safe(title)).title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))),
                        areas[0], &mut state,
                    );
                    frame.render_widget(
                        Paragraph::new(vec![
                            Line::from("Public inputs only · No private keys or passphrases").style(tone(Color::Yellow)),
                            Line::from("Tab/Shift-Tab field · Enter next/review · Backspace edit · Esc cancel"),
                        ]), areas[1],
                    );
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
        match key.code {
            KeyCode::Tab => selected = (selected + 1) % fields.len(),
            KeyCode::BackTab => selected = (selected + fields.len() - 1) % fields.len(),
            KeyCode::Enter if selected + 1 == fields.len() => return Ok(Some(values)),
            KeyCode::Enter => selected += 1,
            KeyCode::Backspace => {
                values[selected].pop();
            }
            KeyCode::Char(c)
                if !c.is_control()
                    && values[selected].len() + c.len_utf8() <= 4096
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                values[selected].push(c);
            }
            _ => {}
        }
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

fn max_scroll(paragraph: &Paragraph<'_>, width: u16, height: u16) -> u16 {
    paragraph
        .line_count(width.saturating_sub(2))
        .saturating_sub(usize::from(height))
        .min(usize::from(u16::MAX)) as u16
}

pub(super) fn review(
    terminal: &mut TerminalOwner,
    title: &str,
    lines: Vec<String>,
    confirmation: Option<&str>,
) -> io::Result<bool> {
    let mut paragraph = review_paragraph(title, lines)?;
    let mut scroll = 0u16;
    let mut redraw = true;
    loop {
        let size = terminal.terminal()?.size()?;
        let small = size.width < 80 || size.height < 24;
        if !small {
            scroll = scroll.min(max_scroll(
                &paragraph,
                size.width,
                size.height.saturating_sub(2),
            ));
        }
        if redraw {
            paragraph = paragraph.scroll((scroll, 0));
            terminal.terminal()?.draw(|frame| {
                let areas = Layout::vertical([Constraint::Min(1), Constraint::Length(2)])
                    .split(frame.area());
                if small {
                    frame.render_widget(Paragraph::new("Resize to 80×24 · Esc/q cancel"), areas[0]);
                } else {
                    frame.render_widget(&paragraph, areas[0]);
                }
                let (footer, style) = if confirmation.is_some() {
                    (
                        "↑↓/j k scroll · Enter confirm · Esc/q cancel",
                        tone(Color::Yellow).add_modifier(Modifier::BOLD),
                    )
                } else {
                    ("↑↓/j k scroll · Esc/q return", tone(Color::DarkGray))
                };
                frame.render_widget(Paragraph::new(footer).style(style), areas[1]);
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
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                scroll = scroll.saturating_add(1).min(max_scroll(
                    &paragraph,
                    size.width,
                    size.height.saturating_sub(2),
                ));
            }
            KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
            KeyCode::Enter if confirmation.is_some() => {
                let expected = confirmation.expect("checked confirmation");
                let label = format!("Type exactly {expected}");
                return Ok(public_fields(terminal, title, &[(&label, "")])?
                    .is_some_and(|values| values[0] == expected));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{label_lines, max_scroll, review_paragraph, value_tail};
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
}
