//! Full-screen, best-effort Windows installation dashboard.
//! Falls back to the existing line-oriented output for CI, pipes, and legacy terminals.
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::{
    collections::VecDeque,
    io::{self, IsTerminal},
    panic::{self, AssertUnwindSafe},
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
enum Event {
    Plan(Vec<String>),
    Stage(usize, usize, String),
    Done(String),
    Activity(String, u64),
    Download(u8),
    Bootstrap(u8),
    Log(String),
    Stop,
}

static CHANNEL: OnceLock<Mutex<Option<Sender<Event>>>> = OnceLock::new();

fn channel() -> &'static Mutex<Option<Sender<Event>>> {
    CHANNEL.get_or_init(|| Mutex::new(None))
}

fn send(event: Event) -> bool {
    if let Ok(lock) = channel().lock() {
        if let Some(sender) = &*lock {
            return sender.send(event).is_ok();
        }
    }
    false
}

pub fn active() -> bool {
    channel().lock().is_ok_and(|lock| lock.is_some())
}

pub fn plan(steps: Vec<String>) -> bool {
    send(Event::Plan(steps))
}

pub fn stage(index: usize, total: usize, name: &str) -> bool {
    send(Event::Stage(index, total, name.into()))
}

pub fn done(message: &str) -> bool {
    send(Event::Done(message.into()))
}

pub fn activity(label: &str, seconds: u64) -> bool {
    send(Event::Activity(label.into(), seconds))
}

pub fn download(percent: u8) -> bool {
    send(Event::Download(percent))
}

pub fn bootstrap(percent: u8) -> bool {
    send(Event::Bootstrap(percent))
}

pub fn log(message: &str) -> bool {
    send(Event::Log(message.into()))
}

fn eligible() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var_os("RATRIYX_NO_TUI").is_none()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map_or(true, |t| t != "dumb")
}

#[derive(Default)]
struct Dashboard {
    total: usize,
    index: usize,
    completed: usize,
    labels: Vec<String>,
    current_since: Option<Instant>,
    download: Option<u8>,
    bootstrap: Option<u8>,
    activity: String,
    logs: VecDeque<String>,
    tick: usize,
}

impl Dashboard {
    fn update(&mut self, event: Event) -> bool {
        match event {
            Event::Plan(steps) => {
                self.total = steps.len();
                self.labels = steps;
                self.index = 0;
                self.completed = 0;
            }
            Event::Stage(index, total, name) => {
                self.completed = index.saturating_sub(1);
                self.total = total.max(1);
                self.index = index;
                if self.labels.len() == total && index > 0 {
                    self.labels[index - 1] = name.clone();
                } else {
                    self.labels.push(name.clone());
                }
                self.current_since = Some(Instant::now());
                self.download = None;
                self.bootstrap = None;
                self.activity = name;
            }
            Event::Done(message) => {
                self.push_log(format!("[OK] {message}"));
                // Last stage is completed when the success signal arrives.
                if message.contains("IsTor=true") {
                    self.completed = self.total;
                }
            }
            Event::Activity(label, seconds) => {
                self.activity = format!("{label} ({seconds}s)");
            }
            Event::Download(percent) => {
                self.download = Some(percent.min(100));
            }
            Event::Bootstrap(percent) => {
                self.bootstrap = Some(percent.min(100));
            }
            Event::Log(message) => self.push_log(message),
            Event::Stop => return false,
        }
        true
    }

    fn push_log(&mut self, message: String) {
        let line = message.trim();
        if line.is_empty() {
            return;
        }
        let clipped: String = line.chars().take(180).collect();
        if self.logs.back().is_some_and(|last| last == &clipped) {
            return;
        }
        self.logs.push_back(clipped);
        while self.logs.len() > 12 {
            self.logs.pop_front();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Component {
    Tor,
    Proxy,
    Verification,
}

fn component(label: &str) -> Component {
    let lower = label.to_ascii_lowercase();
    if lower.starts_with("verif") || lower.contains("istor") || lower.contains("route") {
        Component::Verification
    } else if lower.contains("proxy") {
        Component::Proxy
    } else {
        Component::Tor
    }
}

fn component_progress(state: &Dashboard, target: Component) -> (usize, usize) {
    let total = state
        .labels
        .iter()
        .filter(|name| component(name) == target)
        .count();
    let completed = state
        .labels
        .iter()
        .enumerate()
        .filter(|(i, name)| *i < state.completed && component(name) == target)
        .count();
    (completed, total)
}

fn draw(frame: &mut Frame, state: &Dashboard) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(1),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "  R A T R I Y X  ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " / PRIVATE NETWORK SETUP",
            Style::default().fg(Color::White),
        ),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title(" INSTALL "));
    frame.render_widget(title, rows[0]);

    let ratio = if state.total > 0 {
        state.completed as f64 / state.total as f64
    } else {
        0.0
    };
    let overall = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" VERIFIED STAGES "),
        )
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
        .ratio(ratio)
        .label(format!("{}/{} complete", state.completed, state.total));
    frame.render_widget(overall, rows[1]);

    let steps: Vec<ListItem> = state
        .labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let (symbol, color) = if i < state.completed {
                ("[OK]", Color::Green)
            } else if i + 1 == state.index {
                ("[..]", Color::Yellow)
            } else {
                ("[  ]", Color::DarkGray)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {symbol} "), Style::default().fg(color)),
                Span::raw(label.as_str()),
            ]))
        })
        .collect();
    frame.render_widget(
        List::new(steps).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" INSTALLATION PIPELINE "),
        ),
        rows[2],
    );

    // Component gauges represent completed verified stages, not estimated
    // progress within WinGet, which does not expose a reliable percentage.
    let component_area = rows[3];
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .title(" COMPONENT STAGES "),
        component_area,
    );
    let bar_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(ratatui::layout::Rect {
            x: component_area.x.saturating_add(1),
            y: component_area.y.saturating_add(1),
            width: component_area.width.saturating_sub(2),
            height: component_area.height.saturating_sub(2),
        });
    for (i, (target, title, color)) in [
        (Component::Tor, "Tor       ", Color::LightCyan),
        (Component::Proxy, "Proxy     ", Color::Blue),
        (Component::Verification, "Route     ", Color::LightGreen),
    ]
    .iter()
    .enumerate()
    {
        let (complete, total) = component_progress(state, *target);
        let ratio = if total == 0 {
            0.0
        } else {
            complete as f64 / total as f64
        };
        frame.render_widget(
            Gauge::default()
                .ratio(ratio)
                .gauge_style(Style::default().fg(*color))
                .label(format!("{title} {complete}/{total} stages")),
            bar_rows[i],
        );
    }

    let spinner = ["|", "/", "-", "\\"][state.tick % 4];
    let elapsed = state
        .current_since
        .map_or(0, |time| time.elapsed().as_secs());
    let live_label = if let Some(percent) = state.bootstrap {
        format!("Tor bootstrap {percent}% | {spinner} {elapsed}s")
    } else if let Some(percent) = state.download {
        format!("Tor transfer {percent}% | {spinner} {elapsed}s")
    } else {
        format!("{spinner} {} | {elapsed}s", state.activity)
    };
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" CURRENT OPERATION "),
            )
            .gauge_style(Style::default().fg(Color::LightBlue))
            .ratio(
                state
                    .bootstrap
                    .or(state.download)
                    .map_or(0.0, |p| f64::from(p) / 100.0),
            )
            .label(live_label),
        rows[4],
    );

    let recent = state
        .logs
        .iter()
        .rev()
        .take(4)
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    frame.render_widget(
        Paragraph::new(recent)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" LIVE OUTPUT "),
            )
            .wrap(Wrap { trim: true }),
        rows[4],
    );
    frame.render_widget(
        Paragraph::new(
            "  Local-only proxies  |  No system-wide proxy changes  |  Logs preserved on error",
        ),
        rows[6],
    );
}

fn worker(receiver: Receiver<Event>, ready: Sender<bool>) {
    let Ok(mut terminal) = ratatui::try_init() else {
        let _ = ready.send(false);
        return;
    };
    let _ = ready.send(true);
    let mut state = Dashboard::default();
    loop {
        match receiver.recv_timeout(Duration::from_millis(120)) {
            Ok(event) => {
                if !state.update(event) {
                    break;
                }
                while let Ok(event) = receiver.try_recv() {
                    if !state.update(event) {
                        ratatui::restore();
                        return;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        state.tick += 1;
        if terminal.draw(|frame| draw(frame, &state)).is_err() {
            break;
        }
    }
    ratatui::restore();
}

pub fn with_dashboard<F, R>(work: F) -> R
where
    F: FnOnce() -> R,
{
    if !eligible() || active() {
        return work();
    }
    let (sender, receiver) = mpsc::channel();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let handle = thread::spawn(move || worker(receiver, ready_sender));
    if ready_receiver.recv_timeout(Duration::from_secs(3)).ok() != Some(true) {
        drop(sender);
        let _ = handle.join();
        return work();
    }
    if let Ok(mut channel) = channel().lock() {
        *channel = Some(sender.clone());
    }
    let result = panic::catch_unwind(AssertUnwindSafe(work));
    if let Ok(mut channel) = channel().lock() {
        *channel = None;
    }
    let _ = sender.send(Event::Stop);
    let _ = handle.join();
    match result {
        Ok(value) => value,
        Err(payload) => panic::resume_unwind(payload),
    }
}

/// Stream process output to the dashboard without flooding it with
/// raw WinGet spinner codes or destructive carriage-return sequences.
pub fn ingest_output(bytes: &[u8]) {
    if !active() {
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    for part in text.split(['\r', '\n']) {
        let clean: String = part.chars().filter(|ch| !ch.is_control()).collect();
        let clean = clean.trim();
        if !clean.is_empty() && clean.len() < 256 {
            let _ = log(clean);
        }
    }
}

/// Curl progress meter is streamed as real percentages, not estimates.
pub fn ingest_curl(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for (at, ch) in text.char_indices() {
        if ch != '%' {
            continue;
        }
        let before = &text[..at];
        let number = before
            .rsplit(|c: char| !(c.is_ascii_digit() || c == '.'))
            .next()
            .unwrap_or("");
        if let Ok(value) = number.parse::<f64>() {
            if (0.0..=100.0).contains(&value) {
                let _ = download(value.round() as u8);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratatui_dashboard_renders_real_pipeline_on_small_terminals() {
        for (width, height) in [(100, 36), (60, 22)] {
            let backend = ratatui::backend::TestBackend::new(width, height);
            let mut terminal = ratatui::Terminal::new(backend).unwrap();
            let mut state = Dashboard::default();
            state.update(Event::Plan(vec![
                "Downloading Tor".into(),
                "Starting Tor".into(),
                "Preparing embedded proxy".into(),
                "Starting embedded proxy".into(),
                "Verifying IsTor".into(),
            ]));
            state.update(Event::Stage(3, 5, "Preparing embedded proxy".into()));
            state.update(Event::Activity("Binding a temporary proxy port".into(), 8));
            terminal.draw(|frame| draw(frame, &state)).unwrap();
        }
    }

    #[test]
    fn component_gauges_count_real_completed_stages() {
        let mut state = Dashboard::default();
        state.update(Event::Plan(vec![
            "Downloading Tor".into(),
            "Starting Tor".into(),
            "Preparing embedded proxy".into(),
            "Starting embedded proxy".into(),
            "Verifying IsTor".into(),
        ]));
        state.update(Event::Stage(3, 5, "Preparing embedded proxy".into()));
        assert_eq!(component_progress(&state, Component::Tor), (2, 2));
        assert_eq!(component_progress(&state, Component::Proxy), (0, 2));
        assert_eq!(component_progress(&state, Component::Verification), (0, 1));
        state.update(Event::Stage(5, 5, "Verifying IsTor".into()));
        state.update(Event::Done("IsTor=true".into()));
        assert_eq!(component_progress(&state, Component::Proxy), (2, 2));
        assert_eq!(component_progress(&state, Component::Verification), (1, 1));
    }
}
