use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use crossterm::{
    event::{self, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::{
    io::{self, Write},
    fs::OpenOptions,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
    process::Command,
};

mod avc;
mod booleans;
mod modules;
mod rollback;
mod safe_config;
mod state;
mod file_contexts;
mod ports;

use avc::AVCManager;
use booleans::BooleanManager;
use modules::ModuleManager;
use rollback::{RollbackManager, SystemState};
use safe_config::SafeModeConfig;
use state::{AppState, CurrentView, InputMode, PopupType};
use file_contexts::{FileContext, FileContextManager};
use ports::{PortContext, PortManager};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    simulate: bool,

    #[arg(short, long)]
    logfile: Option<String>,

    #[arg(short, long)]
    debug: bool,

    #[arg(long, default_value_t = 5)]
    update_interval: u64,

    #[arg(long)]
    ascii: bool,
}

#[derive(Clone)]  // <<< ОБЯЗАТЕЛЬНО добавь это в booleans.rs и safe_config.rs тоже!
struct App {
    state: AppState,
    avc_manager: AVCManager,
    module_manager: ModuleManager,
    boolean_manager: BooleanManager,
    rollback_manager: RollbackManager,
    safe_config: SafeModeConfig,
    file_context_manager: FileContextManager,
    port_manager: PortManager,
    last_update: Instant,
    update_interval: Duration,
    should_quit: bool,
    status_message: Option<(String, Color)>,
    debug_mode: bool,
    simulation_mode: bool,
    ascii_mode: bool,
    is_busy: bool,
    spinner_idx: usize,
    pending_rx: Option<Receiver<TaskResult>>,
    logfile_path: Option<PathBuf>,
}

struct TaskResult {
    action: String,
    description: String,
    rollback_commands: Vec<String>,
    error: Option<String>,
}

impl App {
    fn new(simulation: bool, debug: bool, update_interval_secs: u64, ascii_mode: bool) -> Result<Self> {
        let mut app = Self {
            state: AppState::new(),
            avc_manager: AVCManager::new(),
            module_manager: ModuleManager::new(),
            boolean_manager: BooleanManager::new(),
            rollback_manager: RollbackManager::new(),
            safe_config: SafeModeConfig::default(),
            file_context_manager: FileContextManager::new(),
            port_manager: PortManager::new(),
            last_update: Instant::now(),
            update_interval: Duration::from_secs(update_interval_secs.max(1)),
            should_quit: false,
            status_message: None,
            debug_mode: debug,
            simulation_mode: simulation,
            ascii_mode,
            is_busy: false,
            spinner_idx: 0,
            pending_rx: None,
            logfile_path: None,
        };

        app.refresh_data()?;
        Ok(app)
    }

    fn refresh_data(&mut self) -> Result<()> {
        if self.simulation_mode {
            self.load_simulation_data()?;
        } else {
            self.load_real_data()?;
        }
        Ok(())
    }

    fn load_real_data(&mut self) -> Result<()> {
        if let Err(e) = self.avc_manager.load_avc_logs() { self.set_status(format!("Failed: {}", e), Color::Red); }
        if let Err(e) = self.module_manager.load_modules() { self.set_status(format!("Failed: {}", e), Color::Red); }
        if let Err(e) = self.boolean_manager.load_booleans() { self.set_status(format!("Failed: {}", e), Color::Red); }
        if let Err(e) = self.file_context_manager.load_file_contexts() { self.set_status(format!("Failed: {}", e), Color::Red); }
        if let Err(e) = self.port_manager.load_ports() { self.set_status(format!("Failed: {}", e), Color::Red); }
        Ok(())
    }

    fn load_simulation_data(&mut self) -> Result<()> {
        self.avc_manager.load_simulation_data();
        self.module_manager.load_simulation_data();
        self.boolean_manager.load_simulation_data();
        self.file_context_manager.contexts = vec![FileContext { path: "/var/www".into(), context: "httpd_sys_content_t".into() }];
        self.port_manager.ports = vec![PortContext { port: "80".into(), protocol: "tcp".into(), context: "http_port_t".into() }];
        Ok(())
    }

    fn set_status(&mut self, message: String, color: Color) {
        self.status_message = Some((message, color));
    }

    fn handle_key_event(&mut self, key: KeyCode) -> Result<()> {
        if self.is_busy {
            match key {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                _ => {}
            }
            return Ok(());
        }

        if self.state.input_mode != InputMode::Normal {
            match key {
                KeyCode::Enter => self.submit_input()?,
                KeyCode::Esc => self.state.reset_mode(),
                KeyCode::Char(c) => {
                    self.state.input_buffer.push(c);
                    self.state.input_cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if !self.state.input_buffer.is_empty() {
                        self.state.input_buffer.pop();
                        self.state.input_cursor_position = self.state.input_cursor_position.saturating_sub(1);
                    }
                }
                _ => {}
            }
            return Ok(());
        }

        match key {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.show_help_popup(),
            KeyCode::Char('/') => self.state.enter_search_mode(),
            KeyCode::Char('a') => self.show_add_popup(),
            KeyCode::Enter => self.execute_current_selection()?,
            KeyCode::Char('h') | KeyCode::Left => self.state.previous_view(),
            KeyCode::Char('l') | KeyCode::Right => self.state.next_view(),
            KeyCode::Char('k') | KeyCode::Up => self.state.previous_item(),
            KeyCode::Char('j') | KeyCode::Down => self.state.next_item(),
            KeyCode::Char('r') => self.rollback_last_change()?,
            KeyCode::Char('s') => self.apply_safe_settings_async()?,
            KeyCode::Char('R') => {
                self.refresh_data()?;
                self.set_status("Data refreshed".to_string(), Color::Green);
            }
            KeyCode::Char('1') => self.state.current_view = CurrentView::Dashboard,
            KeyCode::Char('2') => self.state.current_view = CurrentView::AVCAlerts,
            KeyCode::Char('3') => self.state.current_view = CurrentView::ModuleManager,
            KeyCode::Char('4') => self.state.current_view = CurrentView::BooleanManager,
            KeyCode::Char('5') => self.state.current_view = CurrentView::RollbackHistory,
            KeyCode::Char('6') => self.state.current_view = CurrentView::SafeSettings,
            KeyCode::Char('7') => self.state.current_view = CurrentView::FileContexts,
            KeyCode::Char('8') => self.state.current_view = CurrentView::Ports,
            _ => {}
        }
        Ok(())
    }

    fn submit_input(&mut self) -> Result<()> {
        let input = self.state.input_buffer.clone();
        match self.state.popup_type {
            PopupType::Search => {
                self.state.search_query = input;
                self.state.reset_mode();
            }
            PopupType::AddPort => {
                let parts: Vec<&str> = input.split_whitespace().collect();
                if parts.len() == 3 {
                    self.port_manager.add_port(parts[0], parts[1], parts[2], self.simulation_mode)?;
                    self.set_status(format!("Port {} added", parts[0]), Color::Green);
                } else {
                    self.set_status("Format: PORT PROTO TYPE".to_string(), Color::Red);
                }
                self.state.reset_mode();
            }
            PopupType::AddFileContext => {
                let parts: Vec<&str> = input.split_whitespace().collect();
                if parts.len() == 2 {
                    self.file_context_manager.add_file_context(parts[0], parts[1], self.simulation_mode)?;
                    self.set_status(format!("Context added for {}", parts[0]), Color::Green);
                } else {
                    self.set_status("Format: PATH TYPE".to_string(), Color::Red);
                }
                self.state.reset_mode();
            }
            _ => self.state.reset_mode(),
        }
        Ok(())
    }

    fn show_add_popup(&mut self) {
        match self.state.current_view {
            CurrentView::Ports => self.state.enter_input_mode(PopupType::AddPort),
            CurrentView::FileContexts => self.state.enter_input_mode(PopupType::AddFileContext),
            _ => self.set_status("Add not supported here".into(), Color::Yellow),
        }
    }

    fn show_help_popup(&mut self) {
        let key = match self.state.current_view {
            CurrentView::BooleanManager => {
                if let Some(idx) = self.state.selected_index {
                    self.boolean_manager.booleans.get(idx).map(|b| b.name.clone())
                } else { None }
            },
            CurrentView::AVCAlerts => Some("avc_general".to_string()),
            _ => None
        };

        if let Some(k) = key {
            if let Some(advice) = self.advisor.get_advice(&k) {
                let text = format!("{}\n\nРиск: {}\nСовет: {}", advice.description, advice.risk, advice.suggestion);
                self.state.popup_type = PopupType::Help(text);
                self.state.input_mode = InputMode::Editing;
            } else {
                self.set_status("Нет совета для этого элемента".to_string(), Color::Yellow);
            }
        } else {
            self.set_status("Выберите элемент для справки".to_string(), Color::Yellow);
        }
    }

    fn execute_current_selection(&mut self) -> Result<()> {
        if let Some(selected) = self.state.selected_index {
            match self.state.current_view {
                CurrentView::Dashboard => self.handle_dashboard_selection(selected)?,
                CurrentView::AVCAlerts => self.handle_avc_selection(selected)?,
                CurrentView::ModuleManager => self.handle_module_selection(selected)?,
                CurrentView::BooleanManager => self.handle_boolean_selection(selected)?,
                CurrentView::RollbackHistory => self.handle_rollback_selection(selected)?,
                CurrentView::SafeSettings => self.handle_safe_settings_selection(selected)?,
                CurrentView::FileContexts => self.handle_file_context_selection(selected)?,
                CurrentView::Ports => self.handle_port_selection(selected)?,
            }
        }
        Ok(())
    }

    fn handle_dashboard_selection(&mut self, selected: usize) -> Result<()> {
        match selected {
            0 => self.state.current_view = CurrentView::AVCAlerts,
            1 => self.state.current_view = CurrentView::ModuleManager,
            2 => self.state.current_view = CurrentView::BooleanManager,
            3 => self.state.current_view = CurrentView::SafeSettings,
            4 => self.state.current_view = CurrentView::RollbackHistory,
            5 => self.state.current_view = CurrentView::FileContexts,
            6 => self.state.current_view = CurrentView::Ports,
            _ => {}
        }
        Ok(())
    }

    fn handle_avc_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(alert) = self.avc_manager.alerts.get(selected) {
            let solution = self.avc_manager.analyze_avc(alert);
            if let Some(sol) = solution {
                let previous_state = self.get_current_system_state()?;
                self.avc_manager.apply_solution(&sol, self.simulation_mode)?;
                let new_state = self.get_current_system_state()?;
                let rollback_commands = sol.commands.iter().map(|c| self.reverse_command(c)).collect();
                self.rollback_manager.record_change("AVC Solution".to_string(), sol.description.clone(), previous_state, new_state, rollback_commands);
                self.set_status(format!("Applied: {}", sol.description), Color::Green);
            }
        }
        Ok(())
    }

    fn reverse_command(&self, cmd: &str) -> String {
        if cmd.contains("setsebool") {
            cmd.replace("1", "temp").replace("0", "1").replace("temp", "0")
        } else if cmd.contains("semodule -i") {
            cmd.replace("-i", "-r")
        } else {
            "".to_string()
        }
    }

    fn handle_module_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(module) = self.module_manager.modules.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("semodule {} {}", if module.enabled { "-d" } else { "-e" }, module.name);
            if module.enabled { self.module_manager.disable_module(&module.name, self.simulation_mode)?; }
            else { self.module_manager.enable_module(&module.name, self.simulation_mode)?; }
            let new_state = self.get_current_system_state()?;
            self.rollback_manager.record_change("Module Toggle".to_string(), format!("Toggled {}", module.name), previous_state, new_state, vec![rollback_command]);
        }
        Ok(())
    }

    fn handle_boolean_selection(&mut self, selected: usize) -> Result<()> {
        let booleans: Vec<_> = if self.state.search_query.is_empty() {
            self.boolean_manager.booleans.clone()
        } else {
            self.boolean_manager.booleans.iter().filter(|b| b.name.contains(&self.state.search_query)).cloned().collect()
        };

        if let Some(boolean) = booleans.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("setsebool -P {} {}", boolean.name, if boolean.current_value { "off" } else { "on" });
            self.boolean_manager.set_boolean(&boolean.name, !boolean.current_value, self.simulation_mode)?;
            let new_state = self.get_current_system_state()?;
            self.rollback_manager.record_change("Boolean Toggle".to_string(), format!("Toggled {}", boolean.name), previous_state, new_state, vec![rollback_command]);
        }
        Ok(())
    }

    fn handle_rollback_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(change) = self.rollback_manager.change_history.get(selected).cloned() {
            self.rollback_manager.rollback_to_id(&change.id, self.simulation_mode)?;
            self.set_status(format!("Rolled back to {}", change.timestamp), Color::Yellow);
        }
        Ok(())
    }

    fn handle_safe_settings_selection(&mut self, selected: usize) -> Result<()> {
        match selected {
            0 => self.apply_safe_settings_async()?,
            1 => self.apply_restrictive_settings_async()?,
            _ => {}
        }
        Ok(())
    }

    fn handle_file_context_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(context) = self.file_context_manager.contexts.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("semanage fcontext -a -t {} {}", context.context, context.path);
            self.file_context_manager.remove_file_context(&context.path, self.simulation_mode)?;
            let new_state = self.get_current_system_state()?;
            self.rollback_manager.record_change("File Context Remove".to_string(), format!("Removed {}", context.path), previous_state, new_state, vec![rollback_command]);
        }
        Ok(())
    }

    fn handle_port_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(port) = self.port_manager.ports.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("semanage port -a -t {} -p {} {}", port.context, port.protocol, port.port);
            self.port_manager.remove_port(&port.port, &port.protocol, self.simulation_mode)?;
            let new_state = self.get_current_system_state()?;
            self.rollback_manager.record_change("Port Remove".to_string(), format!("Removed port {}", port.port), previous_state, new_state, vec![rollback_command]);
        }
        Ok(())
    }

    fn rollback_last_change(&mut self) -> Result<()> {
        self.rollback_manager.rollback_last(self.simulation_mode)?;
        self.set_status("Rolled back last change".to_string(), Color::Yellow);
        Ok(())
    }

    fn apply_safe_settings_async(&mut self) -> Result<()> {
        if self.is_busy { return Ok(()); }
        let simulation = self.simulation_mode;
        let mut boolean_manager = self.boolean_manager.clone();
        let safe_config = self.safe_config.clone();
        let (tx, rx): (Sender<TaskResult>, Receiver<TaskResult>) = mpsc::channel();
        self.pending_rx = Some(rx);
        self.is_busy = true;
        self.set_status("Applying safe settings...".to_string(), Color::Yellow);
        thread::spawn(move || {
            let result = safe_config.apply_safe_defaults(&mut boolean_manager, simulation);
            match result {
                Ok(rollback) => { let _ = tx.send(TaskResult { action: "Safe Defaults".into(), description: "Applied safe defaults".into(), rollback_commands: rollback, error: None }); }
                Err(e) => { let _ = tx.send(TaskResult { action: "Safe Defaults".into(), description: "Failed".into(), rollback_commands: vec![], error: Some(e.to_string()) }); }
            }
        });
        Ok(())
    }

    fn apply_restrictive_settings_async(&mut self) -> Result<()> {
        if self.is_busy { return Ok(()); }
        let simulation = self.simulation_mode;
        let mut boolean_manager = self.boolean_manager.clone();
        let safe_config = self.safe_config.clone();
        let (tx, rx): (Sender<TaskResult>, Receiver<TaskResult>) = mpsc::channel();
        self.pending_rx = Some(rx);
        self.is_busy = true;
        self.set_status("Applying restrictive settings...".to_string(), Color::Yellow);
        thread::spawn(move || {
            let result = safe_config.apply_restrictive_policy(&mut boolean_manager, simulation);
            match result {
                Ok(rollback) => { let _ = tx.send(TaskResult { action: "Restrictive Policy".into(), description: "Applied restrictive policy".into(), rollback_commands: rollback, error: None }); }
                Err(e) => { let _ = tx.send(TaskResult { action: "Restrictive Policy".into(), description: "Failed".into(), rollback_commands: vec![], error: Some(e.to_string()) }); }
            }
        });
        Ok(())
    }

    fn log_error(&mut self, message: &str) {
        let path = self.logfile_path.clone().unwrap_or_else(|| PathBuf::from("selab.log"));
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "[{}] {}", Utc::now().to_rfc3339(), message);
        }
    }

    fn get_current_system_state(&self) -> Result<SystemState> {
        let selinux_mode = if self.simulation_mode { "Enforcing".to_string() } else {
            String::from_utf8_lossy(&std::process::Command::new("getenforce").output()?.stdout).trim().to_string()
        };
        Ok(SystemState {
            timestamp: Utc::now().to_rfc3339(),
           selinux_mode,
           booleans: self.boolean_manager.booleans.clone(),
           modules: self.module_manager.modules.clone(),
           file_contexts: self.file_context_manager.contexts.iter().map(|c| format!("{}:{}", c.path, c.context)).collect(),
           ports: self.port_manager.ports.iter().map(|p| format!("{}/{}:{}", p.port, p.protocol, p.context)).collect(),
        })
    }

    fn tick(&mut self) -> Result<()> {
        if self.last_update.elapsed() > self.update_interval {
            self.refresh_data()?;
            self.last_update = Instant::now();
        }
        if self.is_busy {
            self.spinner_idx = (self.spinner_idx + 1) % 4;
            if let Some(rx) = &self.pending_rx {
                match rx.try_recv() {
                    Ok(res) => {
                        self.is_busy = false;
                        self.pending_rx = None;
                        if let Some(err) = res.error {
                            self.set_status(format!("{}: {}", res.description, err), Color::Red);
                        } else {
                            let _ = self.refresh_data();
                            let previous = self.get_current_system_state()?;
                            let new = self.get_current_system_state()?;
                            self.rollback_manager.record_change(res.action, res.description.clone(), previous, new, res.rollback_commands);
                            self.set_status(res.description, Color::Green);
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.is_busy = false;
                        self.pending_rx = None;
                    }
                }
            }
        }
        Ok(())
    }

    fn ui<B: Backend>(&mut self, f: &mut Frame<B>) {
        let chunks = Layout::Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
                     Constraint::Min(0),
                     Constraint::Length(3),
        ])
        .split(f.size());

        let current_len = match self.state.current_view {
            CurrentView::BooleanManager => {
                if self.state.search_query.is_empty() {
                    self.boolean_manager.booleans.len()
                } else {
                    self.boolean_manager.booleans.iter().filter(|b| b.name.contains(&self.state.search_query)).count()
                }
            },
            CurrentView::Dashboard => 7,
            CurrentView::AVCAlerts => self.avc_manager.alerts.len(),
            CurrentView::ModuleManager => self.module_manager.modules.len(),
            CurrentView::RollbackHistory => self.rollback_manager.change_history.len(),
            CurrentView::SafeSettings => 6,
            CurrentView::FileContexts => self.file_context_manager.contexts.len(),
            CurrentView::Ports => self.port_manager.ports.len(),
        };
        self.state.set_current_len(current_len);

        let tabs = Tabs::new(vec!["1: Dash", "2: AVC", "3: Mods", "4: Bool", "5: Roll", "6: Safe", "7: File", "8: Port"])
        .block(Block::default().borders(Borders::ALL).title("Views"))
        .select(self.state.current_view as usize)
        .highlight_style(Style::default().fg(Color::Yellow));

        f.render_widget(tabs, chunks[0]);

        match self.state.current_view {
            CurrentView::Dashboard => self.render_dashboard(f, chunks[1]),
            CurrentView::AVCAlerts => self.render_avc_alerts(f, chunks[1]),
            CurrentView::ModuleManager => self.render_modules(f, chunks[1]),
            CurrentView::BooleanManager => self.render_booleans(f, chunks[1]),
            CurrentView::RollbackHistory => self.render_rollback_history(f, chunks[1]),
            CurrentView::SafeSettings => self.render_safe_settings(f, chunks[1]),
            CurrentView::FileContexts => self.render_file_contexts(f, chunks[1]),
            CurrentView::Ports => self.render_ports(f, chunks[1]),
        }

        self.render_footer(f, chunks[2]);

        if self.state.popup_type != PopupType::None {
            self.render_popup(f);
        }
    }

    fn render_dashboard<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items = vec![
            ListItem::new("AVC Alerts"),
            ListItem::new("Module Manager"),
            ListItem::new("Boolean Manager"),
            ListItem::new("Safe Settings"),
            ListItem::new("Rollback History"),
            ListItem::new("File Contexts"),
            ListItem::new("Ports"),
        ];
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Dashboard")).highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_avc_alerts<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.avc_manager.alerts.iter().map(|alert| {
            ListItem::new(format!("{} {} [{}:{}]", alert.severity.clone() as u8, alert.comm, alert.target_class, alert.permission))
        }).collect();
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("AVC Alerts")).highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_modules<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.module_manager.modules.iter().map(|m| {
            ListItem::new(format!("{} {}", if m.enabled { "[+]" } else { "[-]" }, m.name))
        }).collect();
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Modules")).highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_booleans<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let booleans_to_show: Vec<_> = if self.state.search_query.is_empty() {
            self.boolean_manager.booleans.clone()
        } else {
            self.boolean_manager.booleans.iter().filter(|b| b.name.contains(&self.state.search_query)).cloned().collect()
        };
        let items: Vec<ListItem> = booleans_to_show.iter().map(|b| {
            ListItem::new(format!("{} {} ({})", if b.current_value { "[ON]" } else { "[OFF]" }, b.name, b.description))
        }).collect();
        let title = if self.state.search_query.is_empty() { "Booleans".to_string() } else { format!("Booleans (Filter: {})", self.state.search_query) };
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title)).highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_rollback_history<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.rollback_manager.change_history.iter().map(|c| ListItem::new(format!("{} - {}", c.timestamp, c.description))).collect();
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("History")).highlight_style(Style::default().fg(Color::Red));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_safe_settings<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items = vec![ListItem::new("[*] Safe Defaults"), ListItem::new("[*] Restrictive Policy")];
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Safe Settings")).highlight_style(Style::default().fg(Color::Green));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_file_contexts<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.file_context_manager.contexts.iter().map(|c| ListItem::new(format!("{} -> {}", c.path, c.context))).collect();
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("File Contexts")).highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_ports<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.port_manager.ports.iter().map(|p| ListItem::new(format!("{}/{} -> {}", p.port, p.protocol, p.context))).collect();
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Ports")).highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_footer<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let mut text = String::new();
        if self.is_busy { text.push_str("[Working...] "); }
        if self.state.input_mode != InputMode::Normal {
            text.push_str("INPUT MODE (Esc to cancel, Enter to confirm) ");
        } else {
            text.push_str("?:Help  /:Search  a:Add  q:Quit  Enter:Action  h/j/k/l:Nav");
        }
        let p = if let Some((msg, color)) = &self.status_message {
            Paragraph::new(format!("{} | Status: {}", text, msg)).style(Style::default().fg(*color))
        } else {
            Paragraph::new(text).style(Style::default().fg(Color::Gray))
        }.block(Block::default().borders(Borders::ALL));
        f.render_widget(p, area);
    }

    fn render_popup<B: Backend>(&mut self, f: &mut Frame<B>) {
        let area = self.centered_rect(60, 50, f.size());
        let block = Block::default().borders(Borders::ALL).style(Style::default().bg(Color::DarkGray));
        match &self.state.popup_type {
            PopupType::Search => {
                f.render_widget(Paragraph::new(format!("Search: {}", self.state.input_buffer)).block(block.title("Filter / Search")).style(Style::default().fg(Color::White)), area);
            },
            PopupType::Help(text) => {
                f.render_widget(Paragraph::new(text.as_str()).block(block.title("Advice / Help")).wrap(Wrap { trim: true }).style(Style::default().fg(Color::White)), area);
            },
            PopupType::AddPort => {
                f.render_widget(Paragraph::new(format!("Example: 8080 tcp http_port_t\n> {}", self.state.input_buffer)).block(block.title("Add Port")).style(Style::default().fg(Color::White)), area);
            },
            PopupType::AddFileContext => {
                f.render_widget(Paragraph::new(format!("Example: /var/www/site httpd_sys_content_t\n> {}", self.state.input_buffer)).block(block.title("Add Context")).style(Style::default().fg(Color::White)), area);
            },
            _ => {}
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.simulate, cli.debug, cli.update_interval, cli.ascii)?;
    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
             LeaveAlternateScreen,
             DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {err}");
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| app.ui(f))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key_event(key.code)?;
            }
        }

        app.tick()?;

        if app.should_quit {
            return Ok(());
        }
    }
}
