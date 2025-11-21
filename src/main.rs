use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

// Подключение модулей
mod advisor;
mod avc;
mod booleans;
mod file_contexts;
mod modules;
mod ports;
mod rollback;
mod safe_config;
mod state;

use advisor::Advisor;
use avc::AVCManager;
use booleans::BooleanManager;
use file_contexts::{FileContext, FileContextManager};
use modules::ModuleManager;
use ports::{PortContext, PortManager};
use rollback::{RollbackManager, SystemState};
use safe_config::SafeModeConfig;
use state::{AppState, CurrentView, InputMode, PopupType};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    simulate: bool,
    #[arg(short, long)]
    logfile: Option<String>,
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = 2)]
    update_interval: u64,
    #[arg(long)]
    ascii: bool,
}

// Результат выполнения фоновой задачи
struct TaskResult {
    action: String,
    description: String,
    rollback_commands: Vec<String>,
    error: Option<String>,
}

struct App {
    state: AppState,
    avc_manager: AVCManager,
    module_manager: ModuleManager,
    boolean_manager: BooleanManager,
    rollback_manager: RollbackManager,
    safe_config: SafeModeConfig,
    file_context_manager: FileContextManager,
    port_manager: PortManager,
    advisor: Advisor,

    last_update: Instant,
    update_interval: Duration,
    should_quit: bool,
    status_message: Option<(String, Color)>,
    simulation_mode: bool,
    ascii_mode: bool,

    // Асинхронность
    is_busy: bool,
    busy_message: String,
    spinner_idx: usize,
    task_rx: Option<Receiver<TaskResult>>,
    logfile_path: Option<PathBuf>,
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
            advisor: Advisor::new(),

            last_update: Instant::now(),
            update_interval: Duration::from_secs(update_interval_secs.max(1)),
            should_quit: false,
            status_message: None,
            simulation_mode: simulation,
            ascii_mode,

            is_busy: false,
            busy_message: String::new(),
            spinner_idx: 0,
            task_rx: None,
            logfile_path: None,
        };
        if debug {
            app.logfile_path = Some(PathBuf::from("selab_debug.log"));
        }
        app.refresh_data()?;
        Ok(app)
    }

    // --- АСИНХРОННЫЙ ЗАПУСК ---
    fn spawn_task<F>(&mut self, message: &str, task: F)
    where
    F: FnOnce() -> Result<(String, Vec<String>)> + Send + 'static,
    {
        if self.is_busy {
            return;
        }

        self.is_busy = true;
        self.busy_message = message.to_string();
        let (tx, rx) = mpsc::channel();
        self.task_rx = Some(rx);
        let action_name = message.to_string();

        thread::spawn(move || {
            let result = task();
            match result {
                Ok((desc, rollback)) => {
                    let _ = tx.send(TaskResult {
                        action: action_name,
                        description: desc,
                        rollback_commands: rollback,
                        error: None,
                    });
                }
                Err(e) => {
                    let _ = tx.send(TaskResult {
                        action: action_name,
                        description: "Operation failed".to_string(),
                                    rollback_commands: vec![],
                                    error: Some(e.to_string()),
                    });
                }
            }
        });
    }

    fn refresh_data(&mut self) -> Result<()> {
        if self.simulation_mode {
            self.load_simulation_data()?;
        } else {
            let _ = self.avc_manager.load_avc_logs();
            let _ = self.module_manager.load_modules();
            let _ = self.boolean_manager.load_booleans();
            let _ = self.file_context_manager.load_file_contexts();
            let _ = self.port_manager.load_ports();
        }
        Ok(())
    }

    fn load_simulation_data(&mut self) -> Result<()> {
        self.avc_manager.load_simulation_data();
        self.module_manager.load_simulation_data();
        self.boolean_manager.load_simulation_data();
        self.file_context_manager.contexts = vec![FileContext {
            path: "/var/www".into(),
            context: "httpd_sys_content_t".into(),
        }];
        self.port_manager.ports = vec![PortContext {
            port: "80".into(),
            protocol: "tcp".into(),
            context: "http_port_t".into(),
        }];
        Ok(())
    }

    fn set_status(&mut self, message: String, color: Color) {
        self.status_message = Some((message, color));
    }

    fn handle_key_event(&mut self, key: KeyCode) -> Result<()> {
        if self.is_busy {
            if let KeyCode::Char('q') = key {
                self.should_quit = true;
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
                        self.state.input_cursor_position =
                        self.state.input_cursor_position.saturating_sub(1);
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
                self.set_status("Data refreshed".into(), Color::Green);
            }
            KeyCode::Char(c) if c.is_digit(10) => {
                if let Some(digit) = c.to_digit(10) {
                    self.state.current_view = match digit {
                        1 => CurrentView::Dashboard,
                        2 => CurrentView::AVCAlerts,
                        3 => CurrentView::ModuleManager,
                        4 => CurrentView::BooleanManager,
                        5 => CurrentView::RollbackHistory,
                        6 => CurrentView::SafeSettings,
                        7 => CurrentView::FileContexts,
                        8 => CurrentView::Ports,
                        _ => CurrentView::Dashboard,
                    };
                    self.state.list_state.select(Some(0));
                }
            }
            _ => {}
        }
        Ok(())
    }

    // --- ВВОД ДАННЫХ (ADD) ---
    fn show_add_popup(&mut self) {
        match self.state.current_view {
            CurrentView::Ports => self.state.enter_input_mode(PopupType::AddPort),
            CurrentView::FileContexts => self.state.enter_input_mode(PopupType::AddFileContext),
            _ => self.set_status("Add option not available here".into(), Color::Yellow),
        }
    }

    fn submit_input(&mut self) -> Result<()> {
        let input = self.state.input_buffer.clone();
        let simulation = self.simulation_mode;

        match self.state.popup_type {
            PopupType::Search => {
                self.state.search_query = input;
                self.state.reset_mode();
            }
            PopupType::AddPort => {
                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                if parts.len() == 3 {
                    let mut mgr = self.port_manager.clone();
                    let (port, proto, ctx) = (parts[0].clone(), parts[1].clone(), parts[2].clone());
                    self.state.reset_mode();

                    self.spawn_task("Adding Port...", move || {
                        mgr.add_port(&port, &proto, &ctx, simulation)?;
                        let rb = vec![format!("semanage port -d -p {} {}", proto, port)];
                        Ok((format!("Added port {}/{}", port, proto), rb))
                    });
                } else {
                    self.set_status("Error: Use format 'PORT PROTO TYPE'".into(), Color::Red);
                }
            }
            PopupType::AddFileContext => {
                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                if parts.len() >= 2 {
                    let ctx = parts.last().unwrap().clone();
                    let path = parts[0..parts.len() - 1].join(" ");
                    let mut mgr = self.file_context_manager.clone();
                    self.state.reset_mode();

                    self.spawn_task("Adding File Context...", move || {
                        mgr.add_file_context(&path, &ctx, simulation)?;
                        let rb = vec![format!("semanage fcontext -d {}", path)];
                        Ok((format!("Added context for {}", path), rb))
                    });
                } else {
                    self.set_status("Error: Use format 'PATH TYPE'".into(), Color::Red);
                }
            }
            _ => self.state.reset_mode(),
        }
        Ok(())
    }

    // --- ВЫПОЛНЕНИЕ ДЕЙСТВИЙ ---
    fn execute_current_selection(&mut self) -> Result<()> {
        let selected = match self.state.selected_index {
            Some(i) => i,
            None => return Ok(()),
        };

        match self.state.current_view {
            CurrentView::Dashboard => match selected {
                0 => self.state.current_view = CurrentView::AVCAlerts,
                1 => self.state.current_view = CurrentView::ModuleManager,
                2 => self.state.current_view = CurrentView::BooleanManager,
                3 => self.state.current_view = CurrentView::SafeSettings,
                4 => self.state.current_view = CurrentView::RollbackHistory,
                5 => self.state.current_view = CurrentView::FileContexts,
                6 => self.state.current_view = CurrentView::Ports,
                _ => {}
            },
            CurrentView::ModuleManager => {
                if let Some(module) = self.module_manager.modules.get(selected).cloned() {
                    let mut mgr = self.module_manager.clone();
                    let sim = self.simulation_mode;
                    let action = if module.enabled { "Disabling" } else { "Enabling" };

                    self.spawn_task(&format!("{} module {}...", action, module.name), move || {
                        let rb_cmd = if module.enabled {
                            mgr.disable_module(&module.name, sim)?;
                            format!("semodule -e {}", module.name)
                        } else {
                            mgr.enable_module(&module.name, sim)?;
                            format!("semodule -d {}", module.name)
                        };
                        Ok((format!("Toggled module {}", module.name), vec![rb_cmd]))
                    });
                }
            }
            CurrentView::BooleanManager => {
                let bools = self.get_filtered_booleans();
                if let Some(b) = bools.get(selected).cloned() {
                    let mut mgr = self.boolean_manager.clone();
                    let sim = self.simulation_mode;
                    let new_val = !b.current_value;

                    self.spawn_task(&format!("Setting boolean {}...", b.name), move || {
                        mgr.set_boolean(&b.name, new_val, sim)?;
                        let rb = format!(
                            "setsebool -P {} {}",
                            b.name,
                            if !new_val { "on" } else { "off" }
                        );
                        Ok((format!("Set {} to {}", b.name, new_val), vec![rb]))
                    });
                }
            }
            CurrentView::Ports => {
                if let Some(p) = self.port_manager.ports.get(selected).cloned() {
                    let mut mgr = self.port_manager.clone();
                    let sim = self.simulation_mode;
                    self.spawn_task(&format!("Removing port {}...", p.port), move || {
                        mgr.remove_port(&p.port, &p.protocol, sim)?;
                        let rb = format!("semanage port -a -t {} -p {} {}", p.context, p.protocol, p.port);
                        Ok((format!("Removed port {}", p.port), vec![rb]))
                    });
                }
            }
            CurrentView::FileContexts => {
                if let Some(c) = self.file_context_manager.contexts.get(selected).cloned() {
                    let mut mgr = self.file_context_manager.clone();
                    let sim = self.simulation_mode;
                    self.spawn_task(&format!("Removing context {}...", c.path), move || {
                        mgr.remove_file_context(&c.path, sim)?;
                        let rb = format!("semanage fcontext -a -t {} {}", c.context, c.path);
                        Ok((format!("Removed context {}", c.path), vec![rb]))
                    });
                }
            }
            CurrentView::AVCAlerts => {
                if let Some(alert) = self.avc_manager.alerts.get(selected).cloned() {
                    if let Some(sol) = self.avc_manager.analyze_avc(&alert) {
                        let mgr = self.avc_manager.clone();
                        let sim = self.simulation_mode;
                        let sol_clone = sol.clone();

                        self.spawn_task("Applying AVC Fix...", move || {
                            mgr.apply_solution(&sol_clone, sim)?;
                            let rb = sol_clone
                            .commands
                            .iter()
                            .map(|c| format!("# undo: {}", c))
                            .collect();
                            Ok((format!("Applied: {}", sol_clone.description), rb))
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn get_filtered_booleans(&self) -> Vec<booleans::BooleanState> {
        if self.state.search_query.is_empty() {
            self.boolean_manager.booleans.clone()
        } else {
            self.boolean_manager
            .booleans
            .iter()
            .filter(|b| {
                b.name.contains(&self.state.search_query)
                || b.description.contains(&self.state.search_query)
            })
            .cloned()
            .collect()
        }
    }

    fn show_help_popup(&mut self) {
        let key = match self.state.current_view {
            CurrentView::BooleanManager => self
            .get_filtered_booleans()
            .get(self.state.selected_index.unwrap_or(0))
            .map(|b| b.name.clone()),
            CurrentView::AVCAlerts => Some("avc_general".to_string()),
            _ => None,
        };

        if let Some(k) = key {
            if let Some(advice) = self.advisor.get_advice(&k) {
                let text = format!(
                    "{}\n\nRisk: {}\nSuggestion: {}",
                    advice.description, advice.risk, advice.suggestion
                );
                self.state.popup_type = PopupType::Help(text);
                self.state.input_mode = InputMode::Editing;
            } else {
                self.set_status("No specific advice found".into(), Color::Yellow);
            }
        } else {
            let text = "Global Keys:\n?: Context Help\n/: Search\na: Add Item\nr: Undo Last\ns: Auto-Secure\nR: Refresh Data".to_string();
            self.state.popup_type = PopupType::Help(text);
            self.state.input_mode = InputMode::Editing;
        }
    }

    fn apply_safe_settings_async(&mut self) -> Result<()> {
        let safe = self.safe_config.clone();
        let mut mgr = self.boolean_manager.clone();
        let sim = self.simulation_mode;

        self.spawn_task("Applying Safe Defaults...", move || {
            let rb = safe.apply_safe_defaults(&mut mgr, sim)?;
            Ok(("Applied safe defaults".to_string(), rb))
        });
        Ok(())
    }

    fn rollback_last_change(&mut self) -> Result<()> {
        self.rollback_manager.rollback_last(self.simulation_mode)?;
        self.set_status("Rolled back last change".into(), Color::Yellow);
        Ok(())
    }

    fn get_current_system_state(&self) -> Result<SystemState> {
        let selinux_mode = if self.simulation_mode {
            "Enforcing".to_string()
        } else {
            "Enforcing".to_string()
        };
        Ok(SystemState {
            timestamp: Utc::now().to_rfc3339(),
           selinux_mode,
           booleans: self.boolean_manager.booleans.clone(),
           modules: self.module_manager.modules.clone(),
           file_contexts: self
           .file_context_manager
           .contexts
           .iter()
           .map(|c| format!("{}:{}", c.path, c.context))
           .collect(),
           ports: self
           .port_manager
           .ports
           .iter()
           .map(|p| format!("{}/{}:{}", p.port, p.protocol, p.context))
           .collect(),
        })
    }

    fn tick(&mut self) -> Result<()> {
        if self.is_busy {
            self.spinner_idx = (self.spinner_idx + 1) % 4;
            if let Some(rx) = &self.task_rx {
                if let Ok(res) = rx.try_recv() {
                    self.is_busy = false;
                    self.task_rx = None;

                    if let Some(err) = res.error {
                        self.set_status(format!("Error: {}", err), Color::Red);
                    } else {
                        self.set_status(format!("Success: {}", res.description), Color::Green);
                        self.refresh_data()?;
                        let state = self.get_current_system_state()?;
                        self.rollback_manager.record_change(
                            res.action,
                            res.description,
                            state.clone(),
                                                            state,
                                                            res.rollback_commands,
                        );
                    }
                }
            }
        } else if self.last_update.elapsed() > self.update_interval {
            self.refresh_data()?;
            self.last_update = Instant::now();
        }
        Ok(())
    }

    fn ui<B: Backend>(&mut self, f: &mut Frame<B>) {
        let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
                     Constraint::Min(0),
                     Constraint::Length(3),
        ])
        .split(f.size());

        let list_len = match self.state.current_view {
            CurrentView::BooleanManager => self.get_filtered_booleans().len(),
            CurrentView::Dashboard => 7,
            CurrentView::AVCAlerts => self.avc_manager.alerts.len(),
            CurrentView::ModuleManager => self.module_manager.modules.len(),
            CurrentView::RollbackHistory => self.rollback_manager.change_history.len(),
            CurrentView::SafeSettings => 2,
            CurrentView::FileContexts => self.file_context_manager.contexts.len(),
            CurrentView::Ports => self.port_manager.ports.len(),
        };
        self.state.set_current_len(list_len);

        let tabs = Tabs::new(vec![
            "1:Dash", "2:AVC", "3:Mod", "4:Bool", "5:Roll", "6:Safe", "7:File", "8:Port",
        ])
        .block(Block::default().borders(Borders::ALL).title("SELab"))
        .select(self.state.current_view as usize)
        .highlight_style(Style::default().fg(Color::Yellow));
        f.render_widget(tabs, chunks[0]);

        match self.state.current_view {
            CurrentView::Dashboard => self.render_dashboard(f, chunks[1]),
            CurrentView::BooleanManager => self.render_booleans(f, chunks[1]),
            CurrentView::ModuleManager => self.render_modules(f, chunks[1]),
            CurrentView::AVCAlerts => self.render_avc(f, chunks[1]),
            CurrentView::Ports => self.render_ports(f, chunks[1]),
            CurrentView::FileContexts => self.render_contexts(f, chunks[1]),
            CurrentView::RollbackHistory => self.render_rollback(f, chunks[1]),
            CurrentView::SafeSettings => self.render_safe(f, chunks[1]),
        }

        self.render_footer(f, chunks[2]);

        if self.is_busy {
            self.render_busy_popup(f);
        } else if self.state.popup_type != PopupType::None {
            self.render_popup(f);
        }
    }

    fn render_busy_popup<B: Backend>(&self, f: &mut Frame<B>) {
        let area = self.centered_rect(40, 20, f.size());
        f.render_widget(Clear, area);

        let spinner_chars = ["|", "/", "-", "\\"];
        let spin = spinner_chars[self.spinner_idx % spinner_chars.len()];

        let block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
        let text = vec![
            Line::from("Processing Operation..."),
            Line::from(""),
            Line::from(format!("{} {}", spin, self.busy_message)),
            Line::from(""),
            Line::from(Span::styled(
                "Please wait...",
                Style::default().fg(Color::Yellow),
            )),
        ];

        let p = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
        f.render_widget(p, area);
    }

    fn render_popup<B: Backend>(&mut self, f: &mut Frame<B>) {
        let area = self.centered_rect(60, 50, f.size());
        f.render_widget(Clear, area);
        let block = Block::default()
        .borders(Borders::ALL)
        .title("Action")
        .style(Style::default().bg(Color::Blue));

        match &self.state.popup_type {
            PopupType::AddPort => {
                let txt = format!(
                    "Add Port Rule\n\nFormat: PORT PROTO TYPE\nExample: 8080 tcp http_port_t\n\n> {}",
                    self.state.input_buffer
                );
                f.render_widget(Paragraph::new(txt).block(block.title("Add Port")), area);
            }
            PopupType::AddFileContext => {
                let txt = format!(
                    "Add Context Rule\n\nFormat: PATH TYPE\nExample: /var/www/app httpd_sys_content_t\n\n> {}",
                    self.state.input_buffer
                );
                f.render_widget(Paragraph::new(txt).block(block.title("Add Context")), area);
            }
            PopupType::Help(msg) => {
                f.render_widget(
                    Paragraph::new(msg.as_str())
                    .block(block.title("Help / Advisor"))
                    .wrap(Wrap { trim: true }),
                                area,
                );
            }
            PopupType::Search => {
                f.render_widget(
                    Paragraph::new(format!("Search Query:\n> {}", self.state.input_buffer))
                    .block(block.title("Search")),
                                area,
                );
            }
            _ => {}
        }
    }

    fn render_booleans<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let bools = self.get_filtered_booleans();
        let items: Vec<ListItem> = bools
        .iter()
        .map(|b| {
            let state = if b.current_value { "ON" } else { "OFF" };
            let color = if b.current_value {
                Color::Green
            } else {
                Color::Red
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{}] ", state), Style::default().fg(color)),
                                     Span::raw(format!("{: <30}", b.name)),
                                     Span::styled(
                                         format!("({})", b.description),
                                             Style::default().fg(Color::DarkGray),
                                     ),
            ]))
        })
        .collect();

        let title = if self.state.search_query.is_empty() {
            "Booleans".to_string()
        } else {
            format!("Booleans (Filter: {})", self.state.search_query)
        };
        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().bg(Color::DarkGray));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }

    fn render_dashboard<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let list = List::new(vec![
            ListItem::new("1. AVC Alerts"),
                             ListItem::new("2. Modules"),
                             ListItem::new("3. Booleans"),
                             ListItem::new("4. Safe Settings"),
                             ListItem::new("5. History"),
                             ListItem::new("6. File Contexts"),
                             ListItem::new("7. Ports"),
        ])
        .block(Block::default().borders(Borders::ALL).title("Dashboard"))
        .highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }
    fn render_modules<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self
        .module_manager
        .modules
        .iter()
        .map(|m| {
            ListItem::new(format!(
                "{} {}",
                if m.enabled { "[+]" } else { "[-]" },
                    m.name
            ))
        })
        .collect();
        f.render_stateful_widget(
            List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Modules"))
            .highlight_style(Style::default().fg(Color::Yellow)),
                                 area,
                                 &mut self.state.list_state,
        );
    }
    fn render_avc<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self
        .avc_manager
        .alerts
        .iter()
        .map(|a| ListItem::new(format!("{} {}", a.comm, a.permission)))
        .collect();
        f.render_stateful_widget(
            List::new(items)
            .block(Block::default().borders(Borders::ALL).title("AVC"))
            .highlight_style(Style::default().fg(Color::Yellow)),
                                 area,
                                 &mut self.state.list_state,
        );
    }
    fn render_ports<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self
        .port_manager
        .ports
        .iter()
        .map(|p| ListItem::new(format!("{}/{} -> {}", p.port, p.protocol, p.context)))
        .collect();
        f.render_stateful_widget(
            List::new(items)
            .block(
                Block::default()
                .borders(Borders::ALL)
                .title("Ports (Press 'a' to add)"),
            )
            .highlight_style(Style::default().fg(Color::Yellow)),
                                 area,
                                 &mut self.state.list_state,
        );
    }
    fn render_contexts<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self
        .file_context_manager
        .contexts
        .iter()
        .map(|c| ListItem::new(format!("{} -> {}", c.path, c.context)))
        .collect();
        f.render_stateful_widget(
            List::new(items)
            .block(
                Block::default()
                .borders(Borders::ALL)
                .title("File Contexts (Press 'a' to add)"),
            )
            .highlight_style(Style::default().fg(Color::Yellow)),
                                 area,
                                 &mut self.state.list_state,
        );
    }
    fn render_rollback<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self
        .rollback_manager
        .change_history
        .iter()
        .map(|c| ListItem::new(format!("{} - {}", c.timestamp, c.description)))
        .collect();
        f.render_stateful_widget(
            List::new(items)
            .block(Block::default().borders(Borders::ALL).title("History"))
            .highlight_style(Style::default().fg(Color::Yellow)),
                                 area,
                                 &mut self.state.list_state,
        );
    }
    fn render_safe<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let items = vec![
            ListItem::new("Apply Safe Defaults"),
            ListItem::new("Apply Restrictive Policy"),
        ];
        f.render_stateful_widget(
            List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Safe Config"))
            .highlight_style(Style::default().fg(Color::Yellow)),
                                 area,
                                 &mut self.state.list_state,
        );
    }

    fn render_footer<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let msg = if self.is_busy {
            "Working..."
        } else {
            "?:Help /:Search a:Add q:Quit"
        };
        let color = if self
        .status_message
        .as_ref()
        .map(|(_, c)| *c == Color::Red)
        .unwrap_or(false)
        {
            Color::Red
        } else {
            Color::Gray
        };
        let status = self
        .status_message
        .as_ref()
        .map(|(s, _)| s.clone())
        .unwrap_or_default();
        f.render_widget(
            Paragraph::new(format!("{} | {}", msg, status))
            .style(Style::default().fg(color))
            .block(Block::default().borders(Borders::ALL)),
                        area,
        );
    }

    fn centered_rect(&self, percent_x: u16, percent_y: u16, r: Rect) -> Rect {
        let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
                     Constraint::Percentage(percent_y),
                     Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
        Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
                     Constraint::Percentage(percent_x),
                     Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
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
        eprintln!("Error: {}", err);
    }
    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| app.ui(f))?;
        if event::poll(Duration::from_millis(100))? {
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
