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
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Tabs,
    },
    Frame, Terminal,
};
use std::{
    io,
    time::{Duration, Instant},
};

mod avc;
mod booleans;
mod modules;
mod rollback;
mod safe_config;
mod state;
mod file_contexts;
mod ports;

use avc::{AVCManager, AVCSeverity, AVCSolution};
use booleans::BooleanManager;
use modules::ModuleManager;
use rollback::{RollbackManager, SystemState};
use safe_config::SafeModeConfig;
use state::{AppState, CurrentView};
use file_contexts::{FileContext, FileContextManager}; // Added FileContextManager
use ports::{PortContext, PortManager}; // Added PortManager

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    simulate: bool,

    #[arg(short, long)]
    logfile: Option<String>,

    #[arg(short, long)]
    debug: bool,
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
    last_update: Instant,
    update_interval: Duration,
    should_quit: bool,
    status_message: Option<(String, Color)>,
    debug_mode: bool,
    simulation_mode: bool,
}

impl App {
    fn new(simulation: bool, debug: bool) -> Result<Self> {
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
            update_interval: Duration::from_secs(5),
            should_quit: false,
            status_message: None,
            debug_mode: debug,
            simulation_mode: simulation,
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
        if let Err(e) = self.avc_manager.load_avc_logs() {
            self.set_status(format!("Failed to load AVC logs: {}", e), Color::Red);
        }

        if let Err(e) = self.module_manager.load_modules() {
            self.set_status(format!("Failed to load modules: {}", e), Color::Red);
        }

        if let Err(e) = self.boolean_manager.load_booleans() {
            self.set_status(format!("Failed to load booleans: {}", e), Color::Red);
        }

        if let Err(e) = self.file_context_manager.load_file_contexts() {
            self.set_status(format!("Failed to load file contexts: {}", e), Color::Red);
        }

        if let Err(e) = self.port_manager.load_ports() {
            self.set_status(format!("Failed to load ports: {}", e), Color::Red);
        }

        Ok(())
    }

    fn load_simulation_data(&mut self) -> Result<()> {
        self.avc_manager.load_simulation_data();
        self.module_manager.load_simulation_data();
        self.boolean_manager.load_simulation_data();
        self.file_context_manager.contexts = vec![
            FileContext {
                path: "/var/www/html".to_string(),
                context: "httpd_sys_content_t".to_string(),
            },
        ];
        self.port_manager.ports = vec![
            PortContext {
                port: "80".to_string(),
                protocol: "tcp".to_string(),
                context: "http_port_t".to_string(),
            },
        ];
        Ok(())
    }

    fn set_status(&mut self, message: String, color: Color) {
        self.status_message = Some((message, color));
    }

    fn handle_key_event(&mut self, key: KeyCode) -> Result<()> {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Char('h') | KeyCode::Left => {
                self.state.previous_view();
            }
            KeyCode::Char('l') | KeyCode::Right => {
                self.state.next_view();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.state.previous_item();
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.state.next_item();
            }
            KeyCode::Char('r') => {
                self.rollback_last_change()?;
            }
            KeyCode::Char('s') => {
                self.apply_safe_settings()?;
            }
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
                self.rollback_manager.record_change(
                    "AVC Solution".to_string(),
                                                    sol.description.clone(),
                                                    previous_state,
                                                    new_state,
                                                    rollback_commands,
                );

                self.set_status(format!("Applied solution: {}", sol.description), Color::Green);
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
            if module.enabled {
                self.module_manager.disable_module(&module.name, self.simulation_mode)?;
            } else {
                self.module_manager.enable_module(&module.name, self.simulation_mode)?;
            }
            let new_state = self.get_current_system_state()?;
            let rollback_commands = vec![rollback_command];
            self.rollback_manager.record_change(
                "Module Toggle".to_string(),
                                                format!("Toggled module {}", module.name),
                                                    previous_state,
                                                new_state,
                                                rollback_commands,
            );
        }
        Ok(())
    }

    fn handle_boolean_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(boolean) = self.boolean_manager.booleans.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("setsebool -P {} {}", boolean.name, if boolean.current_value { "off" } else { "on" });
            self.boolean_manager.set_boolean(&boolean.name, !boolean.current_value, self.simulation_mode)?;
            let new_state = self.get_current_system_state()?;
            let rollback_commands = vec![rollback_command];
            self.rollback_manager.record_change(
                "Boolean Toggle".to_string(),
                                                format!("Toggled boolean {}", boolean.name),
                                                    previous_state,
                                                new_state,
                                                rollback_commands,
            );
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
        let previous_state = self.get_current_system_state()?;
        let rollback_commands = match selected {
            0 => self.safe_config.apply_safe_defaults(&mut self.boolean_manager, self.simulation_mode)?,
            1 => self.safe_config.apply_restrictive_policy(&mut self.boolean_manager, self.simulation_mode)?,
            _ => vec![],
        };
        let new_state = self.get_current_system_state()?;
        self.rollback_manager.record_change(
            "Safe Settings".to_string(),
                                            format!("Applied safe profile {}", selected),
                                                previous_state,
                                            new_state,
                                            rollback_commands,
        );
        self.set_status("Applied safe settings".to_string(), Color::Green);
        Ok(())
    }

    fn handle_file_context_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(context) = self.file_context_manager.contexts.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("semanage fcontext -a -t {} {}", context.context, context.path);
            self.file_context_manager.remove_file_context(&context.path, self.simulation_mode)?;
            let new_state = self.get_current_system_state()?;
            let rollback_commands = vec![rollback_command];
            self.rollback_manager.record_change(
                "File Context Remove".to_string(),
                                                format!("Removed context for {}", context.path),
                                                    previous_state,
                                                new_state,
                                                rollback_commands,
            );
        }
        Ok(())
    }

    fn handle_port_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(port) = self.port_manager.ports.get(selected).cloned() {
            let previous_state = self.get_current_system_state()?;
            let rollback_command = format!("semanage port -a -t {} -p {} {}", port.context, port.protocol, port.port);
            self.port_manager.remove_port(&port.port, &port.protocol, self.simulation_mode)?;
            let new_state = self.get_current_system_state()?;
            let rollback_commands = vec![rollback_command];
            self.rollback_manager.record_change(
                "Port Remove".to_string(),
                                                format!("Removed port {}", port.port),
                                                    previous_state,
                                                new_state,
                                                rollback_commands,
            );
        }
        Ok(())
    }

    fn rollback_last_change(&mut self) -> Result<()> {
        self.rollback_manager.rollback_last(self.simulation_mode)?;
        self.set_status("Rolled back last change".to_string(), Color::Yellow);
        Ok(())
    }

    fn apply_safe_settings(&mut self) -> Result<()> {
        let previous_state = self.get_current_system_state()?;
        let rollback_commands = self.safe_config.apply_safe_defaults(&mut self.boolean_manager, self.simulation_mode)?;
        let new_state = self.get_current_system_state()?;
        self.rollback_manager.record_change(
            "Safe Defaults".to_string(),
                                            "Applied safe defaults".to_string(),
                                            previous_state,
                                            new_state,
                                            rollback_commands,
        );
        self.set_status("Applied safe settings".to_string(), Color::Green);
        Ok(())
    }

    fn get_current_system_state(&self) -> Result<SystemState> {
        let selinux_mode = String::from_utf8_lossy(&std::process::Command::new("getenforce").output()?.stdout).trim().to_string();
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

        let tabs = Tabs::new(vec![
            "1: Dashboard",
            "2: AVC",
            "3: Modules",
            "4: Booleans",
            "5: Rollback",
            "6: Safe",
            "7: Files",
            "8: Ports",
        ])
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
    }

    fn render_dashboard<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items = vec![
            ListItem::new("AVC Alerts"),
            ListItem::new("Module Manager"),
            ListItem::new("Boolean Manager"),
            ListItem::new("Safe Settings"),
            ListItem::new("Rollback History"),
            ListItem::new("File Contexts"),
            ListItem::new("Ports"),
        ];

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Dashboard - Select Section"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_avc_alerts<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.avc_manager.alerts.iter().map(|alert| {
            let severity_icon = match alert.severity {
                AVCSeverity::High => "🔴",
                AVCSeverity::Medium => "🟡",
                AVCSeverity::Low => "🟢",
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} {} ", severity_icon, alert.comm)),
                                     Span::styled(
                                         format!("[{}:{}]", alert.target_class, alert.permission),
                                             Style::default().fg(Color::Gray),
                                     ),
            ]))
        }).collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!("AVC Alerts ({})", self.avc_manager.alerts.len())))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_modules<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.module_manager.modules.iter().map(|module| {
            let status = if module.enabled { "✅" } else { "❌" };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} {} ", status, module.name)),
                                     Span::styled(
                                         if module.enabled { "[ENABLED]" } else { "[DISABLED]" },
                                             Style::default().fg(if module.enabled { Color::Green } else { Color::Red }),
                                     ),
            ]))
        }).collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELinux Modules (Enter to toggle)"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_booleans<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.boolean_manager.booleans.iter().map(|boolean| {
            let status = if boolean.current_value { "✅" } else { "❌" };
            let persistent = if boolean.persistent { "💾" } else { " " };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} {} {} ", status, persistent, boolean.name)),
                                     Span::styled(
                                         format!("({})", boolean.description),
                                             Style::default().fg(Color::Gray),
                                     ),
            ]))
        }).collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELinux Booleans (Enter to toggle)"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_rollback_history<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.rollback_manager.change_history.iter().map(|change| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    &change.timestamp[11..19],
                    Style::default().fg(Color::Blue),
                ),
                Span::raw(" "),
                                     Span::styled(&change.action, Style::default().fg(Color::Cyan)),
                                     Span::raw(" - "),
                                     Span::raw(&change.description),
            ]))
        }).collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Change History (Enter to rollback to this point)"))
        .highlight_style(Style::default().fg(Color::Red))
        .highlight_symbol("⤴️ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_safe_settings<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items = vec![
            ListItem::new("✅ Apply Safe Defaults (Recommended)"),
            ListItem::new("🔒 Apply Restrictive Policy (Paranoid)"),
            ListItem::new("🌐 Web Server Hardening"),
            ListItem::new("🗄️  Database Security"),
            ListItem::new("👤 User Restrictions"),
            ListItem::new("📝 Custom Safe Profile"),
        ];

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Safe Security Profiles (Enter to apply)"))
        .highlight_style(Style::default().fg(Color::Green))
        .highlight_symbol("🛡️ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_file_contexts<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.file_context_manager.contexts.iter().map(|context| {
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} ", context.path)),
                                     Span::styled(
                                         format!("[{}]", context.context),
                                             Style::default().fg(Color::Cyan),
                                     ),
            ]))
        }).collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("File Contexts (Enter to remove)"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_ports<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.port_manager.ports.iter().map(|port| {
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} / {} ", port.port, port.protocol)),
                                     Span::styled(
                                         format!("[{}]", port.context),
                                             Style::default().fg(Color::Cyan),
                                     ),
            ]))
        }).collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Ports (Enter to remove)"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_footer<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let mode_indicator = if self.simulation_mode {
            "[SIMULATION MODE] "
        } else {
            ""
        };

        let help_text = match self.state.current_view {
            CurrentView::Dashboard => "↑↓: Navigate • Enter: Select • 1-8: Switch tabs • Q: Quit",
            CurrentView::AVCAlerts => "↑↓: Navigate • Enter: Analyze & Apply • R: Refresh • S: Safe settings",
            CurrentView::ModuleManager => "↑↓: Navigate • Enter: Toggle • r: Rollback last",
            CurrentView::BooleanManager => "↑↓: Navigate • Enter: Toggle • R: Refreshsending",
            CurrentView::RollbackHistory => "↑↓: Navigate • Enter: Rollback to point • r: Rollback last",
            CurrentView::SafeSettings => "↑↓: Navigate • Enter: Apply • R: Refresh",
            CurrentView::FileContexts => "↑↓: Navigate • Enter: Remove • R: Refresh",
            CurrentView::Ports => "↑↓: Navigate • Enter: Remove • R: Refresh",
        };

        let footer_text = format!("{}{}", mode_indicator, help_text);

        let paragraph = if let Some((message, color)) = &self.status_message {
            Paragraph::new(format!("{} | Status: {}", footer_text, message))
            .style(Style::default().fg(*color))
            .block(Block::default().borders(Borders::ALL))
        } else {
            Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL))
        };

        f.render_widget(paragraph, area);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.simulate, cli.debug)?;
    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
             LeaveAlternateScreen,
             DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        eprintln!("Error: {}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
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
