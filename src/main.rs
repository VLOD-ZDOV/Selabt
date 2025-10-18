use anyhow::Result;  // Убрали Context
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
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Tabs,
    },
    Frame, Terminal,
};
use std::{
    io,
    process::{Command, Output},
    time::{Duration, Instant},
};

// Модули приложения
mod avc;
mod booleans;
mod modules;
mod rollback;
mod safe_config;
mod state;

// Убрали неиспользуемые импорты
use avc::{AVCManager, AVCSeverity};
use booleans::BooleanManager;
use modules::ModuleManager;
use rollback::{RollbackManager, SystemState};
use safe_config::SafeModeConfig;
use state::{AppState, CurrentView};

/// SELinux Assistant - Interactive TUI management tool
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Start in simulation mode (no real changes)
    #[arg(short, long)]
    simulate: bool,

    /// Log file to analyze
    #[arg(short, long)]
    logfile: Option<String>,

    /// Enable debug output
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
            last_update: Instant::now(),
            update_interval: Duration::from_secs(5),
            should_quit: false,
            status_message: None,
            debug_mode: debug,
            simulation_mode: simulation,
        };

        // Загружаем начальное состояние
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
        // Загружаем AVC логи
        if let Err(e) = self.avc_manager.load_avc_logs() {
            self.set_status(format!("Failed to load AVC logs: {}", e), Color::Red);
        }

        // Загружаем модули
        if let Err(e) = self.module_manager.load_modules() {
            self.set_status(format!("Failed to load modules: {}", e), Color::Red);
        }

        // Загружаем boolean'ы
        if let Err(e) = self.boolean_manager.load_booleans() {
            self.set_status(format!("Failed to load booleans: {}", e), Color::Red);
        }

        Ok(())
    }

    fn load_simulation_data(&mut self) -> Result<()> {
        // Симуляционные данные для тестирования
        self.avc_manager.load_simulation_data();
        self.module_manager.load_simulation_data();
        self.boolean_manager.load_simulation_data();
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
            KeyCode::Enter => {
                self.execute_current_selection()?;
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
            _ => {}
        }
        Ok(())
    }

    fn handle_avc_selection(&mut self, selected: usize) -> Result<()> {
        if let Some(alert) = self.avc_manager.alerts.get(selected) {
            let solution = self.avc_manager.analyze_avc(alert);
            if let Some(sol) = solution {
                if self.simulation_mode {
                    self.set_status(format!("[SIM] Would apply solution: {}", sol.description), Color::Yellow);
                } else {
                    // Реализовать применение решения
                    self.set_status(format!("Applied solution: {}", sol.description), Color::Green);
                }
            }
        }
        Ok(())
    }

    fn handle_module_selection(&mut self, selected: usize) -> Result<()> {
        // Копируем нужные данные до начала изменений
        let module_info = if let Some(module) = self.module_manager.modules.get(selected) {
            Some((module.name.clone(), module.enabled))
        } else {
            None
        };

        if let Some((module_name, was_enabled)) = module_info {
            let previous_state = self.capture_system_state();

            if was_enabled {
                if self.simulation_mode {
                    self.set_status(format!("[SIM] Would disable module: {}", module_name), Color::Yellow);
                } else {
                    self.module_manager.disable_module(&module_name)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                    let new_state = self.capture_system_state();
                    self.rollback_manager.record_change(
                        "module_disable".to_string(),
                                                        format!("Disabled module: {}", module_name),
                                                            previous_state,
                                                        new_state,
                                                        vec![format!("semodule -e {}", module_name)],
                    );
                    self.set_status(format!("Disabled module: {}", module_name), Color::Green);
                }
            } else {
                if self.simulation_mode {
                    self.set_status(format!("[SIM] Would enable module: {}", module_name), Color::Yellow);
                } else {
                    self.module_manager.enable_module(&module_name)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                    let new_state = self.capture_system_state();
                    self.rollback_manager.record_change(
                        "module_enable".to_string(),
                                                        format!("Enabled module: {}", module_name),
                                                            previous_state,
                                                        new_state,
                                                        vec![format!("semodule -d {}", module_name)],
                    );
                    self.set_status(format!("Enabled module: {}", module_name), Color::Green);
                }
            }
            self.refresh_data()?;
        }
        Ok(())
    }

    fn handle_boolean_selection(&mut self, selected: usize) -> Result<()> {
        // Копируем нужные данные до начала изменений
        let boolean_info = if let Some(boolean) = self.boolean_manager.booleans.get(selected) {
            Some((boolean.name.clone(), boolean.current_value))
        } else {
            None
        };

        if let Some((boolean_name, current_value)) = boolean_info {
            let previous_state = self.capture_system_state();
            let new_value = !current_value;

            if self.simulation_mode {
                self.set_status(
                    format!("[SIM] Would set boolean {} to {}", boolean_name, new_value),
                        Color::Yellow,
                );
            } else {
                self.boolean_manager.set_boolean(&boolean_name, new_value)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
                let new_state = self.capture_system_state();
                self.rollback_manager.record_change(
                    "boolean_change".to_string(),
                                                    format!("Set boolean {} to {}", boolean_name, new_value),
                                                        previous_state,
                                                    new_state,
                                                    vec![format!("setsebool {} {}", boolean_name, current_value)],
                );
                self.set_status(
                    format!("Set boolean {} to {}", boolean_name, new_value),
                        Color::Green,
                );
            }
            self.refresh_data()?;
        }
        Ok(())
    }

    fn handle_rollback_selection(&mut self, selected: usize) -> Result<()> {
        // Исправляем проблему заимствования: копируем ID до mutable borrow
        let change_id = if let Some(change) = self.rollback_manager.change_history.get(selected) {
            change.id.clone()
        } else {
            return Ok(());
        };

        if self.simulation_mode {
            self.set_status(
                format!("[SIM] Would rollback change: {}", change_id),
                    Color::Yellow,
            );
        } else {
            let previous_state = self.capture_system_state();
            match self.rollback_manager.rollback_to_id(&change_id) {
                Ok(()) => {
                    let new_state = self.capture_system_state();
                    self.rollback_manager.record_change(
                        "rollback".to_string(),
                                                        format!("Rolled back change: {}", change_id),
                                                            previous_state,
                                                        new_state,
                                                        vec!["# Manual intervention may be required".to_string()],
                    );
                    self.set_status("Successfully rolled back change".to_string(), Color::Green);
                    self.refresh_data()?;
                }
                Err(e) => {
                    self.set_status(format!("Rollback failed: {}", e), Color::Red);
                }
            }
        }
        Ok(())
    }

    fn handle_safe_settings_selection(&mut self, selected: usize) -> Result<()> {
        match selected {
            0 => self.apply_safe_settings()?,
            1 => self.apply_restrictive_policy()?,
            2 => self.apply_web_hardening()?,
            3 => self.apply_database_hardening()?,
            4 => self.apply_user_restrictions()?,
            _ => {}
        }
        Ok(())
    }

    fn rollback_last_change(&mut self) -> Result<()> {
        let previous_state = self.capture_system_state();
        if self.simulation_mode {
            self.set_status("[SIM] Would rollback last change".to_string(), Color::Yellow);
        } else {
            match self.rollback_manager.rollback_last() {
                Ok(()) => {
                    let new_state = self.capture_system_state();
                    self.rollback_manager.record_change(
                        "rollback".to_string(),
                                                        "Rolled back last change".to_string(),
                                                        previous_state,
                                                        new_state,
                                                        vec!["# Rollback of rollback - manual intervention required".to_string()],
                    );
                    self.set_status("Successfully rolled back last change".to_string(), Color::Green);
                    self.refresh_data()?;
                }
                Err(e) => {
                    self.set_status(format!("Rollback failed: {}", e), Color::Red);
                }
            }
        }
        Ok(())
    }

    fn apply_safe_settings(&mut self) -> Result<()> {
        let previous_state = self.capture_system_state();

        if self.simulation_mode {
            self.set_status("[SIM] Would apply safe settings".to_string(), Color::Yellow);
        } else {
            self.safe_config.apply_safe_defaults(&mut self.boolean_manager)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
            let new_state = self.capture_system_state();

            let rollback_cmds = self.safe_config.generate_rollback_commands(&previous_state.booleans);
            self.rollback_manager.record_change(
                "safe_settings".to_string(),
                                                "Applied safe security settings".to_string(),
                                                previous_state,
                                                new_state,
                                                rollback_cmds,
            );
            self.set_status("Safe settings applied successfully".to_string(), Color::Green);
            self.refresh_data()?;
        }
        Ok(())
    }

    fn apply_restrictive_policy(&mut self) -> Result<()> {
        let previous_state = self.capture_system_state();

        if self.simulation_mode {
            self.set_status("[SIM] Would apply restrictive policy".to_string(), Color::Yellow);
        } else {
            self.safe_config.apply_restrictive_policy(&mut self.boolean_manager)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
            let new_state = self.capture_system_state();

            let rollback_cmds = self.safe_config.generate_rollback_commands(&previous_state.booleans);
            self.rollback_manager.record_change(
                "restrictive_policy".to_string(),
                                                "Applied restrictive policy settings".to_string(),
                                                previous_state,
                                                new_state,
                                                rollback_cmds,
            );
            self.set_status("Restrictive policy applied (some functionality may be limited)".to_string(), Color::Green);
            self.refresh_data()?;
        }
        Ok(())
    }

    fn apply_web_hardening(&mut self) -> Result<()> {
        self.set_status("Web hardening feature not yet implemented".to_string(), Color::Yellow);
        Ok(())
    }

    fn apply_database_hardening(&mut self) -> Result<()> {
        self.set_status("Database hardening feature not yet implemented".to_string(), Color::Yellow);
        Ok(())
    }

    fn apply_user_restrictions(&mut self) -> Result<()> {
        self.set_status("User restrictions feature not yet implemented".to_string(), Color::Yellow);
        Ok(())
    }

    fn capture_system_state(&self) -> SystemState {
        SystemState {
            timestamp: Utc::now().to_rfc3339(),
            selinux_mode: self.get_selinux_mode(),
            booleans: self.boolean_manager.booleans.clone(),
            modules: self.module_manager.modules.clone(),
            file_contexts: vec![],
            ports: vec![],
        }
    }

    fn get_selinux_mode(&self) -> String {
        if self.simulation_mode {
            "Enforcing".to_string()
        } else {
            String::from_utf8_lossy(
                &Command::new("getenforce")
                .output()
                .unwrap_or_else(|_| Output {
                    status: std::process::ExitStatus::default(),
                                stdout: Vec::new(),
                                stderr: Vec::new(),
                })
                .stdout
            ).trim().to_string()
        }
    }

    fn tick(&mut self) -> Result<()> {
        if self.last_update.elapsed() > self.update_interval {
            self.refresh_data()?;
            self.last_update = Instant::now();
        }
        Ok(())
    }
}

// Реализация рендеринга UI
impl App {
    fn ui<B: Backend>(&self, f: &mut Frame<B>) {
        let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
                     Constraint::Min(0),    // Main content
                     Constraint::Length(3), // Footer
        ])
        .split(f.size());

        self.render_header(f, chunks[0]);
        self.render_main_content(f, chunks[1]);
        self.render_footer(f, chunks[2]);
    }

    fn render_header<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let titles = vec![
            " Dashboard ",
            " AVC Alerts ",
            " Modules ",
            " Booleans ",
            " Rollback ",
            " Safe Settings ",
        ];

        let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("SELinux Assistant"))
        .select(self.state.current_view as usize)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(
            Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        );

        f.render_widget(tabs, area);
    }

    fn render_main_content<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        match self.state.current_view {
            CurrentView::Dashboard => self.render_dashboard(f, area),
            CurrentView::AVCAlerts => self.render_avc_alerts(f, area),
            CurrentView::ModuleManager => self.render_modules(f, area),
            CurrentView::BooleanManager => self.render_booleans(f, area),
            CurrentView::RollbackHistory => self.render_rollback_history(f, area),
            CurrentView::SafeSettings => self.render_safe_settings(f, area),
        }
    }

    fn render_dashboard<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items = vec![
            ListItem::new("📊 AVC Alerts & Denials"),
            ListItem::new("⚙️  Module Management"),
            ListItem::new("🔧 Boolean Management"),
            ListItem::new("🛡️  Safe Security Settings"),
            ListItem::new("📜 Rollback History"),
        ];

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Quick Access"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_avc_alerts<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.avc_manager.alerts
        .iter()
        .enumerate()
        .map(|(_i, alert)| {  // Убрали неиспользуемую переменную i
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
        })
        .collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!("AVC Alerts ({})", self.avc_manager.alerts.len())))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_modules<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.module_manager.modules
        .iter()
        .map(|module| {
            let status = if module.enabled { "✅" } else { "❌" };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} {} ", status, module.name)),
                                     Span::styled(
                                         if module.enabled { "[ENABLED]" } else { "[DISABLED]" },
                                             Style::default().fg(if module.enabled { Color::Green } else { Color::Red }),
                                     ),
            ]))
        })
        .collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELinux Modules (Enter to toggle)"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_booleans<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.boolean_manager.booleans
        .iter()
        .map(|boolean| {
            let status = if boolean.current_value { "✅" } else { "❌" };
            let persistent = if boolean.persistent { "💾" } else { " " };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} {} {} ", status, persistent, boolean.name)),
                                     Span::styled(
                                         format!("({})", boolean.description),
                                             Style::default().fg(Color::Gray),
                                     ),
            ]))
        })
        .collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELinux Booleans (Enter to toggle)"))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("➤ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_rollback_history<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let items: Vec<ListItem> = self.rollback_manager.change_history
        .iter()
        .map(|change| {
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
        })
        .collect();

        let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Change History (Enter to rollback, R for last)"))
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
        .block(Block::default().borders(Borders::ALL).title("Safe Security Profiles"))
        .highlight_style(Style::default().fg(Color::Green))
        .highlight_symbol("🛡️ ");

        f.render_stateful_widget(list, area, &mut self.state.list_state.clone());
    }

    fn render_footer<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let mode_indicator = if self.simulation_mode {
            "[SIMULATION MODE] "
        } else {
            ""
        };

        let help_text = match self.state.current_view {
            CurrentView::Dashboard => "↑↓: Navigate • Enter: Select • 1-6: Switch tabs • Q: Quit",
            CurrentView::AVCAlerts => "↑↓: Navigate • Enter: Analyze • R: Refresh • S: Safe settings",
            CurrentView::ModuleManager => "↑↓: Navigate • Enter: Toggle • R: Rollback last",
            CurrentView::BooleanManager => "↑↓: Navigate • Enter: Toggle • R: Refresh",
            CurrentView::RollbackHistory => "↑↓: Navigate • Enter: Rollback • R: Rollback last",
            CurrentView::SafeSettings => "↑↓: Navigate • Enter: Apply • R: Refresh",
        };

        let mut footer_text = format!("{}{}", mode_indicator, help_text);

        if let Some((message, color)) = &self.status_message {
            footer_text = format!("{} | Status: {}", footer_text, message);
            let paragraph = Paragraph::new(footer_text)
            .style(Style::default().fg(*color))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(paragraph, area);
        } else {
            let paragraph = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(paragraph, area);
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Настройка терминала
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Создание приложения
    let mut app = App::new(cli.simulate, cli.debug)?;
    let result = run_app(&mut terminal, &mut app);

    // Восстановление терминала
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
