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
    io,
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

// --- МОДУЛИ ---
mod advisor;
mod avc;
mod booleans;
mod file_contexts;
mod modules;
mod ports;
mod rollback;
mod safe_config;
mod state;
mod stats;
mod config_export;
mod logging;
mod selinux_mode;

use advisor::{Advisor, AutoRecommendation};
use avc::AVCManager;
use booleans::BooleanManager;
use file_contexts::{FileContext, FileContextManager};
use modules::ModuleManager;
use ports::{PortContext, PortManager};
use rollback::{RollbackManager, SystemState};
use safe_config::SafeModeConfig;
use state::{AppState, CurrentView, InputMode, PopupType};
use stats::{StatsManager, SystemStats};
use config_export::ConfigExporter;
use logging::Logger;
use selinux_mode::{SELinuxMode, SELinuxModeManager};

// --- CLI ARGUMENTS ---
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

// --- СТРУКТУРЫ ---

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
    logger: Logger,
    selinux_mode_manager: SELinuxModeManager,
    
    // Новые поля
    system_stats: SystemStats,
    avc_recommendations: Vec<AutoRecommendation>,
    avc_severity_filter: Option<avc::AVCSeverity>,

    last_update: Instant,
    update_interval: Duration,
    should_quit: bool,
    status_message: Option<(String, Color)>,
    simulation_mode: bool,
    ascii_mode: bool,

    // Поля для асинхронности
    is_busy: bool,
    busy_message: String,
    spinner_idx: usize,
    task_rx: Option<Receiver<TaskResult>>,
    logfile_path: Option<PathBuf>,
}

// --- ЛОГИКА ПРИЛОЖЕНИЯ ---

impl App {
    fn new(simulation: bool, debug: bool, update_interval_secs: u64, ascii_mode: bool) -> Result<Self> {
        let logger = Logger::new();
        let log_path = logger.get_log_path().clone();
        let _ = logger.info(&format!("SELab started (simulation: {})", simulation));
        
        let selinux_mode_manager = SELinuxModeManager::new().unwrap_or_else(|_| {
            // Fallback если не удалось определить режим - создаем с дефолтным режимом
            // Используем временный способ создания через set_mode
            let mut mgr = SELinuxModeManager {
                current_mode: SELinuxMode::Enforcing,
            };
            let _ = mgr.set_mode(SELinuxMode::Enforcing, false, true);
            mgr
        });
        
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
            logger,
            selinux_mode_manager,
            
            system_stats: SystemStats {
                total_avc_alerts: 0,
                avc_by_severity: std::collections::HashMap::new(),
                avc_by_permission: std::collections::HashMap::new(),
                avc_by_source: std::collections::HashMap::new(),
                total_booleans: 0,
                booleans_changed: 0,
                total_modules: 0,
                modules_enabled: 0,
                total_changes: 0,
                recent_changes: Vec::new(),
                risk_score: 0.0,
            },
            avc_recommendations: Vec::new(),
            avc_severity_filter: None,

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
            logfile_path: Some(log_path),
        };

        if debug {
            app.logfile_path = Some(PathBuf::from("selab_debug.log"));
        }

        app.refresh_data()?;
        app.update_stats();
        app.update_recommendations();
        Ok(app)
    }
    
    fn update_stats(&mut self) {
        self.system_stats = StatsManager::calculate_stats(
            &self.avc_manager,
            &self.boolean_manager,
            &self.module_manager,
            &self.rollback_manager,
        );
    }
    
    fn update_recommendations(&mut self) {
        self.avc_recommendations = self.advisor.analyze_avc_alerts(&self.avc_manager.alerts);
    }

    // Запуск задачи в отдельном потоке (чтобы UI не зависал)
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
            // В реальном режиме загрузка логов может занимать время.
            // Для простоты инициализация остается синхронной.
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
        // 1. Если заняты (крутится спиннер), блокируем ввод, кроме выхода
        if self.is_busy {
            if let KeyCode::Char('q') = key {
                self.should_quit = true;
            }
            return Ok(());
        }

        // 2. Режим ввода текста (Add / Search)
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

        // 3. Обычный режим навигации
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
                self.update_stats();
                self.update_recommendations();
                self.set_status("Data refreshed".into(), Color::Green);
            }
            KeyCode::Char('e') => self.show_export_popup(),
            KeyCode::Char('i') => self.show_import_popup(),
            KeyCode::Char('v') => self.show_detail_view(),
            KeyCode::Char('f') => self.toggle_avc_filter(),
            KeyCode::Char('A') => self.show_avc_recommendations(),
            KeyCode::Char('m') => self.show_create_module_popup(),
            KeyCode::Char('M') => self.toggle_selinux_mode(),
            // Быстрые переходы по цифрам
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
                        9 => CurrentView::Statistics,
                        0 => CurrentView::SELinuxMode,
                        _ => CurrentView::Dashboard,
                    };
                    self.state.list_state.select(Some(0));
                }
            }
            _ => {}
        }
        Ok(())
    }

    // --- ФУНКЦИИ ВВОДА (ADD) ---
    fn show_add_popup(&mut self) {
        match self.state.current_view {
            CurrentView::Ports => self.state.enter_input_mode(PopupType::AddPort),
            CurrentView::FileContexts => self.state.enter_input_mode(PopupType::AddFileContext),
            CurrentView::AVCAlerts => self.state.enter_input_mode(PopupType::CreateModule),
            _ => self.set_status("Add option not available here".into(), Color::Yellow),
        }
    }
    
    fn show_create_module_popup(&mut self) {
        if self.state.current_view == CurrentView::AVCAlerts {
            self.state.enter_input_mode(PopupType::CreateModule);
        } else {
            self.set_status("Create module only available in AVC Alerts view".into(), Color::Yellow);
        }
    }
    
    fn toggle_selinux_mode(&mut self) {
        let current = self.selinux_mode_manager.get_current();
        let current_str = current.to_string();
        let next_mode = match current {
            SELinuxMode::Enforcing => SELinuxMode::Permissive,
            SELinuxMode::Permissive => SELinuxMode::Enforcing,
            SELinuxMode::Disabled => SELinuxMode::Enforcing,
        };
        
        let mut mgr = self.selinux_mode_manager.clone();
        let sim = self.simulation_mode;
        let mode_name = next_mode.to_string();
        let log_msg = format!("SELinux mode changed: {} -> {}", current_str, mode_name);
        
        // Обновляем режим сразу в UI
        self.selinux_mode_manager.current_mode = next_mode;
        
        self.spawn_task(&format!("Setting SELinux mode to {}...", mode_name), move || {
            mgr.set_mode(next_mode, false, sim)?;
            // Обновляем режим после выполнения
            let _ = mgr.refresh();
            Ok((format!("SELinux mode set to {}", mode_name), vec![]))
        });
        
        let _ = self.logger.info(&log_msg);
    }

    fn submit_input(&mut self) -> Result<()> {
        let input = self.state.input_buffer.clone();
        let simulation = self.simulation_mode;

        // Важно: клонируем popup_type, чтобы освободить заимствование self для match
        let popup_type = self.state.popup_type.clone();

        match popup_type {
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

                    // Запускаем добавление в фоне
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
            PopupType::ExportConfig => {
                let filename = if input.is_empty() {
                    format!("selab_config_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S"))
                } else {
                    input
                };
                let path = PathBuf::from(&filename);
                let profile = ConfigExporter::export_profile(
                    "Current Configuration",
                    "Exported configuration",
                    &self.boolean_manager,
                    &self.module_manager,
                    &self.file_context_manager,
                    &self.port_manager,
                )?;
                ConfigExporter::save_to_file(&profile, &path)?;
                self.state.reset_mode();
                self.set_status(format!("Configuration exported to {}", filename), Color::Green);
            }
            PopupType::ImportConfig => {
                let path = PathBuf::from(&input);
                let profile = ConfigExporter::load_from_file(&path)?;
                let mut boolean_mgr = self.boolean_manager.clone();
                let mut module_mgr = self.module_manager.clone();
                let mut file_ctx_mgr = self.file_context_manager.clone();
                let mut port_mgr = self.port_manager.clone();
                let sim = self.simulation_mode;
                self.state.reset_mode();
                
                self.spawn_task("Importing Configuration...", move || {
                    let rb = ConfigExporter::apply_profile(
                        &profile,
                        &mut boolean_mgr,
                        &mut module_mgr,
                        &mut file_ctx_mgr,
                        &mut port_mgr,
                        sim,
                    )?;
                    Ok((format!("Imported configuration from {}", input), rb))
                });
            }
            PopupType::CreateModule => {
                if input.is_empty() {
                    self.set_status("Error: Module name required".into(), Color::Red);
                    return Ok(());
                }
                
                let module_name = input.clone();
                let alerts: Vec<_> = if let Some(idx) = self.state.selected_index {
                    // Создаем модуль из выбранного алерта
                    if let Some(alert) = self.avc_manager.alerts.get(idx) {
                        vec![alert.clone()]
                    } else {
                        vec![]
                    }
                } else {
                    // Создаем модуль из всех алертов
                    self.avc_manager.alerts.clone()
                };
                
                if alerts.is_empty() {
                    self.set_status("Error: No AVC alerts to create module from".into(), Color::Red);
                    return Ok(());
                }
                
                let alert_count = alerts.len();
                let mut module_mgr = self.module_manager.clone();
                let sim = self.simulation_mode;
                let log_msg = format!("Creating module {} from {} alerts", module_name, alert_count);
                self.state.reset_mode();
                
                self.spawn_task(&format!("Creating module {}...", module_name), move || {
                    let result = module_mgr.create_module_from_alerts(&module_name, &alerts, sim)?;
                    let rb = vec![format!("semodule -r {}", module_name)];
                    Ok((result, rb))
                });
                
                let _ = self.logger.info(&log_msg);
            }
            _ => self.state.reset_mode(),
        }
        Ok(())
    }

    // --- ВЫПОЛНЕНИЕ ДЕЙСТВИЙ (TOGGLE / EXECUTE) ---
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
                7 => self.state.current_view = CurrentView::Statistics,
                8 => self.state.current_view = CurrentView::SELinuxMode,
                _ => {}
            },
            CurrentView::SELinuxMode => {
                self.toggle_selinux_mode();
            }
            CurrentView::ModuleManager => {
                if let Some(module) = self.module_manager.modules.get(selected).cloned() {
                    // Показываем рекомендацию если есть
                    if let Some(advice) = self.advisor.get_module_advice(&module.name) {
                        let detail = format!(
                            "Module: {}\n\n{}\n\nRisk: {}\nSuggestion: {}\n\nPress Enter again to toggle.",
                            module.name, advice.description, advice.risk, advice.suggestion
                        );
                        self.state.popup_type = PopupType::DetailView(detail);
                        self.state.input_mode = InputMode::Editing;
                        return Ok(());
                    }
                    
                    let mut mgr = self.module_manager.clone();
                    let sim = self.simulation_mode;
                    let action = if module.enabled { "Disabling" } else { "Enabling" };

                    let log_msg = format!("{} module {}", action, module.name);
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
                    let _ = self.logger.info(&log_msg);
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
                    // Показываем рекомендацию если есть
                    if let Some(advice) = self.advisor.get_port_advice(&p.port, &p.protocol) {
                        let detail = format!(
                            "Port: {}/{}\nCurrent context: {}\n\n{}\n\nRisk: {}\nSuggestion: {}\n\nPress Enter again to remove.",
                            p.port, p.protocol, p.context, advice.description, advice.risk, advice.suggestion
                        );
                        self.state.popup_type = PopupType::DetailView(detail);
                        self.state.input_mode = InputMode::Editing;
                        return Ok(());
                    }
                    
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

    // --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
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
            let text = "Global Keys:\n?: Context Help\n/: Search\na: Add Item\nm: Create Module from AVC\nM: Toggle SELinux Mode\nr: Undo Last\ns: Auto-Secure\nR: Refresh Data\ne: Export Config\ni: Import Config\nv: View Details\nf: Filter AVC\nA: AVC Recommendations\n0: SELinux Mode View".to_string();
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
        // Роллбэк выполняется синхронно, так как требует доступа к истории в self
        self.rollback_manager.rollback_last(self.simulation_mode)?;
        let _ = self.logger.info("Rolled back last change");
        self.set_status("Rolled back last change".into(), Color::Yellow);
        Ok(())
    }
    
    fn show_export_popup(&mut self) {
        self.state.enter_input_mode(PopupType::ExportConfig);
    }
    
    fn show_import_popup(&mut self) {
        self.state.enter_input_mode(PopupType::ImportConfig);
    }
    
    fn show_detail_view(&mut self) {
        let detail = match self.state.current_view {
            CurrentView::AVCAlerts => {
                if let Some(idx) = self.state.selected_index {
                    if let Some(alert) = self.avc_manager.alerts.get(idx) {
                        let advice = self.advisor.get_avc_advice(alert);
                        format!(
                            "AVC Alert Details:\n\nTimestamp: {}\nCommand: {}\nPath: {}\nPermission: {}\nSource: {}\nTarget: {}\nClass: {}\nSeverity: {:?}\n\n{}\n\n{}",
                            alert.timestamp,
                            alert.comm,
                            alert.path,
                            alert.permission,
                            alert.source_context,
                            alert.target_context,
                            alert.target_class,
                            alert.severity,
                            advice.as_ref().map(|a| a.description.as_str()).unwrap_or("No advice available"),
                            advice.as_ref().map(|a| a.suggestion.as_str()).unwrap_or("")
                        )
                    } else {
                        "No alert selected".to_string()
                    }
                } else {
                    "No alert selected".to_string()
                }
            }
            CurrentView::BooleanManager => {
                if let Some(idx) = self.state.selected_index {
                    let bools = self.get_filtered_booleans();
                    if let Some(b) = bools.get(idx) {
                        let advice = self.advisor.get_advice(&b.name);
                        format!(
                            "Boolean Details:\n\nName: {}\nCurrent: {}\nDefault: {}\nPersistent: {}\nDescription: {}\n\n{}\n\n{}",
                            b.name,
                            b.current_value,
                            b.default_value,
                            b.persistent,
                            b.description,
                            advice.map(|a| a.description.as_str()).unwrap_or("No advice available"),
                            advice.map(|a| a.suggestion.as_str()).unwrap_or("")
                        )
                    } else {
                        "No boolean selected".to_string()
                    }
                } else {
                    "No boolean selected".to_string()
                }
            }
            _ => "Detail view not available for this view".to_string(),
        };
        self.state.popup_type = PopupType::DetailView(detail);
        self.state.input_mode = InputMode::Editing;
    }
    
    fn toggle_avc_filter(&mut self) {
        self.avc_severity_filter = match self.avc_severity_filter {
            None => Some(avc::AVCSeverity::High),
            Some(avc::AVCSeverity::High) => Some(avc::AVCSeverity::Medium),
            Some(avc::AVCSeverity::Medium) => Some(avc::AVCSeverity::Low),
            Some(avc::AVCSeverity::Low) => None,
        };
        let filter_text = match self.avc_severity_filter {
            Some(avc::AVCSeverity::High) => "High",
            Some(avc::AVCSeverity::Medium) => "Medium",
            Some(avc::AVCSeverity::Low) => "Low",
            None => "All",
        };
        self.set_status(format!("AVC Filter: {}", filter_text), Color::Cyan);
    }
    
    fn show_avc_recommendations(&mut self) {
        if self.avc_recommendations.is_empty() {
            self.set_status("No recommendations available".into(), Color::Yellow);
            return;
        }
        self.state.popup_type = PopupType::AVCRecommendations;
        self.state.input_mode = InputMode::Editing;
    }
    
    fn get_filtered_avc_alerts(&self) -> Vec<avc::AVCAlert> {
        if let Some(severity) = &self.avc_severity_filter {
            self.avc_manager.alerts.iter()
                .filter(|a| std::mem::discriminant(&a.severity) == std::mem::discriminant(severity))
                .cloned()
                .collect()
        } else {
            self.avc_manager.alerts.clone()
        }
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

    // --- ЦИКЛ ОБНОВЛЕНИЯ (TICK) ---
    fn tick(&mut self) -> Result<()> {
        if self.is_busy {
            self.spinner_idx = (self.spinner_idx + 1) % 4;
            if let Some(rx) = &self.task_rx {
                if let Ok(res) = rx.try_recv() {
                    self.is_busy = false;
                    self.task_rx = None;

                    if let Some(err) = res.error {
                        let _ = self.logger.error(&format!("Task failed: {}", err));
                        self.set_status(format!("Error: {}", err), Color::Red);
                    } else {
                        self.set_status(format!("Success: {}", res.description), Color::Green);
                        let _ = self.logger.info(&format!("Task completed: {}", res.description));
                        
                        // Обновляем режим SELinux если это было переключение режима
                        if res.action.contains("SELinux mode") || res.description.contains("SELinux mode") {
                            let _ = self.selinux_mode_manager.refresh();
                        }
                        
                        self.refresh_data()?;
                        self.update_stats();
                        self.update_recommendations();
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
            // Периодически обновляем режим SELinux
            let _ = self.selinux_mode_manager.refresh();
            self.refresh_data()?;
            self.last_update = Instant::now();
        }
        Ok(())
    }

    // --- ОТРИСОВКА ИНТЕРФЕЙСА ---
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
            CurrentView::Dashboard => 9,
            CurrentView::AVCAlerts => self.get_filtered_avc_alerts().len(),
            CurrentView::ModuleManager => self.module_manager.modules.len(),
            CurrentView::RollbackHistory => self.rollback_manager.change_history.len(),
            CurrentView::SafeSettings => 2,
            CurrentView::FileContexts => self.file_context_manager.contexts.len(),
            CurrentView::Ports => self.port_manager.ports.len(),
            CurrentView::Statistics => 10,
            CurrentView::SELinuxMode => 3,
        };
        self.state.set_current_len(list_len);

        let tabs = Tabs::new(vec![
            "1:Dash", "2:AVC", "3:Mod", "4:Bool", "5:Roll", "6:Safe", "7:File", "8:Port", "9:Stats", "0:Mode",
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
            CurrentView::Statistics => self.render_statistics(f, chunks[1]),
            CurrentView::SELinuxMode => self.render_selinux_mode(f, chunks[1]),
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
                let mut txt = format!(
                    "Add Port Rule\n\nFormat: PORT PROTO TYPE\nExample: 8080 tcp http_port_t\n\n"
                );
                
                // Показываем рекомендации если пользователь начал вводить порт
                if let Some(port_part) = self.state.input_buffer.split_whitespace().next() {
                    if let Ok(_) = port_part.parse::<u16>() {
                        let proto = self.state.input_buffer.split_whitespace().nth(1).unwrap_or("tcp");
                        if let Some(advice) = self.advisor.get_port_advice(port_part, proto) {
                            txt.push_str(&format!("💡 Recommendation: {}\n", advice.suggestion));
                            txt.push_str(&format!("Suggested context: {}\n\n", advice.description));
                        }
                    }
                }
                
                txt.push_str(&format!("> {}", self.state.input_buffer));
                f.render_widget(Paragraph::new(txt).block(block.title("Add Port")), area);
            }
            PopupType::AddFileContext => {
                let mut txt = format!(
                    "Add Context Rule\n\nFormat: PATH TYPE\nExample: /var/www/app httpd_sys_content_t\n\n"
                );
                
                // Показываем рекомендуемые контексты если пользователь начал вводить путь
                if let Some(path_part) = self.state.input_buffer.split_whitespace().next() {
                    if !path_part.is_empty() {
                        let suggested = self.advisor.get_suggested_file_contexts(path_part);
                        if !suggested.is_empty() {
                            txt.push_str("💡 Suggested contexts:\n");
                            for (i, ctx) in suggested.iter().take(5).enumerate() {
                                txt.push_str(&format!("  {}. {}\n", i + 1, ctx));
                            }
                            txt.push_str("\n");
                        }
                    }
                }
                
                txt.push_str(&format!("> {}", self.state.input_buffer));
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
            PopupType::DetailView(text) => {
                f.render_widget(
                    Paragraph::new(text.as_str())
                    .block(block.title("Details"))
                    .wrap(Wrap { trim: true }),
                                area,
                );
            }
            PopupType::ExportConfig => {
                f.render_widget(
                    Paragraph::new(format!("Export Configuration\n\nEnter filename (or press Enter for auto):\n> {}", self.state.input_buffer))
                    .block(block.title("Export Config")),
                                area,
                );
            }
            PopupType::ImportConfig => {
                f.render_widget(
                    Paragraph::new(format!("Import Configuration\n\nEnter filename:\n> {}", self.state.input_buffer))
                    .block(block.title("Import Config")),
                                area,
                );
            }
            PopupType::AVCRecommendations => {
                let text: Vec<Line> = self.avc_recommendations.iter()
                    .map(|r| Line::from(vec![
                        Span::styled(format!("{}\n", r.title), Style::default().fg(Color::Yellow)),
                        Span::raw(format!("{}\n", r.description)),
                        Span::styled(format!("Risk: {}\n\n", r.risk), Style::default().fg(Color::Cyan)),
                    ]))
                    .collect();
                f.render_widget(
                    Paragraph::new(text)
                    .block(block.title("AVC Recommendations"))
                    .wrap(Wrap { trim: true }),
                                area,
                );
            }
            PopupType::CreateModule => {
                let selected_info = if let Some(idx) = self.state.selected_index {
                    if let Some(alert) = self.avc_manager.alerts.get(idx) {
                        format!("Selected alert: {} -> {}", alert.comm, alert.permission)
                    } else {
                        "Will use all alerts".to_string()
                    }
                } else {
                    format!("Will use all {} alerts", self.avc_manager.alerts.len())
                };
                f.render_widget(
                    Paragraph::new(format!(
                        "Create Module from AVC Alerts\n\n{}\n\nEnter module name:\n> {}",
                        selected_info,
                        self.state.input_buffer
                    ))
                    .block(block.title("Create Module")),
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
                             ListItem::new("8. Statistics"),
                             ListItem::new("9. SELinux Mode"),
        ])
        .block(Block::default().borders(Borders::ALL).title("Dashboard"))
        .highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }
    
    fn render_selinux_mode<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let current_mode = self.selinux_mode_manager.get_current();
        let mode_text = current_mode.to_string();
        let mode_color = match current_mode {
            SELinuxMode::Enforcing => Color::Green,
            SELinuxMode::Permissive => Color::Yellow,
            SELinuxMode::Disabled => Color::Red,
        };
        
        let items = vec![
            ListItem::new(Line::from(vec![
                Span::raw("Current Mode: "),
                Span::styled(mode_text, Style::default().fg(mode_color)),
            ])),
            ListItem::new("Press Enter to toggle mode (Enforcing <-> Permissive)"),
            ListItem::new("Press 'M' to toggle mode from anywhere"),
        ];
        
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("SELinux Mode"))
            .highlight_style(Style::default().fg(Color::Yellow));
        f.render_stateful_widget(list, area, &mut self.state.list_state);
    }
    
    fn render_statistics<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let (risk_level, risk_color) = StatsManager::get_risk_level(self.system_stats.risk_score);
        
        let stats_text = vec![
            Line::from(vec![
                Span::styled("System Statistics\n", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("AVC Alerts: "),
                Span::styled(format!("{}", self.system_stats.total_avc_alerts), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::raw("  High: "),
                Span::styled(
                    format!("{}", self.system_stats.avc_by_severity.get("High").copied().unwrap_or(0)),
                    Style::default().fg(Color::Red),
                ),
                Span::raw("  Medium: "),
                Span::styled(
                    format!("{}", self.system_stats.avc_by_severity.get("Medium").copied().unwrap_or(0)),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw("  Low: "),
                Span::styled(
                    format!("{}", self.system_stats.avc_by_severity.get("Low").copied().unwrap_or(0)),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("Booleans: "),
                Span::styled(format!("{} total", self.system_stats.total_booleans), Style::default().fg(Color::Cyan)),
                Span::raw(" ("),
                Span::styled(format!("{} changed", self.system_stats.booleans_changed), Style::default().fg(Color::Yellow)),
                Span::raw(")"),
            ]),
            Line::from(vec![
                Span::raw("Modules: "),
                Span::styled(format!("{}", self.system_stats.total_modules), Style::default().fg(Color::Cyan)),
                Span::raw(" ("),
                Span::styled(format!("{} enabled", self.system_stats.modules_enabled), Style::default().fg(Color::Green)),
                Span::raw(")"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("Total Changes: "),
                Span::styled(format!("{}", self.system_stats.total_changes), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("Risk Score: "),
                Span::styled(
                    format!("{:.1} ({})", self.system_stats.risk_score, risk_level),
                    Style::default().fg(risk_color),
                ),
            ]),
        ];
        
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Statistics");
        f.render_widget(
            Paragraph::new(stats_text)
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
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
        let alerts = self.get_filtered_avc_alerts();
        let filter_text = match self.avc_severity_filter {
            Some(avc::AVCSeverity::High) => " (High)",
            Some(avc::AVCSeverity::Medium) => " (Medium)",
            Some(avc::AVCSeverity::Low) => " (Low)",
            None => "",
        };
        let items: Vec<ListItem> = alerts
        .iter()
        .map(|a| {
            let severity_mark = match a.severity {
                avc::AVCSeverity::High => "[!]",
                avc::AVCSeverity::Medium => "[~]",
                avc::AVCSeverity::Low => "[ ]",
            };
            ListItem::new(format!("{} {} {} {}", severity_mark, a.comm, a.permission, a.path))
        })
        .collect();
        f.render_stateful_widget(
            List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!("AVC Alerts{} (Press 'f' to filter)", filter_text)))
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
        let log_info = if let Some(ref path) = self.logfile_path {
            format!("Log: {}", path.file_name().unwrap_or_default().to_string_lossy())
        } else {
            String::new()
        };
        
        let msg = if self.is_busy {
            "Working..."
        } else {
            "?:Help /:Search a:Add m:Module M:Mode e:Export i:Import v:Details f:Filter A:Recs q:Quit"
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
        let footer_text = if !log_info.is_empty() {
            format!("{} | {} | {}", msg, status, log_info)
        } else {
            format!("{} | {}", msg, status)
        };
        f.render_widget(
            Paragraph::new(footer_text)
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
