use ratatui::widgets::ListState;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CurrentView {
    Dashboard,
    AVCAlerts,
    ModuleManager,
    BooleanManager,
    RollbackHistory,
    SafeSettings,
}

impl CurrentView {
    pub fn next(&self) -> Self {
        match self {
            Self::Dashboard => Self::AVCAlerts,
            Self::AVCAlerts => Self::ModuleManager,
            Self::ModuleManager => Self::BooleanManager,
            Self::BooleanManager => Self::RollbackHistory,
            Self::RollbackHistory => Self::SafeSettings,
            Self::SafeSettings => Self::Dashboard,
        }
    }

    pub fn previous(&self) -> Self {
        match self {
            Self::Dashboard => Self::SafeSettings,
            Self::AVCAlerts => Self::Dashboard,
            Self::ModuleManager => Self::AVCAlerts,
            Self::BooleanManager => Self::ModuleManager,
            Self::RollbackHistory => Self::BooleanManager,
            Self::SafeSettings => Self::RollbackHistory,
        }
    }
}

pub struct AppState {
    pub current_view: CurrentView,
    pub list_state: ListState,
    pub selected_index: Option<usize>,
}

impl AppState {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            current_view: CurrentView::Dashboard,
            list_state,
            selected_index: Some(0),
        }
    }

    pub fn next_view(&mut self) {
        self.current_view = self.current_view.next();
        self.list_state.select(Some(0));
        self.selected_index = Some(0);
    }

    pub fn previous_view(&mut self) {
        self.current_view = self.current_view.previous();
        self.list_state.select(Some(0));
        self.selected_index = Some(0);
    }

    pub fn next_item(&mut self) {
        let current = self.list_state.selected().unwrap_or(0);
        let item_count = self.get_current_item_count();
        if current < item_count.saturating_sub(1) {
            self.list_state.select(Some(current + 1));
            self.selected_index = Some(current + 1);
        }
    }

    pub fn previous_item(&mut self) {
        let current = self.list_state.selected().unwrap_or(0);
        if current > 0 {
            self.list_state.select(Some(current - 1));
            self.selected_index = Some(current - 1);
        }
    }

    fn get_current_item_count(&self) -> usize {
        // Заглушка - в реальности зависит от данных в текущем виде
        match self.current_view {
            CurrentView::Dashboard => 5,
            CurrentView::AVCAlerts => 10,
            CurrentView::ModuleManager => 8,
            CurrentView::BooleanManager => 12,
            CurrentView::RollbackHistory => 6,
            CurrentView::SafeSettings => 6,
        }
    }
}
