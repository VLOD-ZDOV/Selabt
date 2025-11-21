use ratatui::widgets::ListState;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CurrentView {
    Dashboard,
    AVCAlerts,
    ModuleManager,
    BooleanManager,
    RollbackHistory,
    SafeSettings,
    FileContexts,
    Ports,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Editing, // Пользователь вводит текст
    Search,  // Пользователь ищет
}

#[derive(Debug, Clone, PartialEq)]
pub enum PopupType {
    None,
    AddPort,
    AddFileContext,
    Help(String), // Показать справку по конкретному ключу
    Search,
}

impl CurrentView {
    pub fn next(&self) -> Self {
        match self {
            Self::Dashboard => Self::AVCAlerts,
            Self::AVCAlerts => Self::ModuleManager,
            Self::ModuleManager => Self::BooleanManager,
            Self::BooleanManager => Self::RollbackHistory,
            Self::RollbackHistory => Self::SafeSettings,
            Self::SafeSettings => Self::FileContexts,
            Self::FileContexts => Self::Ports,
            Self::Ports => Self::Dashboard,
        }
    }

    pub fn previous(&self) -> Self {
        match self {
            Self::Dashboard => Self::Ports,
            Self::AVCAlerts => Self::Dashboard,
            Self::ModuleManager => Self::AVCAlerts,
            Self::BooleanManager => Self::ModuleManager,
            Self::RollbackHistory => Self::BooleanManager,
            Self::SafeSettings => Self::RollbackHistory,
            Self::FileContexts => Self::SafeSettings,
            Self::Ports => Self::FileContexts,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub current_view: CurrentView,
    pub list_state: ListState,
    pub selected_index: Option<usize>,
    pub current_items_len: usize,

    // Новые поля
    pub input_mode: InputMode,
    pub popup_type: PopupType,
    pub input_buffer: String, // Буфер для ввода текста
    pub input_cursor_position: usize,
    pub search_query: String, // Текущый поисковый запрос
}

impl AppState {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            current_view: CurrentView::Dashboard,
            list_state,
            selected_index: Some(0),
            current_items_len: 0,
            input_mode: InputMode::Normal,
            popup_type: PopupType::None,
            input_buffer: String::new(),
            input_cursor_position: 0,
            search_query: String::new(),
        }
    }

    pub fn set_current_len(&mut self, len: usize) {
        self.current_items_len = len;
        // Подстрахуемся: если выбранный индекс вышел за предел, вернем его к последнему элементу
        if let Some(sel) = self.list_state.selected() {
            if sel >= self.current_items_len.saturating_sub(1) && self.current_items_len > 0 {
                self.list_state.select(Some(self.current_items_len.saturating_sub(1)));
                self.selected_index = self.list_state.selected();
            }
        }
    }

    pub fn enter_input_mode(&mut self, popup: PopupType) {
        self.input_mode = InputMode::Editing;
        self.popup_type = popup;
        self.input_buffer.clear();
        self.input_cursor_position = 0;
    }

    pub fn enter_search_mode(&mut self) {
        self.input_mode = InputMode::Search;
        self.popup_type = PopupType::Search;
        self.input_buffer.clear();
    }

    pub fn reset_mode(&mut self) {
        self.input_mode = InputMode::Normal;
        self.popup_type = PopupType::None;
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
        self.current_items_len
    }
}
