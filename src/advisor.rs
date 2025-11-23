// advisor.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use crate::avc::AVCAlert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advice {
    pub key: String,        // Например, имя boolean или avc denial
    pub title: String,      // Понятный заголовок
    pub description: String,// Простое объяснение
    pub risk: String,       // Уровень риска: Low, Medium, High
    pub suggestion: String, // Что делать
}

#[derive(Debug, Clone)]
pub struct AutoRecommendation {
    pub title: String,
    pub description: String,
    pub risk: String,
    pub action_type: String, // "boolean", "module", "file_context", "port"
    pub action_key: String,
    pub action_value: Option<String>,
}

pub struct Advisor {
    pub knowledge_base: HashMap<String, Advice>,
}

impl Advisor {
    pub fn new() -> Self {
        let mut advisor = Self {
            knowledge_base: HashMap::new(),
        };
        // Пытаемся загрузить из файла, если нет - грузим дефолтные
        if let Err(_) = advisor.load_from_file("selab_tips.json") {
            advisor.load_defaults();
        }
        advisor
    }

    pub fn load_from_file(&mut self, filename: &str) -> anyhow::Result<()> {
        let data = fs::read_to_string(filename)?;
        let tips: Vec<Advice> = serde_json::from_str(&data)?;
        for tip in tips {
            self.knowledge_base.insert(tip.key.clone(), tip);
        }
        Ok(())
    }

    pub fn get_advice(&self, key: &str) -> Option<&Advice> {
        self.knowledge_base.get(key)
    }

    /// Получает рекомендации для портов
    pub fn get_port_advice(&self, port: &str, protocol: &str) -> Option<Advice> {
        // Стандартные порты и их рекомендуемые контексты
        let port_num: u16 = port.parse().ok()?;
        let (context, risk, suggestion) = match (port_num, protocol.to_lowercase().as_str()) {
            (80, "tcp") | (443, "tcp") => (
                "http_port_t",
                "Low",
                "Стандартные порты для HTTP/HTTPS. Используйте http_port_t."
            ),
            (22, "tcp") => (
                "ssh_port_t",
                "Low",
                "Стандартный порт SSH. Используйте ssh_port_t."
            ),
            (25, "tcp") => (
                "smtp_port_t",
                "Medium",
                "Порт SMTP. Используйте smtp_port_t."
            ),
            (53, "tcp") | (53, "udp") => (
                "dns_port_t",
                "Medium",
                "Порт DNS. Используйте dns_port_t."
            ),
            (3306, "tcp") => (
                "mysqld_port_t",
                "Medium",
                "Порт MySQL. Используйте mysqld_port_t."
            ),
            (5432, "tcp") => (
                "postgresql_port_t",
                "Medium",
                "Порт PostgreSQL. Используйте postgresql_port_t."
            ),
            (8080, "tcp") | (8443, "tcp") => (
                "http_port_t",
                "Low",
                "Альтернативные порты для веб-серверов. Используйте http_port_t."
            ),
            _ => return None,
        };

        Some(Advice {
            key: format!("port_{}_{}", port, protocol),
             title: format!("Рекомендация для порта {}/{}", port, protocol),
             description: format!("Рекомендуемый контекст: {}", context),
             risk: risk.to_string(),
             suggestion: suggestion.to_string(),
        })
    }

    /// Получает рекомендации для модулей
    pub fn get_module_advice(&self, module_name: &str) -> Option<Advice> {
        // Проверяем известные модули
        let (description, risk, suggestion) = if module_name.contains("httpd") || module_name.contains("apache") {
            (
                "Модуль для веб-сервера Apache",
             "Low",
             "Обычно безопасно включать для работы веб-сервера."
            )
        } else if module_name.contains("mysql") || module_name.contains("mariadb") {
            (
                "Модуль для MySQL/MariaDB",
             "Medium",
             "Включайте только если используете базу данных MySQL."
            )
        } else if module_name.contains("postgres") {
            (
                "Модуль для PostgreSQL",
             "Medium",
             "Включайте только если используете PostgreSQL."
            )
        } else {
            return None;
        };

        Some(Advice {
            key: format!("module_{}", module_name),
             title: format!("Рекомендация для модуля {}", module_name),
             description: description.to_string(),
             risk: risk.to_string(),
             suggestion: suggestion.to_string(),
        })
    }

    /// Получает рекомендации для файловых контекстов
    pub fn get_file_context_advice(&self, path: &str) -> Option<Advice> {
        let (context, risk, suggestion) = match path {
            p if p.starts_with("/var/www") => (
                "httpd_sys_content_t",
                "Low",
                "Стандартный контекст для веб-контента."
            ),
            p if p.starts_with("/home") => (
                "user_home_t",
                "Medium",
                "Контекст для домашних директорий. Будьте осторожны с доступом."
            ),
            p if p.starts_with("/etc") => (
                "etc_t",
                "Low",
                "Контекст для системных конфигов."
            ),
            _ => return None,
        };

        Some(Advice {
            key: format!("file_{}", path),
             title: format!("Рекомендация для пути {}", path),
             description: format!("Рекомендуемый контекст: {}", context),
             risk: risk.to_string(),
             suggestion: suggestion.to_string(),
        })
    }

    /// Возвращает предложенные контексты для пути (используется в UI)
    pub fn get_suggested_file_contexts(&self, path_part: &str) -> Vec<String> {
        // Простая эвристика на основе пути
        let mut suggestions = Vec::new();
        if path_part.contains("www") || path_part.contains("html") {
            suggestions.push("httpd_sys_content_t".to_string());
        }
        if path_part.starts_with("home") || path_part.contains("/user/") {
            suggestions.push("user_home_t".to_string());
        }
        if path_part.starts_with("etc") {
            suggestions.push("etc_t".to_string());
        }
        if path_part.contains("bin") || path_part.contains("sbin") {
            suggestions.push("bin_t".to_string());
        }
        if suggestions.is_empty() {
            suggestions.push("default_t".to_string()); // fallback
        }
        suggestions
    }

    /// Анализирует список AVC алертов и возвращает рекомендации
    pub fn analyze_avc_alerts(&self, alerts: &[AVCAlert]) -> Vec<AutoRecommendation> {
        let mut recommendations = Vec::new();

        for alert in alerts {
            if let Some(advice) = self.get_avc_advice(alert) {
                recommendations.push(AutoRecommendation {
                    title: advice.title.clone(),
                                     description: advice.description.clone(),
                                     risk: advice.risk.clone(),
                                     action_type: "avc_fix".to_string(),
                                     action_key: alert.comm.clone(),
                                     action_value: Some(advice.suggestion.clone()),
                });
            }

            // Дополнительные правила на основе паттернов
            if alert.source_context.contains("httpd_t") && alert.permission == "read" {
                recommendations.push(AutoRecommendation {
                    title: "Веб-сервер не может читать файлы".to_string(),
                                     description: format!("Httpd пытается прочитать {}", alert.path),
                                     risk: "Medium".to_string(),
                                     action_type: "file_context".to_string(),
                                     action_key: alert.path.clone(),
                                     action_value: Some("httpd_sys_content_t".to_string()),
                });
            } else if alert.permission == "connect" && alert.target_class == "tcp_socket" {
                recommendations.push(AutoRecommendation {
                    title: "Процесс пытается установить соединение".to_string(),
                                     description: format!("{} не может подключиться к сети", alert.comm),
                                     risk: "High".to_string(),
                                     action_type: "boolean".to_string(),
                                     action_key: format!("{}_can_network_connect", alert.comm),
                                     action_value: Some("true".to_string()),
                });
            } else if alert.source_context.contains("unconfined_t") {
                recommendations.push(AutoRecommendation {
                    title: "Unconfined процесс".to_string(),
                                     description: "Процесс работает без ограничений SELinux".to_string(),
                                     risk: "High".to_string(),
                                     action_type: "policy".to_string(),
                                     action_key: "review_required".to_string(),
                                     action_value: None,
                });
            }
        }

        recommendations
    }

    /// Получает рекомендацию для конкретного AVC алерта
    pub fn get_avc_advice(&self, alert: &AVCAlert) -> Option<Advice> {
        // Пытаемся найти точное совпадение
        let key = format!("avc_{}_{}",
                          alert.source_context.split(':').next().unwrap_or("unknown"),
                          alert.permission
        );

        if let Some(advice) = self.knowledge_base.get(&key) {
            return Some(advice.clone());
        }

        // Генерируем общий совет на основе паттерна
        let risk = match alert.severity {
            crate::avc::AVCSeverity::High => "High",
            crate::avc::AVCSeverity::Medium => "Medium",
            crate::avc::AVCSeverity::Low => "Low",
        };

        Some(Advice {
            key: key.clone(),
             title: format!("AVC Denial: {} -> {}", alert.source_context, alert.target_context),
             description: format!(
                 "Процесс {} пытается выполнить действие '{}' на {} (класс: {}), но SELinux блокирует это.",
                                  alert.comm, alert.permission, alert.path, alert.target_class
             ),
             risk: risk.to_string(),
             suggestion: format!(
                 "Проверьте контексты: scontext={}, tcontext={}. Используйте audit2allow для генерации правил или настройте файловые контексты.",
                 alert.source_context, alert.target_context
             ),
        })
    }

    fn load_defaults(&mut self) {
        // Встроенные советы для старта
        let defaults = vec![
            Advice {
                key: "httpd_can_network_connect".to_string(),
                title: "Разрешить сайту исходящие соединения".to_string(),
                description: "Если ваш сайт должен обращаться к внешним API или другим серверам, включите это.".to_string(),
                risk: "Medium".to_string(),
                suggestion: "Включайте только если сайт реально делает запросы наружу.".to_string(),
            },
            Advice {
                key: "ftpd_anon_write".to_string(),
                title: "Анонимная запись на FTP".to_string(),
                description: "Позволяет анонимным пользователям загружать файлы на сервер.".to_string(),
                risk: "High".to_string(),
                suggestion: "Держите выключенным, если не уверены. Это частый вектор атаки.".to_string(),
            },
            Advice {
                key: "httpd_read_user_content".to_string(),
                title: "Доступ веб-сервера к домашним папкам".to_string(),
                description: "Разрешает Apache/Nginx читать файлы в /home/user/public_html.".to_string(),
                risk: "Medium".to_string(),
                suggestion: "Включите, если хостите сайты пользователей.".to_string(),
            },
            Advice {
                key: "avc_general".to_string(),
                title: "Общие AVC отказы".to_string(),
                description: "SELinux блокирует доступ к ресурсам.".to_string(),
                risk: "Medium".to_string(),
                suggestion: "Используйте audit2allow для анализа и генерации правил, или настройте контексты файлов/портов.".to_string(),
            },
            Advice {
                key: "httpd_enable_homedirs".to_string(),
                title: "Доступ httpd к домашним директориям".to_string(),
                description: "Разрешает веб-серверу читать файлы в домашних директориях пользователей.".to_string(),
                risk: "Medium".to_string(),
                suggestion: "Включайте только если необходимо для работы пользовательских сайтов.".to_string(),
            },
            Advice {
                key: "allow_ssh_keysign".to_string(),
                title: "SSH ключи подпись".to_string(),
                description: "Разрешает SSH использовать ключи для подписи.".to_string(),
                risk: "Low".to_string(),
                suggestion: "Обычно безопасно включать для SSH аутентификации.".to_string(),
            },
        ];
        for tip in defaults {
            self.knowledge_base.insert(tip.key.clone(), tip);
        }
    }
}
