// advisor.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
//use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advice {
    pub key: String,        // Например, имя boolean или avc denial
    pub title: String,      // Понятный заголовок
    pub description: String,// Простое объяснение
    pub risk: String,       // Уровень риска: Low, Medium, High
    pub suggestion: String, // Что делать
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
        ];
        for tip in defaults {
            self.knowledge_base.insert(tip.key.clone(), tip);
        }
    }
}
