pub const DEFAULT_PORT: u16 = 3000;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 25;
pub const DEFAULT_MIN_CONNECTIONS: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub database_url: String,
    pub port: u16,

    // CORS
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,

    // DB pool
    pub max_connections: u32,
    pub min_connections: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")?;
        let port = match std::env::var("PORT") {
            Ok(val) => val.parse::<u16>()?,
            Err(_) => DEFAULT_PORT,
        };

        Ok(Self {
            database_url,
            port,
            allowed_origins: Vec::new(),
            allowed_methods: vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]
                .into_iter()
                .map(String::from)
                .collect(),
            allowed_headers: vec!["Authorization", "Content-Type"]
                .into_iter()
                .map(String::from)
                .collect(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
        })
    }
}

#[test]
fn test_config_defaults() {
    let cfg = Config {
        database_url: "postgres://user:pass@localhost:5432/metal_auth".into(),
        port: DEFAULT_PORT,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into(), "POST".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: DEFAULT_MAX_CONNECTIONS,
        min_connections: DEFAULT_MIN_CONNECTIONS,
    };

    assert_eq!(cfg.port, 3000);
    assert_eq!(cfg.max_connections, 25);
    assert_eq!(cfg.min_connections, 2);
}
