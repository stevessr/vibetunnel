use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use axum::{
    extract::{
        ws::Message,
        ConnectInfo,
        Path as AxumPath,
        Query,
        State,
        WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{ChildStdin, Command as TokioCommand},
    sync::Mutex,
    task::JoinHandle,
    time::{interval, interval_at, Instant as TokioInstant},
};
use tower_http::{compression::CompressionLayer, set_header::SetResponseHeaderLayer};
use vibetunnel_rs::protocol::{
    snapshot,
    ws_v3::{
        decode_frame, decode_subscribe_payload, encode_frame, WsV3Frame, WsV3MessageType,
        WsV3SubscribeFlags, WS_V3_VERSION,
    },
};

#[derive(Debug, Parser)]
#[command(name = "vibetunnel")]
#[command(about = "VibeTunnel Rust server")]
struct Cli {
    /// Server port
    #[arg(long)]
    port: Option<u16>,

    /// Bind address
    #[arg(long)]
    bind: Option<String>,

    /// Disable auth
    #[arg(long = "no-auth", default_value_t = false)]
    no_auth: bool,

    /// Enable SSH key auth
    #[arg(long = "enable-ssh-keys", default_value_t = false)]
    enable_ssh_keys: bool,

    /// Disallow user/password auth
    #[arg(long = "disallow-user-password", default_value_t = false)]
    disallow_user_password: bool,

    /// Run as HQ server mode
    #[arg(long = "hq", default_value_t = false)]
    is_hq_mode: bool,

    /// HQ URL when running as remote
    #[arg(long = "hq-url")]
    hq_url: Option<String>,

    /// HQ username for registration
    #[arg(long = "hq-username")]
    hq_username: Option<String>,

    /// HQ password for registration
    #[arg(long = "hq-password")]
    hq_password: Option<String>,

    /// Remote name when registering with HQ
    #[arg(long = "name")]
    remote_name: Option<String>,

    /// Allow insecure HQ URL
    #[arg(long = "allow-insecure-hq", default_value_t = false)]
    allow_insecure_hq: bool,

    /// Enable push notifications
    #[arg(long = "push-enabled", default_value_t = true)]
    push_enabled: bool,

    /// Disable push notifications
    #[arg(long = "push-disabled", default_value_t = false)]
    push_disabled: bool,

    /// VAPID contact email
    #[arg(long = "vapid-email")]
    vapid_email: Option<String>,

    /// Auto-generate VAPID keys
    #[arg(long = "generate-vapid-keys", default_value_t = false)]
    generate_vapid_keys: bool,

    /// Allow localhost auth bypass
    #[arg(long = "allow-local-bypass", default_value_t = false)]
    allow_local_bypass: bool,

    /// Local auth token
    #[arg(long = "local-auth-token")]
    local_auth_token: Option<String>,

    /// Enable Tailscale Serve
    #[arg(long = "enable-tailscale-serve", default_value_t = false)]
    enable_tailscale_serve: bool,

    /// Enable Tailscale Funnel
    #[arg(long = "enable-tailscale-funnel", default_value_t = false)]
    enable_tailscale_funnel: bool,

    /// Disable HQ auth for testing
    #[arg(long = "no-hq-auth", default_value_t = false)]
    no_hq_auth: bool,

    /// Disable mDNS advertisement
    #[arg(long = "no-mdns", default_value_t = false)]
    no_mdns: bool,

    /// Enable ngrok tunnel
    #[arg(long = "ngrok", default_value_t = false)]
    enable_ngrok: bool,

    /// Ngrok auth token
    #[arg(long = "ngrok-auth")]
    ngrok_auth_token: Option<String>,

    /// Ngrok custom domain
    #[arg(long = "ngrok-domain")]
    ngrok_domain: Option<String>,

    /// Ngrok region
    #[arg(long = "ngrok-region")]
    ngrok_region: Option<String>,

    /// Enable Cloudflare tunnel
    #[arg(long = "cloudflare", default_value_t = false)]
    enable_cloudflare: bool,

    /// Debug logging
    #[arg(long, default_value_t = false)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show server status
    Status,
    /// Enable follow mode
    Follow {
        /// Optional branch name
        branch: Option<String>,
    },
    /// Disable follow mode
    Unfollow,
    /// Emit git event
    #[command(name = "git-event")]
    GitEvent,
    /// Print version
    Version,
}

#[derive(Debug, Clone)]
struct AppState {
    config: Arc<ServerConfig>,
    sessions: Arc<Mutex<Vec<SessionEntry>>>,
    session_outputs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    session_subscriptions: Arc<Mutex<HashMap<String, HashMap<String, u32>>>>,
    ws_clients: Arc<Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>>,
    session_dimensions: Arc<Mutex<HashMap<String, (u32, u32)>>>,
    git_watchers: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    local_processes: Arc<Mutex<HashMap<String, LocalSessionProcess>>>,
    started_at: Instant,
    tailscale_server_url: Arc<Mutex<Option<String>>>,
    app_config: Arc<Mutex<AppConfig>>,
    auth_challenges: Arc<Mutex<HashMap<String, AuthChallengeEntry>>>,
    push_subscriptions: Arc<Mutex<Vec<PushSubscriptionEntry>>>,
    uploaded_files: Arc<Mutex<Vec<UploadedFileEntry>>>,
    multiplexer_state: Arc<Mutex<MultiplexerState>>,
    multiplexer_available_cache: Arc<Mutex<MultiplexerAvailabilityCache>>,
    remote_registry: Arc<Mutex<Vec<RemoteServerEntry>>>,
    git_notifications: Arc<Mutex<Vec<GitNotificationEntry>>>,
    git_repo_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    port: u16,
    bind: String,
    no_auth: bool,
    enable_ssh_keys: bool,
    disallow_user_password: bool,
    is_hq_mode: bool,
    hq_url: Option<String>,
    hq_username: Option<String>,
    hq_password: Option<String>,
    remote_name: Option<String>,
    allow_insecure_hq: bool,
    push_enabled: bool,
    vapid_email: Option<String>,
    generate_vapid_keys: bool,
    allow_local_bypass: bool,
    local_auth_token: Option<String>,
    enable_tailscale_serve: bool,
    enable_tailscale_funnel: bool,
    no_hq_auth: bool,
    enable_mdns: bool,
    enable_ngrok: bool,
    ngrok_auth_token: Option<String>,
    ngrok_domain: Option<String>,
    ngrok_region: Option<String>,
    enable_cloudflare: bool,
    version: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionEntry {
    id: String,
    name: String,
    command: Vec<String>,
    #[serde(rename = "workingDir")]
    working_dir: String,
    status: String,
    #[serde(rename = "startedAt")]
    started_at: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    #[serde(rename = "initialCols", skip_serializing_if = "Option::is_none")]
    initial_cols: Option<u16>,
    #[serde(rename = "initialRows", skip_serializing_if = "Option::is_none")]
    initial_rows: Option<u16>,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(rename = "gitModifiedCount", skip_serializing_if = "Option::is_none")]
    git_modified_count: Option<u32>,
    #[serde(rename = "gitAddedCount", skip_serializing_if = "Option::is_none")]
    git_added_count: Option<u32>,
    #[serde(rename = "gitDeletedCount", skip_serializing_if = "Option::is_none")]
    git_deleted_count: Option<u32>,
    #[serde(rename = "gitAheadCount", skip_serializing_if = "Option::is_none")]
    git_ahead_count: Option<u32>,
    #[serde(rename = "gitBehindCount", skip_serializing_if = "Option::is_none")]
    git_behind_count: Option<u32>,
}

#[derive(Debug)]
struct LocalSessionProcess {
    stdin: Option<ChildStdin>,
    pid: u32,
    cols: u16,
    rows: u16,
}

#[derive(Debug, Serialize)]
struct HealthConnections {
    http: HealthHttp,
    port: u16,
    #[serde(rename = "sslAvailable")]
    ssl_available: bool,
    #[serde(rename = "isPublic")]
    is_public: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tailscale: Option<HealthTailscale>,
    #[serde(rename = "tailscaleUrl", skip_serializing_if = "Option::is_none")]
    tailscale_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthHttp {
    port: u16,
    url: String,
}

#[derive(Debug, Serialize)]
struct HealthTailscale {
    available: bool,
    #[serde(rename = "isRunning")]
    is_running: bool,
    #[serde(rename = "httpsAvailable")]
    https_available: bool,
    #[serde(rename = "isPublic")]
    is_public: bool,
    funnel: bool,
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(rename = "httpsUrl", skip_serializing_if = "Option::is_none")]
    https_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    timestamp: String,
    mode: &'static str,
    version: &'static str,
    #[serde(rename = "buildDate")]
    build_date: String,
    uptime: f64,
    pid: u32,
    connections: HealthConnections,
    #[serde(rename = "tailscaleUrl", skip_serializing_if = "Option::is_none")]
    tailscale_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationPreferences {
    enabled: bool,
    #[serde(rename = "sessionStart")]
    session_start: bool,
    #[serde(rename = "sessionExit")]
    session_exit: bool,
    #[serde(rename = "commandCompletion")]
    command_completion: bool,
    #[serde(rename = "commandError")]
    command_error: bool,
    bell: bool,
    #[serde(rename = "soundEnabled")]
    sound_enabled: bool,
    #[serde(rename = "vibrationEnabled")]
    vibration_enabled: bool,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            enabled: false,
            session_start: true,
            session_exit: true,
            command_completion: true,
            command_error: true,
            bell: true,
            sound_enabled: false,
            vibration_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuickStartCommand {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    #[serde(rename = "repositoryBasePath")]
    repository_base_path: String,
    #[serde(rename = "quickStartCommands")]
    quick_start_commands: Vec<QuickStartCommand>,
    #[serde(rename = "notificationPreferences", skip_serializing_if = "Option::is_none")]
    notification_preferences: Option<NotificationPreferences>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            repository_base_path: "~/Documents".to_string(),
            quick_start_commands: vec![],
            notification_preferences: Some(default_notification_preferences()),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppConfigResponse {
    #[serde(rename = "repositoryBasePath")]
    repository_base_path: String,
    #[serde(rename = "serverConfigured")]
    server_configured: bool,
    #[serde(rename = "quickStartCommands")]
    quick_start_commands: Vec<QuickStartCommand>,
    #[serde(rename = "notificationPreferences", skip_serializing_if = "Option::is_none")]
    notification_preferences: Option<NotificationPreferences>,
}

#[derive(Debug, Deserialize)]
struct AppConfigUpdateRequest {
    #[serde(rename = "repositoryBasePath")]
    repository_base_path: Option<serde_json::Value>,
    #[serde(rename = "quickStartCommands")]
    quick_start_commands: Option<serde_json::Value>,
    #[serde(rename = "notificationPreferences")]
    notification_preferences: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationPreferencesPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(rename = "sessionStart", skip_serializing_if = "Option::is_none")]
    session_start: Option<bool>,
    #[serde(rename = "sessionExit", skip_serializing_if = "Option::is_none")]
    session_exit: Option<bool>,
    #[serde(rename = "commandCompletion", skip_serializing_if = "Option::is_none")]
    command_completion: Option<bool>,
    #[serde(rename = "commandError", skip_serializing_if = "Option::is_none")]
    command_error: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bell: Option<bool>,
    #[serde(rename = "soundEnabled", skip_serializing_if = "Option::is_none")]
    sound_enabled: Option<bool>,
    #[serde(rename = "vibrationEnabled", skip_serializing_if = "Option::is_none")]
    vibration_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SessionCreateRequest {
    command: Vec<String>,
    #[serde(rename = "workingDir")]
    working_dir: Option<String>,
    name: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Serialize)]
struct SessionCreateResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SessionInputRequest {
    text: Option<String>,
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SessionResizeRequest {
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct SessionPatchRequest {
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct ServerStatusResponse {
    #[serde(rename = "macAppConnected")]
    mac_app_connected: bool,
    #[serde(rename = "isHQMode")]
    is_hq_mode: bool,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct SessionTailscaleStatusResponse {
    #[serde(rename = "isRunning")]
    is_running: bool,
    #[serde(rename = "isPermanentlyDisabled")]
    is_permanently_disabled: bool,
    #[serde(rename = "lastError", skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    recommendation: String,
    #[serde(rename = "fallbackMode")]
    fallback_mode: String,
    #[serde(rename = "permanentlyDisabled")]
    permanently_disabled: bool,
    #[serde(rename = "serverUrl", skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionTailscaleTestResponse {
    timestamp: String,
    tailscale: serde_json::Value,
    #[serde(rename = "tailscaleServe")]
    tailscale_serve: serde_json::Value,
    server: serde_json::Value,
    recommendations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigQuery {
    token: Option<String>,
    #[serde(rename = "localAuthToken")]
    local_auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyQuery {
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WsQuery {
    token: Option<String>,
    #[serde(rename = "localAuthToken")]
    local_auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthChallengeRequest {
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthSshKeyRequest {
    #[serde(rename = "challengeId")]
    challenge_id: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthPasswordRequest {
    #[serde(rename = "userId")]
    user_id: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Clone)]
struct AuthChallengeEntry {
    user_id: String,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct PushSubscribeRequest {
    endpoint: Option<String>,
    keys: Option<PushSubscribeKeys>,
}

#[derive(Debug, Deserialize)]
struct PushSubscribeKeys {
    p256dh: Option<String>,
    auth: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PushUnsubscribeRequest {
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PushTestRequest {
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitPathQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorktreesQuery {
    #[serde(rename = "repoPath")]
    repo_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateWorktreeRequest {
    #[serde(rename = "repoPath")]
    repo_path: Option<String>,
    branch: Option<String>,
    path: Option<String>,
    #[serde(rename = "baseBranch")]
    base_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteWorktreeQuery {
    #[serde(rename = "repoPath")]
    repo_path: Option<String>,
    force: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PruneWorktreesRequest {
    #[serde(rename = "repoPath")]
    repo_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FollowWorktreesRequest {
    #[serde(rename = "repoPath")]
    repo_path: Option<String>,
    branch: Option<String>,
    enable: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RepositoriesBranchesQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RepositoriesDiscoverQuery {
    path: Option<String>,
    #[serde(rename = "maxDepth")]
    max_depth: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FsPreviewQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FsDiffQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FsMkdirRequest {
    path: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FsCompletionsQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MultiplexerCreateRequest {
    #[serde(rename = "type")]
    mux_type: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MultiplexerAttachRequest {
    #[serde(rename = "type")]
    mux_type: Option<String>,
    #[serde(rename = "sessionName")]
    session_name: Option<String>,
    #[serde(rename = "windowIndex")]
    window_index: Option<u32>,
    #[serde(rename = "paneIndex")]
    pane_index: Option<u32>,
    cols: Option<u16>,
    rows: Option<u16>,
    #[serde(rename = "workingDir")]
    working_dir: Option<String>,
    #[serde(rename = "titleMode")]
    title_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MultiplexerWindowQuery {
    window: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitEventRequest {
    #[serde(rename = "repoPath")]
    repo_path: Option<String>,
    branch: Option<String>,
    event: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TmuxCreateSessionRequest {
    name: Option<String>,
    command: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct TmuxAttachRequest {
    #[serde(rename = "sessionName")]
    session_name: Option<String>,
    #[serde(rename = "windowIndex")]
    window_index: Option<u32>,
    #[serde(rename = "paneIndex")]
    pane_index: Option<u32>,
    cols: Option<u32>,
    rows: Option<u32>,
    #[serde(rename = "workingDir")]
    working_dir: Option<String>,
    #[serde(rename = "titleMode")]
    title_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TmuxSendRequest {
    command: Option<String>,
    #[serde(rename = "windowIndex")]
    window_index: Option<u32>,
    #[serde(rename = "paneIndex")]
    pane_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RegisterRemoteRequest {
    id: Option<String>,
    name: Option<String>,
    url: Option<String>,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RefreshRemoteSessionsRequest {
    action: Option<String>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct GitUiNotification {
    level: String,
    title: String,
    message: String,
}

#[derive(Debug, Clone)]
struct GitNotificationEntry {
    timestamp_ms: u64,
    notification: GitUiNotification,
}

#[derive(Debug, Clone)]
struct PushSubscriptionEntry {
    id: String,
    endpoint: String,
    p256dh: String,
    auth: String,
    is_active: bool,
}

#[derive(Debug, Clone)]
struct WorktreeEntry {
    path: String,
    branch: String,
    #[allow(non_snake_case)]
    head: String,
    detached: bool,
    prunable: bool,
    locked: bool,
    locked_reason: Option<String>,
}

#[derive(Debug)]
struct HookInstallResult {
    success: bool,
    error: Option<String>,
}

#[derive(Debug)]
struct HookUninstallResult {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct BranchEntry {
    name: String,
    current: bool,
    remote: bool,
    worktree_path: Option<String>,
}

#[derive(Debug, Clone)]
struct DiscoveredRepository {
    id: String,
    path: String,
    folder_name: String,
    last_modified: String,
    relative_path: String,
    git_branch: Option<String>,
}

#[derive(Debug, Clone)]
struct UploadedFileEntry {
    filename: String,
    size: u64,
    created_at: String,
    modified_at: String,
    extension: String,
    absolute_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct MultiplexerSession {
    name: String,
    #[serde(rename = "type")]
    session_type: String,
    current: bool,
    attached: bool,
    windows: usize,
    activity: String,
    exited: bool,
}

#[derive(Debug, Clone)]
struct MultiplexerState {
    tmux: Vec<MultiplexerSession>,
    zellij: Vec<MultiplexerSession>,
    screen: Vec<MultiplexerSession>,
    kitty: Vec<MultiplexerSession>,
}

#[derive(Debug, Clone)]
struct MultiplexerAvailabilityCache {
    values: HashMap<String, bool>,
    expires_at: Instant,
}

#[derive(Debug, Clone, Serialize)]
struct RemoteServerEntry {
    id: String,
    name: String,
    url: String,
    token: String,
    #[serde(rename = "registeredAt")]
    registered_at: String,
    #[serde(rename = "lastHeartbeat")]
    last_heartbeat: String,
    #[serde(rename = "sessionIds")]
    session_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PushStatusResponse {
    enabled: bool,
    configured: bool,
    #[serde(rename = "hasVapidKeys")]
    has_vapid_keys: bool,
    #[serde(rename = "totalSubscriptions")]
    total_subscriptions: usize,
    #[serde(rename = "activeSubscriptions")]
    active_subscriptions: usize,
    subscriptions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct AuthVerifyResponse {
    valid: bool,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Clone)]
struct AuthContext {
    user_id: Option<String>,
    auth_method: Option<&'static str>,
    is_hq_request: bool,
}

#[derive(RustEmbed)]
#[folder = "../public"]
struct EmbeddedAssets;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        return handle_command(command);
    }

    let config = Arc::new(build_server_config(cli));
    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .with_context(|| format!("Invalid bind/port combination: {}:{}", config.bind, config.port))?;

    let state = AppState {
        config,
        sessions: Arc::new(Mutex::new(Vec::new())),
        session_outputs: Arc::new(Mutex::new(HashMap::new())),
        session_subscriptions: Arc::new(Mutex::new(HashMap::new())),
        ws_clients: Arc::new(Mutex::new(HashMap::new())),
        session_dimensions: Arc::new(Mutex::new(HashMap::new())),
        git_watchers: Arc::new(Mutex::new(HashMap::new())),
        local_processes: Arc::new(Mutex::new(HashMap::new())),
        started_at: Instant::now(),
        tailscale_server_url: Arc::new(Mutex::new(None)),
        app_config: Arc::new(Mutex::new(load_app_config())),
        auth_challenges: Arc::new(Mutex::new(HashMap::new())),
        push_subscriptions: Arc::new(Mutex::new(Vec::new())),
        uploaded_files: Arc::new(Mutex::new(Vec::new())),
        multiplexer_state: Arc::new(Mutex::new(MultiplexerState {
            tmux: Vec::new(),
            zellij: Vec::new(),
            screen: Vec::new(),
            kitty: Vec::new(),
        })),
        multiplexer_available_cache: Arc::new(Mutex::new(MultiplexerAvailabilityCache {
            values: HashMap::new(),
            expires_at: Instant::now(),
        })),
        remote_registry: Arc::new(Mutex::new(Vec::new())),
        git_notifications: Arc::new(Mutex::new(Vec::new())),
        git_repo_locks: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind {addr}"))?;

    eprintln!("VibeTunnel Server running on http://{addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
        .await
        .context("HTTP server exited with error")?;

    Ok(())
}

fn build_server_config(cli: Cli) -> ServerConfig {
    let port = cli.port.unwrap_or_else(default_port);
    let bind = cli.bind.unwrap_or_else(default_bind);
    let no_auth = cli.no_auth;
    let enable_ssh_keys = cli.enable_ssh_keys || cli.disallow_user_password;
    let disallow_user_password = cli.disallow_user_password;
    let enable_mdns = !cli.no_mdns;
    let push_enabled = if cli.push_disabled { false } else { cli.push_enabled };

    ServerConfig {
        port,
        bind,
        no_auth,
        enable_ssh_keys,
        disallow_user_password,
        is_hq_mode: cli.is_hq_mode,
        hq_url: cli.hq_url,
        hq_username: cli.hq_username,
        hq_password: cli.hq_password,
        remote_name: cli.remote_name,
        allow_insecure_hq: cli.allow_insecure_hq,
        push_enabled,
        vapid_email: cli.vapid_email,
        generate_vapid_keys: cli.generate_vapid_keys,
        allow_local_bypass: cli.allow_local_bypass,
        local_auth_token: cli.local_auth_token,
        enable_tailscale_serve: cli.enable_tailscale_serve,
        enable_tailscale_funnel: cli.enable_tailscale_funnel,
        no_hq_auth: cli.no_hq_auth,
        enable_mdns,
        enable_ngrok: cli.enable_ngrok,
        ngrok_auth_token: cli.ngrok_auth_token,
        ngrok_domain: cli.ngrok_domain,
        ngrok_region: cli.ngrok_region,
        enable_cloudflare: cli.enable_cloudflare,
        version: env!("CARGO_PKG_VERSION"),
    }
}

fn handle_command(command: Command) -> Result<()> {
    match command {
        Command::Status => {
            println!("VibeTunnel status (rust scaffold): running=unknown");
        }
        Command::Follow { branch } => {
            if let Some(branch) = branch {
                println!("Follow command acknowledged (rust scaffold): branch={branch}");
            } else {
                println!("Follow command acknowledged (rust scaffold)");
            }
        }
        Command::Unfollow => {
            println!("Unfollow command acknowledged (rust scaffold)");
        }
        Command::GitEvent => {
            println!("Git event acknowledged (rust scaffold)");
        }
        Command::Version => {
            println!("VibeTunnel Server v{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

fn default_port() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(4020)
}

fn default_bind() -> String {
    std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let total_seconds = now.as_secs() as i64;
    let millis = now.subsec_millis();

    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);

    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u32;
    if month <= 2 {
        year += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn log_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".vibetunnel").join("log.txt"))
}

fn config_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".vibetunnel").join("config.json"))
}

fn parse_quick_start_commands(value: &serde_json::Value) -> Option<Vec<QuickStartCommand>> {
    let serde_json::Value::Array(items) = value else {
        return None;
    };

    let mut out = Vec::new();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };

        let command = object
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let Some(command) = command else {
            continue;
        };

        let name = object
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        out.push(QuickStartCommand { name, command });
    }

    Some(out)
}

fn parse_repository_base_path(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn parse_notification_preferences_patch(
    value: &serde_json::Value,
) -> Option<NotificationPreferencesPatch> {
    serde_json::from_value(value.clone()).ok()
}

fn apply_notification_preferences_patch(
    current: &NotificationPreferences,
    patch: NotificationPreferencesPatch,
) -> NotificationPreferences {
    NotificationPreferences {
        enabled: patch.enabled.unwrap_or(current.enabled),
        session_start: patch.session_start.unwrap_or(current.session_start),
        session_exit: patch.session_exit.unwrap_or(current.session_exit),
        command_completion: patch.command_completion.unwrap_or(current.command_completion),
        command_error: patch.command_error.unwrap_or(current.command_error),
        bell: patch.bell.unwrap_or(current.bell),
        sound_enabled: patch.sound_enabled.unwrap_or(current.sound_enabled),
        vibration_enabled: patch.vibration_enabled.unwrap_or(current.vibration_enabled),
    }
}

fn load_app_config() -> AppConfig {
    let mut defaults = AppConfig::default();

    let Some(path) = config_file_path() else {
        return defaults;
    };

    let Ok(raw) = fs::read_to_string(path) else {
        return defaults;
    };

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return defaults;
    };

    defaults.repository_base_path = parsed
        .get("repositoryBasePath")
        .and_then(parse_repository_base_path)
        .unwrap_or_else(|| "~/Documents".to_string());

    defaults.quick_start_commands = parsed
        .get("quickStartCommands")
        .and_then(parse_quick_start_commands)
        .unwrap_or_default();

    defaults.notification_preferences = Some(
        parsed
            .get("preferences")
            .and_then(|p| p.get("notifications"))
            .and_then(|n| serde_json::from_value::<NotificationPreferences>(n.clone()).ok())
            .unwrap_or_else(default_notification_preferences),
    );

    defaults
}

fn save_app_config(app_config: &AppConfig) -> Result<()> {
    let Some(path) = config_file_path() else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory {}", parent.display()))?;
    }

    let existing_json = fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({ "version": 1 }));

    let mut object = existing_json.as_object().cloned().unwrap_or_default();
    object.insert(
        "repositoryBasePath".to_string(),
        serde_json::Value::String(app_config.repository_base_path.clone()),
    );
    object.insert(
        "quickStartCommands".to_string(),
        serde_json::to_value(&app_config.quick_start_commands).unwrap_or(serde_json::json!([])),
    );

    if let Some(preferences) = &app_config.notification_preferences {
        let mut preferences_object = object
            .get("preferences")
            .and_then(|value| value.as_object())
            .cloned()
            .unwrap_or_default();
        preferences_object.insert(
            "notifications".to_string(),
            serde_json::to_value(preferences).unwrap_or(serde_json::json!({})),
        );
        object.insert(
            "preferences".to_string(),
            serde_json::Value::Object(preferences_object),
        );
    }

    if !object.contains_key("version") {
        object.insert("version".to_string(), serde_json::json!(1));
    }

    let output = serde_json::to_string_pretty(&serde_json::Value::Object(object))
        .context("Failed to serialize app config")?;
    fs::write(&path, output).with_context(|| format!("Failed to write config file {}", path.display()))?;

    Ok(())
}

fn current_system_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn validate_avatar_user_id(user_id: &str) -> bool {
    if user_id.is_empty() || user_id.len() > 255 {
        return false;
    }
    user_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn is_allowed_log_level(level: &str) -> bool {
    matches!(level, "log" | "info" | "warn" | "error" | "debug")
}

fn is_existing_system_user(user_id: &str) -> bool {
    if user_id.trim().is_empty() {
        return false;
    }

    let status = ProcessCommand::new("id")
        .arg(user_id)
        .status();

    status.map(|s| s.success()).unwrap_or(false)
}

fn read_authorized_keys(user_id: &str) -> Option<String> {
    let home_dir = if let Ok(current_user) = std::env::var("USER") {
        if current_user == user_id {
            std::env::var("HOME").ok()
        } else {
            Some(format!("/home/{user_id}"))
        }
    } else {
        Some(format!("/home/{user_id}"))
    }?;

    let path = PathBuf::from(home_dir).join(".ssh").join("authorized_keys");
    fs::read_to_string(path).ok()
}

fn is_authorized_ssh_key_for_user(user_id: &str, public_key: &str) -> bool {
    let key_data = public_key
        .trim()
        .split_whitespace()
        .nth(1)
        .unwrap_or(public_key)
        .trim();

    if key_data.is_empty() {
        return false;
    }

    read_authorized_keys(user_id)
        .map(|content| content.contains(key_data))
        .unwrap_or(false)
}

fn create_auth_token_for_user(user_id: &str) -> String {
    format!("{}.{}", user_id, uuid_like())
}

fn password_matches_configured_credentials(user_id: &str, password: &str) -> bool {
    let env_username = std::env::var("VIBETUNNEL_USERNAME").ok();
    let env_password = std::env::var("VIBETUNNEL_PASSWORD").ok();

    match (env_username, env_password) {
        (Some(expected_user), Some(expected_password)) => {
            user_id == expected_user && password == expected_password
        }
        _ => false,
    }
}

fn is_valid_log_entry(payload: &serde_json::Value) -> bool {
    let level = payload.get("level").and_then(|v| v.as_str());
    let module = payload.get("module").and_then(|v| v.as_str());
    let args = payload.get("args").and_then(|v| v.as_array());

    matches!(level, Some(v) if is_allowed_log_level(v))
        && matches!(module, Some(v) if !v.trim().is_empty())
        && args.is_some()
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 Bytes".to_string();
    }

    let k = 1024_f64;
    let sizes = ["Bytes", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut idx = 0usize;

    while size >= k && idx < sizes.len() - 1 {
        size /= k;
        idx += 1;
    }

    if idx == 0 {
        format!("{} {}", bytes, sizes[idx])
    } else {
        format!("{:.2} {}", size, sizes[idx])
    }
}

fn default_notification_preferences() -> NotificationPreferences {
    NotificationPreferences::default()
}

fn default_repository_base_path() -> String {
    std::env::var("HOME")
        .map(|home| format!("{home}/Code"))
        .unwrap_or_else(|_| "~/Code".to_string())
}

fn unix_to_iso(seconds: u64) -> String {
    format!("{seconds}.000Z")
}

#[derive(Debug, Clone)]
struct GitExecError {
    message: String,
    stderr: String,
    code: Option<i32>,
    not_found: bool,
}

fn resolve_absolute_path(path_input: &str) -> PathBuf {
    let trimmed = path_input.trim();
    let expanded = if trimmed == "~" {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(trimmed))
    } else if let Some(stripped) = trimmed.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(stripped)
        } else {
            PathBuf::from(trimmed)
        }
    } else {
        PathBuf::from(trimmed)
    };

    if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(expanded)
    }
}

fn run_git(cwd: &Path, args: Vec<String>) -> Result<(String, String), GitExecError> {
    let output = ProcessCommand::new("git")
        .args(&args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if output.status.success() {
                Ok((stdout, stderr))
            } else {
                Err(GitExecError {
                    message: format!("Git command failed: git {}", args.join(" ")),
                    stderr,
                    code: output.status.code(),
                    not_found: false,
                })
            }
        }
        Err(error) => Err(GitExecError {
            message: error.to_string(),
            stderr: String::new(),
            code: None,
            not_found: error.kind() == std::io::ErrorKind::NotFound,
        }),
    }
}

fn is_not_git_repository_error(error: &GitExecError) -> bool {
    error.not_found
        || error
            .stderr
            .contains("not a git repository (or any of the parent directories): .git")
        || error.stderr.contains("not a git repository")
        || error.message.contains("No such file or directory")
}

fn is_git_config_not_found_error(error: &GitExecError) -> bool {
    error.code == Some(5) || error.stderr.contains("key \"vibetunnel.followWorktree\" not found")
}

fn parse_worktree_porcelain(output: &str) -> Vec<WorktreeEntry> {
    let mut worktrees = Vec::new();
    let mut current: Option<WorktreeEntry> = None;

    for line in output.lines() {
        if line.trim().is_empty() {
            if let Some(entry) = current.take() {
                if !entry.path.is_empty() && !entry.head.is_empty() {
                    worktrees.push(entry);
                }
            }
            continue;
        }

        if let Some(path) = line.strip_prefix("worktree ") {
            if let Some(entry) = current.take() {
                if !entry.path.is_empty() && !entry.head.is_empty() {
                    worktrees.push(entry);
                }
            }
            current = Some(WorktreeEntry {
                path: path.to_string(),
                branch: "HEAD".to_string(),
                head: String::new(),
                detached: false,
                prunable: false,
                locked: false,
                locked_reason: None,
            });
            continue;
        }

        let Some(entry) = current.as_mut() else {
            continue;
        };

        if let Some(head) = line.strip_prefix("HEAD ") {
            entry.head = head.to_string();
        } else if let Some(branch) = line.strip_prefix("branch ") {
            entry.branch = branch.to_string();
        } else if line == "detached" {
            entry.detached = true;
        } else if line.starts_with("prunable") {
            entry.prunable = true;
        } else if let Some(locked_reason) = line.strip_prefix("locked") {
            entry.locked = true;
            let reason = locked_reason.trim();
            if !reason.is_empty() {
                entry.locked_reason = Some(reason.to_string());
            }
        }
    }

    if let Some(entry) = current.take() {
        if !entry.path.is_empty() && !entry.head.is_empty() {
            worktrees.push(entry);
        }
    }

    worktrees
}

fn get_hooks_directory(repo_path: &Path) -> PathBuf {
    if let Ok((stdout, _)) = run_git(
        repo_path,
        vec!["config".to_string(), "core.hooksPath".to_string()],
    ) {
        let custom_path = stdout.trim();
        if !custom_path.is_empty() {
            return if Path::new(custom_path).is_absolute() {
                PathBuf::from(custom_path)
            } else {
                repo_path.join(custom_path)
            };
        }
    }

    repo_path.join(".git").join("hooks")
}

fn hook_script_content(hook_type: &str) -> String {
    format!(
        "#!/bin/sh\n# VibeTunnel Git hook - {hook_type}\n# This hook notifies VibeTunnel when Git events occur\n\n# Check if vt command is available\nif command -v vt >/dev/null 2>&1; then\n  # Run in background to avoid blocking Git operations\n  vt git event &\nfi\n\n# Always exit successfully\nexit 0\n"
    )
}

fn hook_script_with_backup(hook_type: &str, backup_path: &Path) -> String {
    format!(
        "#!/bin/sh\n# VibeTunnel Git hook - {hook_type}\n# This hook notifies VibeTunnel when Git events occur\n\n# Check if vt command is available\nif command -v vt >/dev/null 2>&1; then\n  # Run in background to avoid blocking Git operations\n  vt git event &\nfi\n\n# Execute the original hook if it exists\nif [ -f \"{}\" ]; then\n  exec \"{}\" \"$@\"\nfi\n\nexit 0\n",
        backup_path.display(),
        backup_path.display()
    )
}

fn install_hook(repo_path: &Path, hook_type: &str) -> HookInstallResult {
    let hooks_dir = get_hooks_directory(repo_path);
    let hook_path = hooks_dir.join(hook_type);
    let backup_path = PathBuf::from(format!("{}.vtbak", hook_path.display()));

    if let Err(error) = fs::create_dir_all(&hooks_dir) {
        return HookInstallResult {
            success: false,
            error: Some(error.to_string()),
        };
    }

    let existing_hook = fs::read_to_string(&hook_path).ok();

    if existing_hook
        .as_ref()
        .is_some_and(|content| content.contains("VibeTunnel Git hook"))
    {
        return HookInstallResult {
            success: true,
            error: None,
        };
    }

    if let Some(content) = existing_hook.as_ref() {
        if let Err(error) = fs::write(&backup_path, content) {
            return HookInstallResult {
                success: false,
                error: Some(error.to_string()),
            };
        }
    }

    let script = if existing_hook.is_some() {
        hook_script_with_backup(hook_type, &backup_path)
    } else {
        hook_script_content(hook_type)
    };

    if let Err(error) = fs::write(&hook_path, script) {
        return HookInstallResult {
            success: false,
            error: Some(error.to_string()),
        };
    }

    if let Err(error) = fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)) {
        return HookInstallResult {
            success: false,
            error: Some(error.to_string()),
        };
    }

    HookInstallResult {
        success: true,
        error: None,
    }
}

fn uninstall_hook(repo_path: &Path, hook_type: &str) -> HookUninstallResult {
    let hooks_dir = get_hooks_directory(repo_path);
    let hook_path = hooks_dir.join(hook_type);
    let backup_path = PathBuf::from(format!("{}.vtbak", hook_path.display()));

    let existing_hook = match fs::read_to_string(&hook_path) {
        Ok(content) => content,
        Err(_) => {
            return HookUninstallResult {
                success: true,
                error: None,
            }
        }
    };

    if !existing_hook.contains("VibeTunnel Git hook") {
        return HookUninstallResult {
            success: true,
            error: None,
        };
    }

    if backup_path.exists() {
        let backup_content = match fs::read_to_string(&backup_path) {
            Ok(content) => content,
            Err(error) => {
                return HookUninstallResult {
                    success: false,
                    error: Some(error.to_string()),
                }
            }
        };

        if let Err(error) = fs::write(&hook_path, backup_content) {
            return HookUninstallResult {
                success: false,
                error: Some(error.to_string()),
            };
        }

        if let Err(error) = fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)) {
            return HookUninstallResult {
                success: false,
                error: Some(error.to_string()),
            };
        }

        if let Err(error) = fs::remove_file(&backup_path) {
            return HookUninstallResult {
                success: false,
                error: Some(error.to_string()),
            };
        }

        return HookUninstallResult {
            success: true,
            error: None,
        };
    }

    if let Err(error) = fs::remove_file(&hook_path) {
        return HookUninstallResult {
            success: false,
            error: Some(error.to_string()),
        };
    }

    HookUninstallResult {
        success: true,
        error: None,
    }
}

fn are_hooks_installed(repo_path: &Path) -> bool {
    let hooks_dir = get_hooks_directory(repo_path);
    ["post-commit", "post-checkout"].iter().all(|hook_type| {
        let hook_path = hooks_dir.join(hook_type);
        fs::read_to_string(&hook_path)
            .map(|content| content.contains("VibeTunnel Git hook"))
            .unwrap_or(false)
    })
}

fn install_git_hooks(repo_path: &Path) -> Result<(), Vec<String>> {
    let results = [
        install_hook(repo_path, "post-commit"),
        install_hook(repo_path, "post-checkout"),
    ];

    let errors: Vec<String> = results
        .into_iter()
        .filter_map(|result| if result.success { None } else { result.error })
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn uninstall_git_hooks(repo_path: &Path) -> Result<(), Vec<String>> {
    let results = [
        uninstall_hook(repo_path, "post-commit"),
        uninstall_hook(repo_path, "post-checkout"),
    ];

    let errors: Vec<String> = results
        .into_iter()
        .filter_map(|result| if result.success { None } else { result.error })
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn detect_default_branch(repo_path: &Path) -> String {
    if let Ok((stdout, _)) = run_git(
        repo_path,
        vec![
            "symbolic-ref".to_string(),
            "refs/remotes/origin/HEAD".to_string(),
        ],
    ) {
        if let Some(branch) = stdout
            .trim()
            .strip_prefix("refs/remotes/origin/")
            .filter(|b| !b.is_empty())
        {
            return branch.to_string();
        }
    }

    if run_git(
        repo_path,
        vec![
            "rev-parse".to_string(),
            "--verify".to_string(),
            "main".to_string(),
        ],
    )
    .is_ok()
    {
        "main".to_string()
    } else {
        "master".to_string()
    }
}

fn parse_diff_shortstat(diff_stat: &str) -> (u64, u64, u64) {
    let mut files_changed = 0_u64;
    let mut insertions = 0_u64;
    let mut deletions = 0_u64;

    for token in diff_stat.split(',') {
        let part = token.trim();
        let count = part
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);

        if part.contains("file changed") || part.contains("files changed") {
            files_changed = count;
        } else if part.contains("insertion") {
            insertions = count;
        } else if part.contains("deletion") {
            deletions = count;
        }
    }

    (files_changed, insertions, deletions)
}

fn get_branch_stats(worktree_path: &Path, branch: &str, base_branch: &str) -> (u64, u64, u64, u64) {
    let mut commits_ahead = 0_u64;
    let mut files_changed = 0_u64;
    let mut insertions = 0_u64;
    let mut deletions = 0_u64;

    if let Ok((stdout, _)) = run_git(
        worktree_path,
        vec![
            "rev-list".to_string(),
            "--count".to_string(),
            format!("{base_branch}...{branch}"),
        ],
    ) {
        commits_ahead = stdout.trim().parse::<u64>().unwrap_or(0);
    }

    if let Ok((stdout, _)) = run_git(
        worktree_path,
        vec![
            "diff".to_string(),
            "--shortstat".to_string(),
            format!("{base_branch}...{branch}"),
        ],
    ) {
        let (files, ins, del) = parse_diff_shortstat(stdout.trim());
        files_changed = files;
        insertions = ins;
        deletions = del;
    }

    (commits_ahead, files_changed, insertions, deletions)
}

fn has_uncommitted_changes(worktree_path: &Path) -> bool {
    run_git(
        worktree_path,
        vec!["status".to_string(), "--porcelain".to_string()],
    )
    .map(|(stdout, _)| !stdout.trim().is_empty())
    .unwrap_or(false)
}

fn parse_worktree_branch_map(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut current_path: Option<String> = None;

    for line in output.lines() {
        if line.trim().is_empty() {
            current_path = None;
            continue;
        }

        if let Some(path) = line.strip_prefix("worktree ") {
            current_path = Some(path.to_string());
            continue;
        }

        if let Some(branch) = line.strip_prefix("branch ") {
            if let Some(path) = current_path.as_ref() {
                map.insert(
                    branch.trim_start_matches("refs/heads/").to_string(),
                    path.clone(),
                );
            }
        }
    }

    map
}

fn list_branches(repo_path: &Path) -> Result<Vec<BranchEntry>, GitExecError> {
    let current_branch = run_git(
        repo_path,
        vec!["branch".to_string(), "--show-current".to_string()],
    )
    .map(|(stdout, _)| stdout.trim().to_string())
    .unwrap_or_default();

    let (local_stdout, _) = run_git(repo_path, vec!["branch".to_string()])?;
    let mut branches: Vec<BranchEntry> = local_stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let is_current = line.starts_with('*');
            let name = line.trim_start_matches('*').trim().to_string();
            BranchEntry {
                current: is_current || name == current_branch,
                name,
                remote: false,
                worktree_path: None,
            }
        })
        .collect();

    if let Ok((remote_stdout, _)) = run_git(repo_path, vec!["branch".to_string(), "-r".to_string()]) {
        branches.extend(
            remote_stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.contains("->"))
                .map(|line| BranchEntry {
                    name: line.to_string(),
                    current: false,
                    remote: true,
                    worktree_path: None,
                }),
        );
    }

    if let Ok((worktree_stdout, _)) = run_git(
        repo_path,
        vec!["worktree".to_string(), "list".to_string(), "--porcelain".to_string()],
    ) {
        let worktree_map = parse_worktree_branch_map(&worktree_stdout);
        for branch in &mut branches {
            if let Some(path) = worktree_map
                .get(&branch.name)
                .cloned()
                .or_else(|| branch.name.strip_prefix("origin/").and_then(|n| worktree_map.get(n).cloned()))
            {
                branch.worktree_path = Some(path);
            }
        }
    }

    branches.sort_by(|a, b| {
        if a.current != b.current {
            return b.current.cmp(&a.current);
        }
        if a.remote != b.remote {
            return a.remote.cmp(&b.remote);
        }
        a.name.cmp(&b.name)
    });

    Ok(branches)
}

fn discover_repositories(base_path: &Path, max_depth: usize) -> Vec<DiscoveredRepository> {
    fn scan(dir: &Path, depth: usize, max_depth: usize, repos: &mut Vec<DiscoveredRepository>) {
        if depth > max_depth {
            return;
        }

        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        if depth == 0 {
            let git_path = dir.join(".git");
            if git_path.exists() {
                if let Some(repo) = create_discovered_repository(dir) {
                    repos.push(repo);
                }
                return;
            }
        }

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if !path.is_dir() {
                continue;
            }

            if file_name.starts_with('.') && file_name != ".git" {
                continue;
            }

            let git_path = path.join(".git");
            if git_path.exists() {
                if let Some(repo) = create_discovered_repository(&path) {
                    repos.push(repo);
                }
                continue;
            }

            scan(&path, depth + 1, max_depth, repos);
        }
    }

    let mut repositories = Vec::new();
    scan(base_path, 0, max_depth, &mut repositories);
    repositories.sort_by(|a, b| a.folder_name.cmp(&b.folder_name));
    repositories
}

fn create_discovered_repository(repo_path: &Path) -> Option<DiscoveredRepository> {
    let folder_name = repo_path.file_name()?.to_string_lossy().to_string();
    let metadata = fs::metadata(repo_path).ok()?;
    let modified_seconds = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    let home_dir = std::env::var("HOME").unwrap_or_default();
    let repo_path_string = repo_path.to_string_lossy().to_string();
    let relative_path = if !home_dir.is_empty() && repo_path_string.starts_with(&home_dir) {
        format!("~{}", &repo_path_string[home_dir.len()..])
    } else {
        repo_path_string.clone()
    };

    let git_branch = run_git(
        repo_path,
        vec!["branch".to_string(), "--show-current".to_string()],
    )
    .ok()
    .map(|(stdout, _)| stdout.trim().to_string())
    .filter(|branch| !branch.is_empty());

    Some(DiscoveredRepository {
        id: format!("{}-{}", folder_name, modified_seconds),
        path: repo_path_string,
        folder_name,
        last_modified: unix_to_iso(modified_seconds),
        relative_path,
        git_branch,
    })
}

fn get_git_status_for_directory(full_path: &Path) -> Option<serde_json::Value> {
    let (repo_root_stdout, _) = run_git(
        full_path,
        vec![
            "rev-parse".to_string(),
            "--show-toplevel".to_string(),
        ],
    )
    .ok()?;
    let git_repo_root = repo_root_stdout.trim().to_string();

    let branch = run_git(
        full_path,
        vec!["branch".to_string(), "--show-current".to_string()],
    )
    .ok()
    .map(|(stdout, _)| stdout.trim().to_string())
    .unwrap_or_default();

    let (status_stdout, _) = run_git(
        Path::new(&git_repo_root),
        vec!["status".to_string(), "--porcelain".to_string()],
    )
    .ok()?;

    let mut modified = Vec::<String>::new();
    let mut added = Vec::<String>::new();
    let mut deleted = Vec::<String>::new();
    let mut untracked = Vec::<String>::new();

    for line in status_stdout.lines() {
        if line.len() < 4 {
            continue;
        }

        let status_code = &line[..2];
        let filename = line[3..].to_string();

        match status_code {
            " M" | "M " | "MM" => modified.push(filename),
            "A " | "AM" => added.push(filename),
            " D" | "D " => deleted.push(filename),
            "??" => untracked.push(filename),
            _ => {}
        }
    }

    let (ahead, behind) = run_git(
        Path::new(&git_repo_root),
        vec![
            "rev-list".to_string(),
            "--left-right".to_string(),
            "--count".to_string(),
            "HEAD...@{upstream}".to_string(),
        ],
    )
    .ok()
    .and_then(|(stdout, _)| {
        let mut parts = stdout.split_whitespace();
        let ahead = parts.next()?.parse::<u32>().ok()?;
        let behind = parts.next()?.parse::<u32>().ok()?;
        Some((ahead, behind))
    })
    .unwrap_or((0, 0));

    Some(serde_json::json!({
        "isGitRepo": true,
        "branch": branch,
        "modified": modified,
        "added": added,
        "deleted": deleted,
        "untracked": untracked,
        "ahead": ahead,
        "behind": behind,
    }))
}

fn git_status_counts_for_directory(full_path: &Path) -> Option<(u32, u32, u32, u32, u32)> {
    let status = get_git_status_for_directory(full_path)?;
    let git_modified_count = status
        .get("modified")
        .and_then(|v| v.as_array())
        .map(|v| v.len() as u32)
        .unwrap_or(0);
    let git_added_count = status
        .get("added")
        .and_then(|v| v.as_array())
        .map(|v| v.len() as u32)
        .unwrap_or(0);
    let git_deleted_count = status
        .get("deleted")
        .and_then(|v| v.as_array())
        .map(|v| v.len() as u32)
        .unwrap_or(0);
    let git_ahead_count = status
        .get("ahead")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);
    let git_behind_count = status
        .get("behind")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    Some((
        git_modified_count,
        git_added_count,
        git_deleted_count,
        git_ahead_count,
        git_behind_count,
    ))
}

fn get_file_git_status(
    absolute_path: &Path,
    git_status: Option<&serde_json::Value>,
    git_repo_path: &Path,
) -> serde_json::Value {
    let Some(status) = git_status else {
        return serde_json::Value::Null;
    };

    let relative_path = absolute_path
        .strip_prefix(git_repo_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| absolute_path.to_string_lossy().to_string());

    let contains = |key: &str| -> bool {
        status
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|entry| entry.as_str() == Some(relative_path.as_str())))
            .unwrap_or(false)
    };

    if contains("modified") {
        serde_json::json!("modified")
    } else if contains("added") {
        serde_json::json!("added")
    } else if contains("deleted") {
        serde_json::json!("deleted")
    } else if contains("untracked") {
        serde_json::json!("untracked")
    } else {
        serde_json::json!("unchanged")
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

fn uploads_directory() -> PathBuf {
    if let Ok(control_dir) = std::env::var("VIBETUNNEL_CONTROL_DIR") {
        PathBuf::from(control_dir).join("uploads")
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".vibetunnel")
            .join("control")
            .join("uploads")
    }
}

fn sanitize_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 || name.starts_with('.') {
        return false;
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn detect_mime_from_path(file_path: &Path) -> &'static str {
    match file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "json" => "application/json",
        "js" => "application/javascript",
        "ts" => "application/typescript",
        "xml" => "application/xml",
        "wasm" => "application/wasm",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "md" => "text/markdown",
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn parse_github_url(remote_url: &str) -> Option<String> {
    if remote_url.starts_with("https://github.com/") {
        return Some(remote_url.trim_end_matches(".git").to_string());
    }

    if let Some(path_part) = remote_url.strip_prefix("git@github.com:") {
        let clean_path = path_part.trim_end_matches(".git");
        return Some(format!("https://github.com/{clean_path}"));
    }

    None
}

fn parse_git_status_porcelain_counts(status_output: &str) -> (u64, u64, u64, u64, u64, bool) {
    let lines: Vec<&str> = status_output
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect();

    let mut modified_count = 0_u64;
    let mut untracked_count = 0_u64;
    let mut staged_count = 0_u64;
    let mut added_count = 0_u64;
    let mut deleted_count = 0_u64;

    for line in &lines {
        let chars: Vec<char> = line.chars().collect();
        if chars.len() < 2 {
            continue;
        }

        let index_status = chars[0];
        let worktree_status = chars[1];

        if index_status != ' ' && index_status != '?' {
            staged_count += 1;
            if index_status == 'A' {
                added_count += 1;
            } else if index_status == 'D' {
                deleted_count += 1;
            }
        }

        if worktree_status == 'M' {
            modified_count += 1;
        } else if worktree_status == 'D' && index_status == ' ' {
            deleted_count += 1;
        }

        if index_status == '?' && worktree_status == '?' {
            untracked_count += 1;
        }
    }

    (
        modified_count,
        untracked_count,
        staged_count,
        added_count,
        deleted_count,
        !lines.is_empty(),
    )
}

fn parse_ahead_behind_counts(output: &str) -> (u64, u64) {
    let mut parts = output.trim().split_whitespace();
    let ahead = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    let behind = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    (ahead, behind)
}

fn extract_main_repo_from_git_dir(git_dir: &str, fallback: &Path) -> PathBuf {
    for marker in ["/.git/worktrees/", ".git/worktrees/"] {
        if let Some(idx) = git_dir.find(marker) {
            let prefix = git_dir[..idx].trim_end_matches('/');
            if !prefix.is_empty() {
                return PathBuf::from(prefix);
            }
        }
    }
    fallback.to_path_buf()
}

fn is_git_event_label(label: &str) -> bool {
    matches!(
        label,
        "checkout"
            | "branch"
            | "merge"
            | "rebase"
            | "commit"
            | "push"
            | "pull"
            | "fetch"
            | "stash"
            | "reset"
            | "cherry-pick"
    )
}

fn strip_git_event_suffix(name: &str) -> String {
    if let Some(start) = name.rfind(" [") {
        if name.ends_with(']') {
            let inner = &name[start + 2..name.len() - 1];
            if let Some((event, _branch)) = inner.split_once(": ") {
                if is_git_event_label(event) {
                    return name[..start].trim_end().to_string();
                }
            }
        }
    }
    name.to_string()
}

fn trim_old_git_notifications(entries: &mut Vec<GitNotificationEntry>) {
    let cutoff_ms = now_unix_ms().saturating_sub(5 * 60 * 1000);
    entries.retain(|entry| entry.timestamp_ms >= cutoff_ms);
}

fn multiplexer_available(command: &str) -> bool {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let candidate = dir.join(command);
                if candidate.is_file() {
                    Some(candidate)
                } else {
                    None
                }
            })
        })
        .is_some()
}

fn strip_ansi_codes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if matches!(chars.peek(), Some('[')) {
                let _ = chars.next();
                while let Some(code_ch) = chars.next() {
                    if code_ch.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(ch);
    }

    out
}

fn is_screen_full_session_name(name: &str) -> bool {
    let Some((pid, rest)) = name.split_once('.') else {
        return false;
    };
    !rest.is_empty() && pid.chars().all(|ch| ch.is_ascii_digit())
}

fn list_zellij_sessions() -> Vec<MultiplexerSession> {
    let output = match ProcessCommand::new("zellij").arg("list-sessions").output() {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.contains("No active zellij sessions found") {
        return Vec::new();
    }

    stdout
        .lines()
        .filter_map(|raw_line| {
            let clean_line = strip_ansi_codes(raw_line).trim().to_string();
            if clean_line.is_empty() {
                return None;
            }

            let name = clean_line.split('[').next().unwrap_or_default().trim().to_string();
            if name.is_empty() {
                return None;
            }

            let exited = clean_line.contains("[EXITED]");
            let activity = if let Some(start) = clean_line.find("[Created ") {
                let created_start = start + "[Created ".len();
                if let Some(end_rel) = clean_line[created_start..].find(']') {
                    clean_line[created_start..created_start + end_rel].to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            Some(MultiplexerSession {
                name,
                session_type: "zellij".to_string(),
                current: false,
                attached: false,
                windows: 1,
                activity,
                exited,
            })
        })
        .collect()
}

fn list_screen_sessions() -> Vec<MultiplexerSession> {
    let output = match ProcessCommand::new("screen").arg("-ls").output() {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.contains("No Sockets found") {
        return Vec::new();
    }

    stdout
        .lines()
        .filter_map(|raw_line| {
            let line = raw_line.trim();
            if line.is_empty() {
                return None;
            }

            let open_idx = line.rfind('(')?;
            let close_idx = line.rfind(')')?;
            if close_idx <= open_idx {
                return None;
            }

            let session_name = line[..open_idx].trim();
            if !is_screen_full_session_name(session_name) {
                return None;
            }

            let status = line[open_idx + 1..close_idx].trim().to_ascii_lowercase();
            let attached = status.starts_with("attached");
            let exited = status.contains("dead");

            Some(MultiplexerSession {
                name: session_name.to_string(),
                session_type: "screen".to_string(),
                current: false,
                attached,
                windows: 1,
                activity: String::new(),
                exited,
            })
        })
        .collect()
}

fn resolve_screen_session_name(session_name: &str) -> Option<String> {
    if is_screen_full_session_name(session_name) {
        return Some(session_name.to_string());
    }

    for session in list_screen_sessions() {
        if let Some((_, simple_name)) = session.name.split_once('.') {
            if simple_name == session_name {
                return Some(session.name);
            }
        }
    }

    None
}

fn kitty_window_id_from_name(session_name: &str) -> Option<String> {
    if let Some(id) = session_name.strip_prefix("id:") {
        if !id.is_empty() && id.chars().all(|ch| ch.is_ascii_digit()) {
            return Some(id.to_string());
        }
    }

    None
}

fn list_kitty_sessions() -> Vec<MultiplexerSession> {
    let output = match ProcessCommand::new("kitty").args(["@", "ls"]).output() {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    let mut sessions = Vec::new();
    let Some(os_windows) = parsed.as_array() else {
        return sessions;
    };

    for os_window in os_windows {
        let tabs = os_window
            .get("tabs")
            .and_then(|tabs| tabs.as_array())
            .cloned()
            .unwrap_or_default();

        for tab in tabs {
            let windows = tab
                .get("windows")
                .and_then(|windows| windows.as_array())
                .cloned()
                .unwrap_or_default();

            for window in windows {
                let Some(id) = window.get("id").and_then(|value| value.as_i64()) else {
                    continue;
                };
                let title = window
                    .get("title")
                    .and_then(|value| value.as_str())
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("window-{id}"));

                sessions.push(MultiplexerSession {
                    name: format!("id:{id}"),
                    session_type: "kitty".to_string(),
                    current: false,
                    attached: true,
                    windows: 1,
                    activity: title,
                    exited: false,
                });
            }
        }
    }

    sessions
}

fn build_multiplexer_status(
    state: &MultiplexerState,
    availability: &HashMap<String, bool>,
) -> serde_json::Value {
    let tmux_available = availability.get("tmux").copied().unwrap_or(false);
    let zellij_available = availability.get("zellij").copied().unwrap_or(false);
    let screen_available = availability.get("screen").copied().unwrap_or(false);
    let kitty_available = availability.get("kitty").copied().unwrap_or(false);

    let tmux_sessions = if tmux_available { state.tmux.clone() } else { Vec::new() };
    let zellij_sessions = if zellij_available {
        list_zellij_sessions()
    } else {
        Vec::new()
    };

    let screen_sessions = if screen_available {
        list_screen_sessions()
    } else {
        Vec::new()
    };

    let kitty_sessions = if kitty_available {
        list_kitty_sessions()
    } else {
        Vec::new()
    };

    serde_json::json!({
        "tmux": {
            "available": tmux_available,
            "type": "tmux",
            "sessions": tmux_sessions,
        },
        "zellij": {
            "available": zellij_available,
            "type": "zellij",
            "sessions": zellij_sessions,
        },
        "screen": {
            "available": screen_available,
            "type": "screen",
            "sessions": screen_sessions,
        },
        "kitty": {
            "available": kitty_available,
            "type": "kitty",
            "sessions": kitty_sessions,
        }
    })
}

fn build_app(state: AppState) -> Router {
    let _features_enabled = use_remaining_config(&state.config);

    let api = Router::new()
        .route("/health", get(api_health))
        .route("/server/status", get(api_server_status))
        .route("/config", get(api_get_config).put(api_put_config))
        .route("/auth/challenge", post(api_auth_challenge))
        .route("/auth/password", post(api_auth_password))
        .route("/auth/ssh-key", post(api_auth_ssh_key))
        .route("/auth/config", get(api_auth_config))
        .route("/auth/verify", get(api_auth_verify))
        .route("/auth/current-user", get(api_auth_current_user))
        .route("/auth/avatar/{user_id}", get(api_auth_avatar))
        .route("/auth/logout", post(api_auth_logout))
        .route("/auth/tailscale-token", post(api_auth_tailscale_token))
        .route("/logs/client", post(api_logs_client))
        .route("/logs/raw", get(api_logs_raw))
        .route("/logs/info", get(api_logs_info))
        .route("/logs/clear", axum::routing::delete(api_logs_clear))
        .route("/logs/flush", post(api_logs_flush))
        .route("/push/vapid-public-key", get(api_push_vapid_public_key))
        .route("/push/status", get(api_push_status))
        .route("/push/subscribe", post(api_push_subscribe))
        .route("/push/unsubscribe", post(api_push_unsubscribe))
        .route("/push/test", post(api_push_test))
        .route("/git/repo-info", get(api_git_repo_info))
        .route("/git/status", get(api_git_status))
        .route("/git/event", post(api_git_event))
        .route("/git/notifications", get(api_git_notifications))
        .route("/git/remote", get(api_git_remote))
        .route("/git/repository-info", get(api_git_repository_info))
        .route("/worktrees", get(api_worktrees).post(api_create_worktree))
        .route("/worktrees/prune", post(api_prune_worktrees))
        .route("/worktrees/follow", post(api_follow_worktrees))
        .route("/worktrees/{branch}", axum::routing::delete(api_delete_worktree))
        .route("/remotes", get(api_remotes_list))
        .route("/remotes/register", post(api_remotes_register))
        .route("/remotes/{remote_id}", axum::routing::delete(api_remotes_delete))
        .route(
            "/remotes/{remote_name}/refresh-sessions",
            post(api_remotes_refresh_sessions),
        )
        .route("/repositories/branches", get(api_repositories_branches))
        .route("/repositories/discover", get(api_repositories_discover))
        .route("/fs/browse", get(api_fs_browse))
        .route("/fs/preview", get(api_fs_preview))
        .route("/fs/raw", get(api_fs_raw))
        .route("/fs/content", get(api_fs_content))
        .route("/fs/diff", get(api_fs_diff))
        .route("/fs/diff-content", get(api_fs_diff_content))
        .route("/fs/mkdir", post(api_fs_mkdir))
        .route("/fs/completions", get(api_fs_completions))
        .route("/files/upload", post(api_files_upload))
        .route("/files", get(api_files_list))
        .route(
            "/files/{filename}",
            get(api_files_get).delete(api_files_delete),
        )
        .route("/multiplexer/status", get(api_multiplexer_status))
        .route(
            "/multiplexer/tmux/sessions/{session_name}/windows",
            get(api_multiplexer_tmux_windows),
        )
        .route(
            "/multiplexer/tmux/sessions/{session_name}/panes",
            get(api_multiplexer_tmux_panes),
        )
        .route("/multiplexer/sessions", post(api_multiplexer_create_session))
        .route("/multiplexer/attach", post(api_multiplexer_attach))
        .route(
            "/multiplexer/{mux_type}/sessions/{session_name}",
            axum::routing::delete(api_multiplexer_kill_session),
        )
        .route(
            "/multiplexer/tmux/sessions/{session_name}/windows/{window_index}",
            axum::routing::delete(api_multiplexer_kill_window),
        )
        .route(
            "/multiplexer/tmux/sessions/{session_name}/panes/{pane_id}",
            axum::routing::delete(api_multiplexer_kill_pane),
        )
        .route("/multiplexer/context", get(api_multiplexer_context))
        .route("/tmux/available", get(api_tmux_available))
        .route("/tmux/sessions", get(api_tmux_sessions).post(api_tmux_create_session))
        .route(
            "/tmux/sessions/{session_name}/windows",
            get(api_tmux_session_windows),
        )
        .route(
            "/tmux/sessions/{session_name}/panes",
            get(api_tmux_session_panes),
        )
        .route("/tmux/attach", post(api_tmux_attach))
        .route(
            "/tmux/sessions/{session_name}/send",
            post(api_tmux_session_send),
        )
        .route(
            "/tmux/sessions/{session_name}",
            axum::routing::delete(api_tmux_delete_session),
        )
        .route("/tmux/context", get(api_tmux_context))
        .route("/sessions/tailscale/status", get(api_tailscale_status))
        .route("/sessions/tailscale/test", get(api_tailscale_test))
        .route("/sessions", get(api_list_sessions).post(api_create_session))
        .route("/sessions/{session_id}/git-status", get(api_session_git_status))
        .route("/sessions/{session_id}", get(api_get_session).delete(api_delete_session))
        .route("/sessions/{session_id}/cleanup", axum::routing::delete(api_cleanup_session))
        .route("/cleanup-exited", post(api_cleanup_exited))
        .route("/sessions/{session_id}/text", get(api_session_text))
        .route("/sessions/{session_id}/input", post(api_session_input))
        .route("/sessions/{session_id}/resize", post(api_session_resize))
        .route("/sessions/{session_id}", axum::routing::patch(api_patch_session))
        .route("/sessions/{session_id}/reset-size", post(api_reset_session_size))
        .route("/test-notification", post(api_test_notification))
        .fallback(api_not_found)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .nest("/api", api)
        .route("/ws", get(ws_upgrade))
        .route("/", get(serve_index))
        .route("/session/{id}", get(serve_index))
        .route("/worktrees", get(serve_index))
        .route("/file-browser", get(serve_index))
        .fallback(serve_embedded_asset)
        .layer(CompressionLayer::new())
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

fn is_localhost_ip(ip: &str) -> bool {
    matches!(ip, "127.0.0.1" | "::1" | "::ffff:127.0.0.1")
}

fn is_local_request(headers: &HeaderMap) -> bool {
    let no_forwarded_for = !headers.contains_key("x-forwarded-for");
    let no_real_ip = !headers.contains_key("x-real-ip");
    let no_forwarded_host = !headers.contains_key("x-forwarded-host");

    let host = header_string(headers, header::HOST.as_str()).unwrap_or_default();
    let host_only = host.split(':').next().unwrap_or_default();
    let host_is_local = matches!(host_only, "localhost" | "127.0.0.1" | "[::1]");

    no_forwarded_for && no_real_ip && no_forwarded_host && host_is_local
}

fn extract_primary_forwarded_ip(headers: &HeaderMap) -> String {
    header_string(headers, "x-forwarded-for")
        .unwrap_or_default()
        .split(',')
        .next()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn has_tailscale_proxy_headers(headers: &HeaderMap) -> bool {
    headers.contains_key("x-forwarded-proto")
        && headers.contains_key("x-forwarded-for")
        && headers.contains_key("x-forwarded-host")
}

fn has_hq_registration_config(config: &ServerConfig) -> bool {
    (config.hq_url.is_some() || config.hq_username.is_some() || config.hq_password.is_some())
        && (config.no_hq_auth || (config.hq_url.is_some() && config.hq_username.is_some() && config.hq_password.is_some()))
}

fn has_hq_auth_payload(config: &ServerConfig) -> bool {
    config.hq_username.is_some() && config.hq_password.is_some()
}

fn tailscale_mode(config: &ServerConfig) -> &'static str {
    if config.enable_tailscale_funnel {
        "public"
    } else {
        "private"
    }
}

fn tailscale_is_public(config: &ServerConfig) -> bool {
    config.enable_tailscale_funnel
}

fn build_middleware_bypass_paths() -> [&'static str; 7] {
    [
        "/api/auth",
        "/api/logs",
        "/api/sessions/tailscale/status",
        "/api/sessions/tailscale/test",
        "/api/push",
        "/api/test-notification",
        "/api/server/status",
    ]
}

fn extract_token_from_uri(uri: &axum::http::Uri) -> Option<String> {
    let query = uri.query()?;

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        if (key == "token" || key == "localAuthToken") && !value.trim().is_empty() {
            return Some(value.to_string());
        }
    }

    None
}

fn use_remaining_config(config: &ServerConfig) -> bool {
    let mut enabled = false;

    if config.remote_name.as_ref().is_some() {
        enabled = true;
    }
    if config.allow_insecure_hq {
        enabled = true;
    }
    if config.push_enabled {
        enabled = true;
    }
    if config.vapid_email.as_ref().is_some() {
        enabled = true;
    }
    if config.generate_vapid_keys {
        enabled = true;
    }
    if config.enable_mdns {
        enabled = true;
    }
    if config.enable_ngrok {
        enabled = true;
    }
    if config.ngrok_auth_token.as_ref().is_some() {
        enabled = true;
    }
    if config.ngrok_domain.as_ref().is_some() {
        enabled = true;
    }
    if config.ngrok_region.as_ref().is_some() {
        enabled = true;
    }
    if config.enable_cloudflare {
        enabled = true;
    }

    enabled
}

fn tailscale_is_running(config: &ServerConfig) -> bool {
    config.enable_tailscale_serve
}

fn tailscale_last_error(config: &ServerConfig) -> Option<String> {
    if config.enable_tailscale_serve {
        None
    } else {
        Some("Tailscale Serve is not enabled".to_string())
    }
}

fn tailscale_fallback_message(config: &ServerConfig) -> String {
    if config.enable_tailscale_serve {
        "Tailscale Serve configured".to_string()
    } else {
        "Running in standard mode - accessible via your machine's tailnet IP".to_string()
    }
}

fn tailscale_recommendations(config: &ServerConfig) -> Vec<String> {
    if config.enable_tailscale_serve {
        vec!["Tailscale integration is configured".to_string()]
    } else {
        vec!["Enable Tailscale Serve integration in settings".to_string()]
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();

    let bypass_paths = build_middleware_bypass_paths();
    if path.starts_with(bypass_paths[0])
        || path.starts_with(bypass_paths[1])
        || path == bypass_paths[2]
        || path == bypass_paths[3]
        || path.starts_with(bypass_paths[4])
        || path.starts_with(bypass_paths[5])
        || path == bypass_paths[6]
    {
        return next.run(request).await;
    }

    if state.config.no_auth {
        return next.run(request).await;
    }

    let token_query = extract_token_from_uri(request.uri());

    let ctx = authenticate_headers(
        &state.config,
        &headers,
        token_query.as_deref(),
        Some(remote_addr),
    );
    if ctx.user_id.is_some() || ctx.is_hq_request {
        return next.run(request).await;
    }

    unauthorized_response()
}

fn authenticate_headers(
    config: &ServerConfig,
    headers: &HeaderMap,
    token_query: Option<&str>,
    remote_addr: Option<std::net::SocketAddr>,
) -> AuthContext {
    if config.no_auth {
        return AuthContext {
            user_id: Some("no-auth-user".to_string()),
            auth_method: Some("no-auth"),
            is_hq_request: false,
        };
    }

    if config.allow_local_bypass
        && is_local_request(headers)
        && remote_addr
            .map(|addr| is_localhost_ip(&addr.ip().to_string()))
            .unwrap_or(false)
    {
        if let Some(expected) = config.local_auth_token.as_ref() {
            if expected.is_empty() || header_equals(headers, "x-vibetunnel-local", expected) {
                return AuthContext {
                    user_id: Some("local-user".to_string()),
                    auth_method: Some("local-bypass"),
                    is_hq_request: false,
                };
            }
        } else {
            return AuthContext {
                user_id: Some("local-user".to_string()),
                auth_method: Some("local-bypass"),
                is_hq_request: false,
            };
        }
    }

    if config.enable_tailscale_serve {
        if let Some(tailscale_user) = header_string(headers, "x-tailscale-user-login") {
            let forwarded_ip = extract_primary_forwarded_ip(headers);

            if !tailscale_user.trim().is_empty()
                && has_tailscale_proxy_headers(headers)
                && is_localhost_ip(&forwarded_ip)
            {
                return AuthContext {
                    user_id: Some(tailscale_user),
                    auth_method: Some("tailscale"),
                    is_hq_request: false,
                };
            }
        }
    }

    if let Some(auth_header) = header_string(headers, header::AUTHORIZATION.as_str()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            if !token.trim().is_empty() {
                return AuthContext {
                    user_id: Some("token-user".to_string()),
                    auth_method: Some("password"),
                    is_hq_request: false,
                };
            }
        }
    }

    if let Some(token) = token_query {
        if !token.trim().is_empty() {
            return AuthContext {
                user_id: Some("token-user".to_string()),
                auth_method: Some("password"),
                is_hq_request: false,
            };
        }
    }

    AuthContext {
        user_id: None,
        auth_method: None,
        is_hq_request: false,
    }
}

fn header_equals(headers: &HeaderMap, key: &str, expected: &str) -> bool {
    header_string(headers, key)
        .map(|value| value == expected)
        .unwrap_or(false)
}

fn decode_input_key(payload: &[u8]) -> Option<String> {
    let key = std::str::from_utf8(payload).ok()?;
    let mapped = match key {
        "enter" => "\r",
        "shift_enter" => "\n",
        "ctrl_enter" => "\r",
        "tab" => "\t",
        "shift_tab" => "\u{1b}[Z",
        "backspace" => "\u{7f}",
        "escape" => "\u{1b}",
        "arrow_up" => "\u{1b}[A",
        "arrow_down" => "\u{1b}[B",
        "arrow_right" => "\u{1b}[C",
        "arrow_left" => "\u{1b}[D",
        "home" => "\u{1b}[H",
        "end" => "\u{1b}[F",
        "page_up" => "\u{1b}[5~",
        "page_down" => "\u{1b}[6~",
        "delete" => "\u{1b}[3~",
        "f1" => "\u{1b}OP",
        "f2" => "\u{1b}OQ",
        "f3" => "\u{1b}OR",
        "f4" => "\u{1b}OS",
        "f5" => "\u{1b}[15~",
        "f6" => "\u{1b}[17~",
        "f7" => "\u{1b}[18~",
        "f8" => "\u{1b}[19~",
        "f9" => "\u{1b}[20~",
        "f10" => "\u{1b}[21~",
        "f11" => "\u{1b}[23~",
        "f12" => "\u{1b}[24~",
        _ => key,
    };
    Some(mapped.to_string())
}

fn header_string(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"VibeTunnel\"")],
        Json(ErrorResponse {
            error: "Authentication required".to_string(),
        }),
    )
        .into_response()
}

async fn api_health(State(state): State<AppState>) -> impl IntoResponse {
    let tailscale_enabled = state.config.enable_tailscale_serve;
    let tailscale_url = None::<String>;
    let mode = if state.config.is_hq_mode {
        "hq"
    } else if has_hq_registration_config(&state.config) {
        if has_hq_auth_payload(&state.config) {
            "remote"
        } else {
            "remote-no-auth"
        }
    } else {
        "standalone"
    };

    let connections = HealthConnections {
        http: HealthHttp {
            port: state.config.port,
            url: format!("http://localhost:{}", state.config.port),
        },
        port: state.config.port,
        ssl_available: false,
        is_public: false,
        tailscale: if tailscale_enabled {
            Some(HealthTailscale {
                available: tailscale_is_running(&state.config),
                is_running: tailscale_is_running(&state.config),
                https_available: tailscale_is_running(&state.config),
                is_public: tailscale_is_public(&state.config),
                funnel: false,
                mode: tailscale_mode(&state.config),
                hostname: None,
                https_url: None,
            })
        } else {
            None
        },
        tailscale_url: tailscale_url.clone(),
    };

    {
        let mut lock = state.tailscale_server_url.lock().await;
        *lock = tailscale_url.clone();
    }

    Json(HealthResponse {
        status: "healthy",
        timestamp: now_iso(),
        mode,
        version: state.config.version,
        build_date: std::env::var("BUILD_DATE").unwrap_or_else(|_| "development".to_string()),
        uptime: state.started_at.elapsed().as_secs_f64(),
        pid: std::process::id(),
        connections,
        tailscale_url,
    })
}

async fn api_server_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(ServerStatusResponse {
        mac_app_connected: true,
        is_hq_mode: state.config.is_hq_mode,
        version: state.config.version,
    })
}

async fn api_tailscale_status(State(state): State<AppState>) -> impl IntoResponse {
    let server_url = state.tailscale_server_url.lock().await.clone();
    Json(SessionTailscaleStatusResponse {
        is_running: tailscale_is_running(&state.config),
        is_permanently_disabled: !state.config.enable_tailscale_serve,
        last_error: tailscale_last_error(&state.config),
        recommendation: if state.config.enable_tailscale_serve {
            "Tailscale integration is configured".to_string()
        } else {
            "Enable Tailscale Serve integration in settings".to_string()
        },
        fallback_mode: tailscale_fallback_message(&state.config),
        permanently_disabled: !state.config.enable_tailscale_serve,
        server_url,
    })
}

async fn api_tailscale_test(State(state): State<AppState>) -> impl IntoResponse {
    let test_response = SessionTailscaleTestResponse {
        timestamp: now_iso(),
        tailscale: serde_json::json!({
            "installed": tailscale_is_running(&state.config),
            "status": if tailscale_is_running(&state.config) {
                "configured"
            } else {
                "disabled"
            },
        }),
        tailscale_serve: serde_json::json!({
            "configured": tailscale_is_running(&state.config),
            "error": tailscale_last_error(&state.config),
        }),
        server: serde_json::json!({
            "isListening": true,
            "port": state.config.port,
            "bindAddress": state.config.bind,
        }),
        recommendations: tailscale_recommendations(&state.config),
    };

    Json(test_response)
}

async fn api_auth_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<AuthConfigQuery>,
) -> impl IntoResponse {
    let auth_ctx = authenticate_headers(
        &state.config,
        &headers,
        query
            .token
            .as_deref()
            .or(query.local_auth_token.as_deref()),
        Some(remote_addr),
    );

    let mut response = serde_json::json!({
        "enableSSHKeys": state.config.enable_ssh_keys,
        "disallowUserPassword": state.config.disallow_user_password,
        "noAuth": state.config.no_auth,
    });

    if let Some(user) = auth_ctx.user_id {
        if auth_ctx.auth_method == Some("tailscale") {
            response["tailscaleAuth"] = serde_json::Value::Bool(true);
            response["authenticatedUser"] = serde_json::Value::String(user.clone());
            response["tailscaleUser"] = serde_json::json!({
                "login": user,
                "name": header_string(&headers, "x-tailscale-user-name").unwrap_or_default(),
                "profilePic": header_string(&headers, "x-tailscale-user-profile-pic"),
            });
        }
    }

    Json(response)
}

async fn api_auth_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<VerifyQuery>,
) -> impl IntoResponse {
    let auth_ctx = authenticate_headers(
        &state.config,
        &headers,
        query.token.as_deref(),
        Some(remote_addr),
    );

    if let Some(user_id) = auth_ctx.user_id {
        return Json(AuthVerifyResponse {
            valid: true,
            user_id: Some(user_id),
            error: None,
        })
        .into_response();
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(AuthVerifyResponse {
            valid: false,
            user_id: None,
            error: Some("Invalid or expired token".to_string()),
        }),
    )
        .into_response()
}

async fn api_auth_challenge(
    State(state): State<AppState>,
    Json(payload): Json<AuthChallengeRequest>,
) -> impl IntoResponse {
    let Some(user_id) = payload.user_id.map(|v| v.trim().to_string()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "User ID is required".to_string(),
            }),
        )
            .into_response();
    };

    if user_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "User ID is required".to_string(),
            }),
        )
            .into_response();
    }

    if !is_existing_system_user(&user_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".to_string(),
            }),
        )
            .into_response();
    }

    let challenge_id = uuid_like();
    let challenge = uuid_like();
    let expires_at_ms = now_unix_ms() + 5 * 60 * 1000;

    {
        let mut challenges = state.auth_challenges.lock().await;
        challenges.insert(
            challenge_id.clone(),
            AuthChallengeEntry {
                user_id,
                expires_at_ms,
            },
        );
    }

    Json(serde_json::json!({
        "challengeId": challenge_id,
        "challenge": challenge,
        "expiresAt": expires_at_ms,
    }))
    .into_response()
}

async fn api_auth_ssh_key(
    State(state): State<AppState>,
    Json(payload): Json<AuthSshKeyRequest>,
) -> impl IntoResponse {
    let Some(challenge_id) = payload.challenge_id.map(|v| v.trim().to_string()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge ID, public key, and signature are required".to_string(),
            }),
        )
            .into_response();
    };
    let Some(public_key) = payload.public_key.map(|v| v.trim().to_string()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge ID, public key, and signature are required".to_string(),
            }),
        )
            .into_response();
    };
    let Some(signature) = payload.signature.map(|v| v.trim().to_string()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge ID, public key, and signature are required".to_string(),
            }),
        )
            .into_response();
    };

    if challenge_id.is_empty() || public_key.is_empty() || signature.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge ID, public key, and signature are required".to_string(),
            }),
        )
            .into_response();
    }

    let challenge_entry = {
        let mut challenges = state.auth_challenges.lock().await;
        challenges.remove(&challenge_id)
    };

    let Some(challenge_entry) = challenge_entry else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "error": "Invalid or expired challenge",
            })),
        )
            .into_response();
    };

    if now_unix_ms() > challenge_entry.expires_at_ms {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "error": "Invalid or expired challenge",
            })),
        )
            .into_response();
    }

    if !is_authorized_ssh_key_for_user(&challenge_entry.user_id, &public_key) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "error": "SSH key not authorized for this user",
            })),
        )
            .into_response();
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "success": false,
            "error": "SSH key authentication failed",
        })),
    )
        .into_response()
}

async fn api_auth_password(Json(payload): Json<AuthPasswordRequest>) -> impl IntoResponse {
    let Some(user_id) = payload.user_id.map(|v| v.trim().to_string()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "User ID and password are required".to_string(),
            }),
        )
            .into_response();
    };
    let Some(password) = payload.password else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "User ID and password are required".to_string(),
            }),
        )
            .into_response();
    };

    if user_id.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "User ID and password are required".to_string(),
            }),
        )
            .into_response();
    }

    if !password_matches_configured_credentials(&user_id, &password) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "error": "Invalid username or password",
            })),
        )
            .into_response();
    }

    let token = create_auth_token_for_user(&user_id);
    Json(serde_json::json!({
        "success": true,
        "token": token,
        "userId": user_id,
        "authMethod": "password",
    }))
    .into_response()
}

async fn api_get_config(State(state): State<AppState>) -> impl IntoResponse {
    let app_config = state.app_config.lock().await.clone();
    Json(AppConfigResponse {
        repository_base_path: app_config.repository_base_path,
        server_configured: true,
        quick_start_commands: app_config.quick_start_commands,
        notification_preferences: app_config.notification_preferences,
    })
}

async fn api_put_config(
    State(state): State<AppState>,
    Json(payload): Json<AppConfigUpdateRequest>,
) -> impl IntoResponse {
    let mut updated = serde_json::Map::new();
    let mut app_config = state.app_config.lock().await;

    if let Some(repository_base_path_value) = payload.repository_base_path {
        if let Some(repository_base_path) = parse_repository_base_path(&repository_base_path_value) {
            app_config.repository_base_path = repository_base_path.clone();
            updated.insert(
                "repositoryBasePath".to_string(),
                serde_json::Value::String(repository_base_path),
            );
        }
    }

    if let Some(quick_start_commands_value) = payload.quick_start_commands {
        if let Some(quick_start_commands) = parse_quick_start_commands(&quick_start_commands_value) {
            app_config.quick_start_commands = quick_start_commands.clone();
            updated.insert(
                "quickStartCommands".to_string(),
                serde_json::to_value(quick_start_commands).unwrap_or(serde_json::json!([])),
            );
        }
    }

    if let Some(notification_preferences_value) = payload.notification_preferences {
        if let Some(notification_patch) =
            parse_notification_preferences_patch(&notification_preferences_value)
        {
            let current = app_config
                .notification_preferences
                .clone()
                .unwrap_or_else(default_notification_preferences);
            let merged = apply_notification_preferences_patch(&current, notification_patch);
            app_config.notification_preferences = Some(merged.clone());
            updated.insert(
                "notificationPreferences".to_string(),
                serde_json::to_value(merged).unwrap_or(serde_json::json!({})),
            );
        }
    }

    if updated.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No valid updates provided".to_string(),
            }),
        )
            .into_response();
    }

    if let Err(_error) = save_app_config(&app_config) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update config".to_string(),
            }),
        )
            .into_response();
    }

    updated.insert("success".to_string(), serde_json::Value::Bool(true));
    Json(serde_json::Value::Object(updated)).into_response()
}

async fn api_auth_current_user() -> impl IntoResponse {
    let user_id = std::env::var("VIBETUNNEL_USERNAME").unwrap_or_else(|_| current_system_user());
    Json(serde_json::json!({
        "userId": user_id
    }))
}

async fn api_auth_avatar(AxumPath(user_id): AxumPath<String>) -> impl IntoResponse {
    if !validate_avatar_user_id(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid user ID format".to_string(),
            }),
        )
            .into_response();
    }

    Json(serde_json::json!({
        "avatar": serde_json::Value::Null,
        "platform": "darwin",
    }))
    .into_response()
}

async fn api_auth_logout() -> impl IntoResponse {
    Json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully"
    }))
}

async fn api_logs_client(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    if !is_valid_log_entry(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid log request. Required: level, module, args[]".to_string(),
            }),
        )
            .into_response();
    }

    let level = payload
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("log")
        .to_uppercase();
    let module = payload
        .get("module")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let args = payload.get("args").cloned().unwrap_or_else(|| serde_json::json!([]));

    let Some(log_path) = log_file_path() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to process log".to_string(),
            }),
        )
            .into_response();
    };

    if let Some(parent) = log_path.parent() {
        if let Err(_error) = fs::create_dir_all(parent) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to process log".to_string(),
                }),
            )
                .into_response();
        }
    }

    let line = format!(
        "{} {} [CLIENT:{}] {}\n",
        now_iso(),
        level,
        module,
        serde_json::to_string(&args).unwrap_or_else(|_| "[]".to_string())
    );

    use std::io::Write;
    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(mut file) => {
            if file.write_all(line.as_bytes()).is_err() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to process log".to_string(),
                    }),
                )
                    .into_response();
            }
        }
        Err(_error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to process log".to_string(),
                }),
            )
                .into_response();
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

async fn api_logs_raw() -> impl IntoResponse {
    let Some(log_path) = log_file_path() else {
        return (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            String::new(),
        )
            .into_response();
    };

    if !log_path.exists() {
        return (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            String::new(),
        )
            .into_response();
    }

    match fs::read_to_string(log_path) {
        Ok(content) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], content).into_response(),
        Err(_error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to read log file".to_string(),
            }),
        )
            .into_response(),
    }
}

async fn api_logs_info() -> impl IntoResponse {
    let Some(log_path) = log_file_path() else {
        return Json(serde_json::json!({
            "exists": false,
            "size": 0,
            "lastModified": serde_json::Value::Null,
            "path": "",
        }))
        .into_response();
    };

    if !log_path.exists() {
        return Json(serde_json::json!({
            "exists": false,
            "size": 0,
            "lastModified": serde_json::Value::Null,
            "path": log_path.display().to_string(),
        }))
        .into_response();
    }

    match fs::metadata(&log_path) {
        Ok(stats) => {
            let last_modified = stats
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs().to_string())
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null);

            Json(serde_json::json!({
                "exists": true,
                "size": stats.len(),
                "sizeHuman": format_bytes(stats.len()),
                "lastModified": last_modified,
                "path": log_path.display().to_string(),
            }))
            .into_response()
        }
        Err(_error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get log info".to_string(),
            }),
        )
            .into_response(),
    }
}

async fn api_logs_clear() -> impl IntoResponse {
    let Some(log_path) = log_file_path() else {
        return StatusCode::NO_CONTENT.into_response();
    };

    if log_path.exists() && fs::write(log_path, "").is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to clear log file".to_string(),
            }),
        )
            .into_response();
    }

    StatusCode::NO_CONTENT.into_response()
}

async fn api_logs_flush() -> impl IntoResponse {
    StatusCode::NO_CONTENT.into_response()
}

fn configured_vapid_public_key() -> Option<String> {
    std::env::var("VIBETUNNEL_VAPID_PUBLIC_KEY")
        .ok()
        .or_else(|| std::env::var("VAPID_PUBLIC_KEY").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn push_runtime_available(config: &ServerConfig) -> bool {
    config.push_enabled && configured_vapid_public_key().is_some()
}

async fn api_push_vapid_public_key() -> impl IntoResponse {
    if let Some(public_key) = configured_vapid_public_key() {
        return Json(serde_json::json!({
            "publicKey": public_key,
            "enabled": true,
        }))
        .into_response();
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "Push notifications not configured",
            "message": "VAPID keys not available or service not initialized"
        })),
    )
        .into_response()
}

async fn api_push_status(State(state): State<AppState>) -> impl IntoResponse {
    let subscriptions = state.push_subscriptions.lock().await.clone();
    let total_subscriptions = subscriptions.len();
    let active_subscriptions = subscriptions.iter().filter(|sub| sub.is_active).count();

    if !push_runtime_available(&state.config) {
        return Json(PushStatusResponse {
            enabled: false,
            configured: false,
            has_vapid_keys: false,
            total_subscriptions: 0,
            active_subscriptions: 0,
            subscriptions: 0,
            errors: Some(vec![
                "Push notification service not initialized or VAPID not configured".to_string(),
            ]),
            status: None,
        })
        .into_response();
    }

    Json(PushStatusResponse {
        enabled: true,
        configured: true,
        has_vapid_keys: true,
        total_subscriptions,
        active_subscriptions,
        subscriptions: total_subscriptions,
        errors: None,
        status: Some(serde_json::json!({
            "enabled": true,
            "subscriptions": total_subscriptions,
            "active": active_subscriptions,
        })),
    })
    .into_response()
}

async fn api_push_subscribe(
    State(state): State<AppState>,
    Json(payload): Json<PushSubscribeRequest>,
) -> impl IntoResponse {
    if !push_runtime_available(&state.config) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Push notifications not initialized",
                "message": "Push notification service is not available",
            })),
        )
            .into_response();
    }

    let endpoint = payload.endpoint.map(|v| v.trim().to_string()).unwrap_or_default();
    let p256dh = payload
        .keys
        .as_ref()
        .and_then(|keys| keys.p256dh.as_ref())
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let auth = payload
        .keys
        .as_ref()
        .and_then(|keys| keys.auth.as_ref())
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    if endpoint.is_empty() || p256dh.is_empty() || auth.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid subscription data",
                "message": "Missing required subscription fields",
            })),
        )
            .into_response();
    }

    let subscription_id = {
        let mut subscriptions = state.push_subscriptions.lock().await;
        if let Some(existing) = subscriptions.iter_mut().find(|sub| sub.endpoint == endpoint) {
            existing.p256dh = p256dh;
            existing.auth = auth;
            existing.is_active = true;
            existing.id.clone()
        } else {
            let id = uuid_like();
            subscriptions.push(PushSubscriptionEntry {
                id: id.clone(),
                endpoint,
                p256dh,
                auth,
                is_active: true,
            });
            id
        }
    };

    Json(serde_json::json!({
        "success": true,
        "subscriptionId": subscription_id,
        "message": "Successfully subscribed to push notifications",
    }))
    .into_response()
}

async fn api_push_unsubscribe(
    State(state): State<AppState>,
    Json(payload): Json<PushUnsubscribeRequest>,
) -> impl IntoResponse {
    if !push_runtime_available(&state.config) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Push notifications not initialized",
                "message": "Push notification service is not available",
            })),
        )
            .into_response();
    }

    let endpoint = payload.endpoint.map(|v| v.trim().to_string()).unwrap_or_default();
    if endpoint.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Missing endpoint",
                "message": "Endpoint is required for unsubscription",
            })),
        )
            .into_response();
    }

    {
        let mut subscriptions = state.push_subscriptions.lock().await;
        subscriptions.retain(|sub| sub.endpoint != endpoint);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "Successfully unsubscribed from push notifications",
    }))
    .into_response()
}

async fn api_push_test(
    State(state): State<AppState>,
    Json(payload): Json<PushTestRequest>,
) -> impl IntoResponse {
    if !push_runtime_available(&state.config) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Push notifications not initialized",
                "message": "Push notification service is not available",
            })),
        )
            .into_response();
    }

    let active_subscribers = {
        let subscriptions = state.push_subscriptions.lock().await;
        subscriptions.iter().filter(|sub| sub.is_active).count()
    };

    let message = payload
        .message
        .unwrap_or_else(|| "This is a test notification from VibeTunnel".to_string());

    Json(serde_json::json!({
        "success": true,
        "sent": active_subscribers,
        "failed": 0,
        "errors": [],
        "message": format!("Test notification sent to {} push subscribers", active_subscribers),
        "body": message,
    }))
    .into_response()
}

async fn api_git_repo_info(Query(query): Query<GitPathQuery>) -> impl IntoResponse {
    let Some(path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid path parameter" })),
        )
            .into_response();
    };

    let absolute_path = resolve_absolute_path(&path);

    match run_git(
        &absolute_path,
        vec![
            "rev-parse".to_string(),
            "--show-toplevel".to_string(),
        ],
    ) {
        Ok((stdout, _)) => {
            let repo_path = stdout.trim().to_string();
            Json(serde_json::json!({
                "isGitRepo": true,
                "repoPath": repo_path,
            }))
            .into_response()
        }
        Err(error) => {
            if is_not_git_repository_error(&error) {
                return Json(serde_json::json!({ "isGitRepo": false })).into_response();
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to check git repository info",
                })),
            )
                .into_response()
        }
    }
}

async fn api_git_status(Query(query): Query<GitPathQuery>) -> impl IntoResponse {
    let Some(path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid path parameter" })),
        )
            .into_response();
    };

    let absolute_path = resolve_absolute_path(&path);

    let repo_path = match run_git(
        &absolute_path,
        vec![
            "rev-parse".to_string(),
            "--show-toplevel".to_string(),
        ],
    ) {
        Ok((stdout, _)) => stdout.trim().to_string(),
        Err(error) => {
            if is_not_git_repository_error(&error) {
                return Json(serde_json::json!({ "isGitRepo": false })).into_response();
            }

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get git status",
                    "message": error.message,
                })),
            )
                .into_response();
        }
    };

    let current_branch = run_git(
        Path::new(&repo_path),
        vec!["branch".to_string(), "--show-current".to_string()],
    )
    .map(|(stdout, _)| stdout.trim().to_string())
    .unwrap_or_default();

    let status_output = run_git(
        Path::new(&repo_path),
        vec!["status".to_string(), "--porcelain=v1".to_string()],
    )
    .map(|(stdout, _)| stdout)
    .unwrap_or_default();

    let (modified_count, untracked_count, staged_count, added_count, deleted_count, has_changes) =
        parse_git_status_porcelain_counts(&status_output);

    let mut ahead_count = 0_u64;
    let mut behind_count = 0_u64;
    let mut has_upstream = false;

    if run_git(
        Path::new(&repo_path),
        vec![
            "rev-parse".to_string(),
            "--abbrev-ref".to_string(),
            "--symbolic-full-name".to_string(),
            "@{u}".to_string(),
        ],
    )
    .map(|(stdout, _)| !stdout.trim().is_empty())
    .unwrap_or(false)
    {
        has_upstream = true;

        if let Ok((stdout, _)) = run_git(
            Path::new(&repo_path),
            vec![
                "rev-list".to_string(),
                "--left-right".to_string(),
                "--count".to_string(),
                "HEAD...@{u}".to_string(),
            ],
        ) {
            (ahead_count, behind_count) = parse_ahead_behind_counts(&stdout);
        }
    }

    Json(serde_json::json!({
        "isGitRepo": true,
        "repoPath": repo_path,
        "currentBranch": current_branch,
        "hasChanges": has_changes,
        "modifiedCount": modified_count,
        "untrackedCount": untracked_count,
        "stagedCount": staged_count,
        "addedCount": added_count,
        "deletedCount": deleted_count,
        "aheadCount": ahead_count,
        "behindCount": behind_count,
        "hasUpstream": has_upstream,
    }))
    .into_response()
}

async fn api_git_event(
    State(state): State<AppState>,
    Json(payload): Json<GitEventRequest>,
) -> impl IntoResponse {
    let Some(repo_path_raw) = payload.repo_path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid repoPath parameter" })),
        )
            .into_response();
    };

    let repo_path = resolve_absolute_path(&repo_path_raw);
    let repo_key = repo_path.to_string_lossy().to_string();

    let repo_lock = {
        let mut locks = state.git_repo_locks.lock().await;
        locks
            .entry(repo_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };

    let _repo_guard = repo_lock.lock().await;

    let mut current_branch = run_git(
        &repo_path,
        vec!["branch".to_string(), "--show-current".to_string()],
    )
    .map(|(stdout, _)| stdout.trim().to_string())
    .unwrap_or_default();

    if let Some(explicit_branch) = payload.branch.filter(|b| !b.trim().is_empty()) {
        current_branch = explicit_branch;
    }

    let mut follow_mode = false;
    let mut follow_worktree: Option<String> = None;
    let mut is_worktree_repo = false;
    let mut is_main_repo = false;
    let mut main_repo_path = repo_path.clone();

    if let Ok((git_dir_stdout, _)) = run_git(
        &repo_path,
        vec!["rev-parse".to_string(), "--git-dir".to_string()],
    ) {
        let git_dir = git_dir_stdout.trim().to_string();
        is_worktree_repo = git_dir.contains("/.git/worktrees/") || git_dir.contains(".git/worktrees/");
        if is_worktree_repo {
            main_repo_path = extract_main_repo_from_git_dir(&git_dir, &repo_path);
        } else {
            is_main_repo = true;
        }

        if let Ok((follow_stdout, _)) = run_git(
            &main_repo_path,
            vec!["config".to_string(), "vibetunnel.followWorktree".to_string()],
        ) {
            let follow = follow_stdout.trim().to_string();
            if !follow.is_empty() {
                follow_mode = true;
                follow_worktree = Some(follow);
            }
        }
    }

    let mut updated_session_ids = Vec::<String>::new();

    {
        let mut sessions = state.sessions.lock().await;
        for session in sessions.iter_mut() {
            if session.working_dir.trim().is_empty() {
                continue;
            }

            let session_path = PathBuf::from(&session.working_dir);
            if !session_path.starts_with(&repo_path) {
                continue;
            }

            let base_name = strip_git_event_suffix(&session.name);
            let new_name = if let (Some(event), true) = (
                payload.event.as_ref().filter(|e| !e.trim().is_empty()),
                !current_branch.trim().is_empty(),
            ) {
                format!("{base_name} [{}: {}]", event.trim(), current_branch)
            } else if let Some(event) = payload.event.as_ref().filter(|e| !e.trim().is_empty()) {
                format!("{base_name} [{}]", event.trim())
            } else {
                base_name
            };

            session.name = new_name;
            session.last_modified = now_iso();
            updated_session_ids.push(session.id.clone());
        }
    }

    if follow_mode {
        if is_main_repo && payload.event.as_deref() == Some("checkout") {
            let _ = run_git(
                &main_repo_path,
                vec![
                    "config".to_string(),
                    "--local".to_string(),
                    "--unset".to_string(),
                    "vibetunnel.followWorktree".to_string(),
                ],
            );
            follow_mode = false;
            follow_worktree = None;
        } else if let Some(follow_target) = follow_worktree.as_ref() {
            if is_main_repo && payload.event.as_deref() == Some("commit") {
                let follow_target_path = PathBuf::from(follow_target);
                let _ = run_git(
                    &follow_target_path,
                    vec!["pull".to_string(), "--ff-only".to_string()],
                );
            } else if is_worktree_repo && repo_path == PathBuf::from(follow_target) {
                if !current_branch.trim().is_empty() {
                    let _ = run_git(
                        &main_repo_path,
                        vec!["checkout".to_string(), current_branch.clone()],
                    );
                    let _ = run_git(
                        &main_repo_path,
                        vec!["pull".to_string(), "--ff-only".to_string()],
                    );
                }
            }
        }
    }

    let mut notifications_to_send = Vec::<GitUiNotification>::new();

    if follow_mode {
        if let Some(worktree) = follow_worktree.as_ref() {
            let worktree_name = Path::new(worktree)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(worktree);
            notifications_to_send.push(GitUiNotification {
                level: "info".to_string(),
                title: "Follow Mode Active".to_string(),
                message: format!(
                    "Following worktree '{}' in {}",
                    worktree_name,
                    repo_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("repository")
                ),
            });
        }
    }

    if !notifications_to_send.is_empty() {
        let mut notifications = state.git_notifications.lock().await;
        let now = now_unix_ms();
        for notification in notifications_to_send {
            notifications.push(GitNotificationEntry {
                timestamp_ms: now,
                notification,
            });
        }
        trim_old_git_notifications(&mut notifications);
    }

    let notification_event = payload.event.clone();

    Json(serde_json::json!({
        "success": true,
        "repoPath": repo_path.to_string_lossy().to_string(),
        "sessionsUpdated": updated_session_ids.len(),
        "followMode": follow_mode,
        "notification": {
            "type": "git-event",
            "repoPath": repo_path.to_string_lossy().to_string(),
            "branch": if current_branch.is_empty() { serde_json::Value::Null } else { serde_json::json!(current_branch) },
            "event": notification_event,
            "followMode": follow_mode,
            "sessionsUpdated": updated_session_ids,
        }
    }))
    .into_response()
}

async fn api_git_notifications(State(state): State<AppState>) -> impl IntoResponse {
    let mut notifications = state.git_notifications.lock().await;
    trim_old_git_notifications(&mut notifications);

    let payload: Vec<GitUiNotification> = notifications
        .iter()
        .map(|entry| entry.notification.clone())
        .collect();
    notifications.clear();

    Json(serde_json::json!({ "notifications": payload })).into_response()
}

async fn api_git_remote(Query(query): Query<GitPathQuery>) -> impl IntoResponse {
    let Some(path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid path parameter" })),
        )
            .into_response();
    };

    let absolute_path = resolve_absolute_path(&path);

    let repo_path = match run_git(
        &absolute_path,
        vec![
            "rev-parse".to_string(),
            "--show-toplevel".to_string(),
        ],
    ) {
        Ok((stdout, _)) => stdout.trim().to_string(),
        Err(error) => {
            if is_not_git_repository_error(&error) {
                return Json(serde_json::json!({ "isGitRepo": false })).into_response();
            }

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get git remote",
                    "message": error.message,
                })),
            )
                .into_response();
        }
    };

    match run_git(
        Path::new(&repo_path),
        vec!["remote".to_string(), "get-url".to_string(), "origin".to_string()],
    ) {
        Ok((stdout, _)) => {
            let remote_url = stdout.trim().to_string();
            let github_url = parse_github_url(&remote_url);
            Json(serde_json::json!({
                "isGitRepo": true,
                "repoPath": repo_path,
                "remoteUrl": remote_url,
                "githubUrl": github_url,
            }))
            .into_response()
        }
        Err(error) => {
            if error.stderr.contains("No such remote") {
                return Json(serde_json::json!({
                    "isGitRepo": true,
                    "remoteUrl": serde_json::Value::Null,
                    "githubUrl": serde_json::Value::Null,
                }))
                .into_response();
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get git remote",
                    "message": error.message,
                })),
            )
                .into_response()
        }
    }
}

async fn api_git_repository_info(Query(query): Query<GitPathQuery>) -> impl IntoResponse {
    let Some(path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid path parameter" })),
        )
            .into_response();
    };

    let absolute_path = resolve_absolute_path(&path);

    let repo_path = match run_git(
        &absolute_path,
        vec![
            "rev-parse".to_string(),
            "--show-toplevel".to_string(),
        ],
    ) {
        Ok((stdout, _)) => stdout.trim().to_string(),
        Err(error) => {
            if is_not_git_repository_error(&error) {
                return Json(serde_json::json!({ "isGitRepo": false })).into_response();
            }

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get repository info",
                    "message": error.message,
                })),
            )
                .into_response();
        }
    };

    let current_branch = run_git(
        Path::new(&repo_path),
        vec!["branch".to_string(), "--show-current".to_string()],
    )
    .ok()
    .map(|(stdout, _)| stdout.trim().to_string());

    let status_output = run_git(
        Path::new(&repo_path),
        vec!["status".to_string(), "--porcelain=v1".to_string()],
    )
    .ok()
    .map(|(stdout, _)| stdout)
    .unwrap_or_default();

    let (modified_count, untracked_count, staged_count, added_count, deleted_count, has_changes) =
        parse_git_status_porcelain_counts(&status_output);

    let remote_url = run_git(
        Path::new(&repo_path),
        vec!["remote".to_string(), "get-url".to_string(), "origin".to_string()],
    )
    .ok()
    .map(|(stdout, _)| stdout.trim().to_string());

    let github_url = remote_url
        .as_ref()
        .and_then(|url| parse_github_url(url));

    let mut ahead_count = 0_u64;
    let mut behind_count = 0_u64;
    let mut has_upstream = false;

    if let Ok((stdout, _)) = run_git(
        Path::new(&repo_path),
        vec![
            "rev-list".to_string(),
            "--left-right".to_string(),
            "--count".to_string(),
            "HEAD...@{u}".to_string(),
        ],
    ) {
        has_upstream = true;
        (ahead_count, behind_count) = parse_ahead_behind_counts(&stdout);
    }

    let is_worktree = fs::metadata(Path::new(&repo_path).join(".git"))
        .map(|meta| meta.is_file())
        .unwrap_or(false);

    Json(serde_json::json!({
        "isGitRepo": true,
        "repoPath": repo_path,
        "currentBranch": current_branch,
        "remoteUrl": remote_url,
        "githubUrl": github_url,
        "hasChanges": has_changes,
        "modifiedCount": modified_count,
        "untrackedCount": untracked_count,
        "stagedCount": staged_count,
        "addedCount": added_count,
        "deletedCount": deleted_count,
        "aheadCount": ahead_count,
        "behindCount": behind_count,
        "hasUpstream": has_upstream,
        "isWorktree": is_worktree,
    }))
    .into_response()
}

async fn api_worktrees(Query(query): Query<WorktreesQuery>) -> impl IntoResponse {
    let Some(repo_path_raw) = query.repo_path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid repoPath parameter" })),
        )
            .into_response();
    };

    let absolute_repo_path = resolve_absolute_path(&repo_path_raw);
    let base_branch = detect_default_branch(&absolute_repo_path);

    let mut follow_branch: Option<String> = None;

    let parsed_worktrees = if let Ok((worktree_list_stdout, _)) = run_git(
        &absolute_repo_path,
        vec!["worktree".to_string(), "list".to_string(), "--porcelain".to_string()],
    ) {
        let parsed = parse_worktree_porcelain(&worktree_list_stdout);

        if let Ok((follow_stdout, _)) = run_git(
            &absolute_repo_path,
            vec!["config".to_string(), "vibetunnel.followWorktree".to_string()],
        ) {
            let follow_worktree_path = follow_stdout.trim();
            if !follow_worktree_path.is_empty() {
                if let Some(wt) = parsed.iter().find(|w| w.path == follow_worktree_path) {
                    follow_branch = Some(wt.branch.trim_start_matches("refs/heads/").to_string());
                }
            }
        }

        parsed
    } else {
        return Json(serde_json::json!({
            "worktrees": [],
            "baseBranch": "main",
            "followBranch": serde_json::Value::Null,
        }))
        .into_response();
    };

    let mut enriched = Vec::new();
    for worktree in parsed_worktrees {
        let mut value = serde_json::json!({
            "path": worktree.path,
            "branch": worktree.branch,
            "HEAD": worktree.head,
            "detached": worktree.detached,
            "prunable": worktree.prunable,
            "locked": worktree.locked,
            "lockedReason": worktree.locked_reason,
        });

        if !worktree.detached && !worktree.branch.is_empty() {
            let branch = worktree.branch.clone();
            let (commits_ahead, files_changed, insertions, deletions) =
                get_branch_stats(Path::new(value["path"].as_str().unwrap_or("")), &branch, &base_branch);
            let has_changes = has_uncommitted_changes(Path::new(value["path"].as_str().unwrap_or("")));

            if let Some(obj) = value.as_object_mut() {
                obj.insert("commitsAhead".to_string(), serde_json::json!(commits_ahead));
                obj.insert("filesChanged".to_string(), serde_json::json!(files_changed));
                obj.insert("insertions".to_string(), serde_json::json!(insertions));
                obj.insert("deletions".to_string(), serde_json::json!(deletions));
                obj.insert(
                    "stats".to_string(),
                    serde_json::json!({
                        "commitsAhead": commits_ahead,
                        "filesChanged": files_changed,
                        "insertions": insertions,
                        "deletions": deletions,
                    }),
                );
                obj.insert(
                    "hasUncommittedChanges".to_string(),
                    serde_json::json!(has_changes),
                );
            }
        }

        enriched.push(value);
    }

    Json(serde_json::json!({
        "worktrees": enriched,
        "baseBranch": base_branch,
        "followBranch": follow_branch,
    }))
    .into_response()
}

async fn api_create_worktree(Json(payload): Json<CreateWorktreeRequest>) -> impl IntoResponse {
    let Some(repo_path) = payload.repo_path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid repoPath in request body" })),
        )
            .into_response();
    };

    let Some(branch) = payload.branch.filter(|b| !b.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid branch in request body" })),
        )
            .into_response();
    };

    let Some(worktree_path) = payload.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid path in request body" })),
        )
            .into_response();
    };

    let absolute_repo_path = resolve_absolute_path(&repo_path);
    let absolute_worktree_path = resolve_absolute_path(&worktree_path);

    let mut args = vec!["worktree".to_string(), "add".to_string()];
    if let Some(base_branch) = payload.base_branch.filter(|b| !b.trim().is_empty()) {
        args.push("-b".to_string());
        args.push(branch.clone());
        args.push(absolute_worktree_path.to_string_lossy().to_string());
        args.push(base_branch);
    } else {
        args.push(absolute_worktree_path.to_string_lossy().to_string());
        args.push(branch.clone());
    }

    match run_git(&absolute_repo_path, args) {
        Ok(_) => Json(serde_json::json!({
            "message": "Worktree created successfully",
            "worktreePath": absolute_worktree_path.to_string_lossy().to_string(),
            "branch": branch,
        }))
        .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to create worktree",
                "details": if error.stderr.is_empty() { error.message } else { error.stderr },
            })),
        )
            .into_response(),
    }
}

async fn api_delete_worktree(
    AxumPath(branch): AxumPath<String>,
    Query(query): Query<DeleteWorktreeQuery>,
) -> impl IntoResponse {
    let Some(repo_path) = query.repo_path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid repoPath parameter" })),
        )
            .into_response();
    };

    let absolute_repo_path = resolve_absolute_path(&repo_path);
    let force_delete = query.force.as_deref() == Some("true");

    let list_output = match run_git(
        &absolute_repo_path,
        vec!["worktree".to_string(), "list".to_string(), "--porcelain".to_string()],
    ) {
        Ok((stdout, _)) => stdout,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to remove worktree",
                    "details": if error.stderr.is_empty() { error.message } else { error.stderr },
                })),
            )
                .into_response();
        }
    };

    let worktrees = parse_worktree_porcelain(&list_output);
    let target = worktrees.iter().find(|w| {
        let short_branch = w.branch.trim_start_matches("refs/heads/");
        w.branch == format!("refs/heads/{branch}") || short_branch == branch || w.branch == branch
    });

    let Some(target_worktree) = target else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Worktree for branch '{}' not found", branch),
            })),
        )
            .into_response();
    };

    if !force_delete && has_uncommitted_changes(Path::new(&target_worktree.path)) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Worktree has uncommitted changes",
                "worktreePath": target_worktree.path,
            })),
        )
            .into_response();
    }

    let mut remove_args = vec!["worktree".to_string(), "remove".to_string()];
    if force_delete {
        remove_args.push("--force".to_string());
    }
    remove_args.push(target_worktree.path.clone());

    match run_git(&absolute_repo_path, remove_args) {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "message": "Worktree removed successfully",
            "removedPath": target_worktree.path,
        }))
        .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to remove worktree",
                "details": if error.stderr.is_empty() { error.message } else { error.stderr },
            })),
        )
            .into_response(),
    }
}

async fn api_prune_worktrees(Json(payload): Json<PruneWorktreesRequest>) -> impl IntoResponse {
    let Some(repo_path) = payload.repo_path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid repoPath in request body" })),
        )
            .into_response();
    };

    let absolute_repo_path = resolve_absolute_path(&repo_path);

    match run_git(
        &absolute_repo_path,
        vec!["worktree".to_string(), "prune".to_string()],
    ) {
        Ok((stdout, stderr)) => {
            let output = if stdout.trim().is_empty() {
                if stderr.trim().is_empty() {
                    "No output".to_string()
                } else {
                    stderr.clone()
                }
            } else {
                stdout.clone()
            };

            Json(serde_json::json!({
                "success": true,
                "message": "Worktree information pruned successfully",
                "output": output,
                "pruned": if stdout.is_empty() { stderr } else { stdout },
            }))
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to prune worktrees",
                "details": if error.stderr.is_empty() { error.message } else { error.stderr },
            })),
        )
            .into_response(),
    }
}

async fn api_follow_worktrees(
    State(state): State<AppState>,
    Json(payload): Json<FollowWorktreesRequest>,
) -> impl IntoResponse {
    let Some(repo_path) = payload.repo_path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid repoPath in request body" })),
        )
            .into_response();
    };

    let Some(enable) = payload.enable else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid enable flag in request body" })),
        )
            .into_response();
    };

    if enable && payload.branch.as_deref().map(|b| b.trim().is_empty()).unwrap_or(true) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid branch in request body" })),
        )
            .into_response();
    }

    let absolute_repo_path = resolve_absolute_path(&repo_path);

    if enable {
        let branch = payload.branch.unwrap_or_default();

        let hooks_already_installed = are_hooks_installed(&absolute_repo_path);
        let mut hooks_install_result = serde_json::Value::Null;

        if !hooks_already_installed {
            match install_git_hooks(&absolute_repo_path) {
                Ok(()) => {
                    hooks_install_result = serde_json::json!({
                        "success": true,
                    });
                }
                Err(errors) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "Failed to install Git hooks",
                            "details": errors,
                        })),
                    )
                        .into_response();
                }
            }
        }

        let worktree_list = match run_git(
            &absolute_repo_path,
            vec!["worktree".to_string(), "list".to_string(), "--porcelain".to_string()],
        ) {
            Ok((stdout, _)) => stdout,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to manage follow mode",
                        "details": if error.stderr.is_empty() { error.message } else { error.stderr },
                    })),
                )
                    .into_response();
            }
        };

        let worktrees = parse_worktree_porcelain(&worktree_list);
        let target = worktrees.iter().find(|w| {
            let short = w.branch.trim_start_matches("refs/heads/");
            w.branch == branch
                || w.branch == format!("refs/heads/{branch}")
                || short == branch
        });

        let Some(target_worktree) = target else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("No worktree found for branch: {}", branch),
                })),
            )
                .into_response();
        };

        if let Err(error) = run_git(
            &absolute_repo_path,
            vec![
                "config".to_string(),
                "--local".to_string(),
                "vibetunnel.followWorktree".to_string(),
                target_worktree.path.clone(),
            ],
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to manage follow mode",
                    "details": if error.stderr.is_empty() { error.message } else { error.stderr },
                })),
            )
                .into_response();
        }

        let clean_branch = branch.trim_start_matches("refs/heads/").to_string();

        if run_git(
            &absolute_repo_path,
            vec![
                "branch".to_string(),
                "--list".to_string(),
                clean_branch.clone(),
            ],
        )
        .map(|(stdout, _)| !stdout.trim().is_empty())
        .unwrap_or(false)
        {
            let _ = run_git(
                &absolute_repo_path,
                vec!["checkout".to_string(), clean_branch],
            );
        } else {
            let fetch_result = run_git(
                &absolute_repo_path,
                vec![
                    "fetch".to_string(),
                    "origin".to_string(),
                    format!("{}:{}", clean_branch, clean_branch),
                ],
            );
            if fetch_result.is_ok() {
                let _ = run_git(
                    &absolute_repo_path,
                    vec!["checkout".to_string(), clean_branch],
                );
            }
        }

        let repo_name = absolute_repo_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("repository");
        let mut notifications = state.git_notifications.lock().await;
        notifications.push(GitNotificationEntry {
            timestamp_ms: now_unix_ms(),
            notification: GitUiNotification {
                level: "info".to_string(),
                title: "Follow Mode Enabled".to_string(),
                message: format!("Now following branch '{}' in {}", branch, repo_name),
            },
        });
        trim_old_git_notifications(&mut notifications);

        return Json(serde_json::json!({
            "success": true,
            "enabled": true,
            "message": "Follow mode enabled",
            "branch": branch,
            "hooksInstalled": true,
            "hooksInstallResult": hooks_install_result,
        }))
        .into_response();
    }

    let unset_result = run_git(
        &absolute_repo_path,
        vec![
            "config".to_string(),
            "--local".to_string(),
            "--unset".to_string(),
            "vibetunnel.followWorktree".to_string(),
        ],
    );

    if let Err(error) = unset_result {
        if !is_git_config_not_found_error(&error) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to manage follow mode",
                    "details": if error.stderr.is_empty() { error.message } else { error.stderr },
                })),
            )
                .into_response();
        }
    }

    let hooks_uninstall_result = uninstall_git_hooks(&absolute_repo_path);

    let repo_name = absolute_repo_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repository");
    let mut notifications = state.git_notifications.lock().await;
    notifications.push(GitNotificationEntry {
        timestamp_ms: now_unix_ms(),
        notification: GitUiNotification {
            level: "info".to_string(),
            title: "Follow Mode Disabled".to_string(),
            message: format!("Follow mode has been disabled for {}", repo_name),
        },
    });
    trim_old_git_notifications(&mut notifications);

    match hooks_uninstall_result {
        Ok(()) => Json(serde_json::json!({
            "success": true,
            "enabled": false,
            "message": "Follow mode disabled",
            "branch": payload.branch,
        }))
        .into_response(),
        Err(errors) => Json(serde_json::json!({
            "success": true,
            "enabled": false,
            "message": "Follow mode disabled",
            "branch": payload.branch,
            "hooksUninstallResult": {
                "success": false,
                "errors": errors,
            },
        }))
        .into_response(),
    }
}

async fn api_repositories_branches(Query(query): Query<RepositoriesBranchesQuery>) -> impl IntoResponse {
    let Some(path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Missing or invalid path parameter",
            })),
        )
            .into_response();
    };

    let expanded_path = resolve_absolute_path(&path);

    match list_branches(&expanded_path) {
        Ok(branches) => {
            let payload: Vec<serde_json::Value> = branches
                .into_iter()
                .map(|branch| {
                    serde_json::json!({
                        "name": branch.name,
                        "current": branch.current,
                        "remote": branch.remote,
                        "worktreePath": branch.worktree_path,
                    })
                })
                .collect();
            Json(serde_json::json!(payload)).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to list branches",
            })),
        )
            .into_response(),
    }
}

async fn api_repositories_discover(Query(query): Query<RepositoriesDiscoverQuery>) -> impl IntoResponse {
    let base_path = query.path.unwrap_or_else(default_repository_base_path);
    let max_depth = query
        .max_depth
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|depth| *depth > 0)
        .unwrap_or(3);

    let expanded_path = resolve_absolute_path(&base_path);
    let repositories = discover_repositories(&expanded_path, max_depth);

    let payload: Vec<serde_json::Value> = repositories
        .into_iter()
        .map(|repo| {
            serde_json::json!({
                "id": repo.id,
                "path": repo.path,
                "folderName": repo.folder_name,
                "lastModified": repo.last_modified,
                "relativePath": repo.relative_path,
                "gitBranch": repo.git_branch,
            })
        })
        .collect();

    Json(serde_json::json!(payload)).into_response()
}

async fn api_fs_browse(Query(query): Query<std::collections::HashMap<String, String>>) -> impl IntoResponse {
    let requested_path = query
        .get("path")
        .map(|s| s.as_str())
        .unwrap_or(".")
        .to_string();
    let show_hidden = query
        .get("showHidden")
        .map(|s| s == "true")
        .unwrap_or(false);
    let git_filter = query
        .get("gitFilter")
        .map(|s| s.as_str())
        .unwrap_or("all");

    let full_path = resolve_absolute_path(&requested_path);

    let canonical = match fs::canonicalize(&full_path) {
        Ok(path) => path,
        Err(error) => {
            let status = if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (
                status,
                Json(ErrorResponse {
                    error: if status == StatusCode::NOT_FOUND {
                        "Directory not found".to_string()
                    } else {
                        error.to_string()
                    },
                }),
            )
                .into_response();
        }
    };

    let metadata = match fs::metadata(&canonical) {
        Ok(meta) => meta,
        Err(error) => {
            let status = match error.kind() {
                std::io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return (
                status,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };

    if !metadata.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path is not a directory".to_string(),
            }),
        )
            .into_response();
    }

    let git_status = if git_filter != "none" {
        get_git_status_for_directory(&canonical)
    } else {
        None
    };

    let git_repo_root = if git_status.is_some() {
        run_git(
            &canonical,
            vec![
                "rev-parse".to_string(),
                "--show-toplevel".to_string(),
            ],
        )
        .ok()
        .map(|(stdout, _)| PathBuf::from(stdout.trim()))
        .unwrap_or_else(|| canonical.clone())
    } else {
        canonical.clone()
    };

    let mut files = Vec::new();
    match fs::read_dir(&canonical) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !show_hidden && name.starts_with('.') {
                    continue;
                }

                let path = entry.path();
                let meta = fs::metadata(&path).ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

                let modified = meta
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs().to_string())
                    .unwrap_or_else(now_iso);

                let git_status_value = if git_filter == "none" {
                    serde_json::Value::Null
                } else {
                    get_file_git_status(&path, git_status.as_ref(), &git_repo_root)
                };

                if git_filter == "changed"
                    && (git_status_value.is_null() || git_status_value == serde_json::json!("unchanged"))
                {
                    continue;
                }

                files.push(serde_json::json!({
                    "name": name,
                    "path": path.to_string_lossy().to_string(),
                    "type": if is_dir { "directory" } else { "file" },
                    "size": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    "modified": modified,
                    "permissions": meta.as_ref().map(|m| format!("{:o}", m.permissions().mode() & 0o777)).unwrap_or_else(|| "000".to_string()),
                    "isGitTracked": !git_status_value.is_null() && git_status_value != serde_json::json!("untracked"),
                    "gitStatus": git_status_value,
                    "isSymlink": is_symlink(&path),
                }));
            }
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    }

    files.sort_by(|a, b| {
        let a_type = a.get("type").and_then(|v| v.as_str()).unwrap_or("file");
        let b_type = b.get("type").and_then(|v| v.as_str()).unwrap_or("file");
        if a_type != b_type {
            return if a_type == "directory" {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        a_name.cmp(b_name)
    });

    Json(serde_json::json!({
        "path": requested_path,
        "fullPath": canonical.to_string_lossy().to_string(),
        "gitStatus": git_status,
        "files": files,
    }))
    .into_response()
}

async fn api_fs_preview(Query(query): Query<FsPreviewQuery>) -> impl IntoResponse {
    let Some(requested_path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path is required".to_string(),
            }),
        )
            .into_response();
    };

    let full_path = resolve_absolute_path(&requested_path);
    let metadata = match fs::metadata(&full_path) {
        Ok(meta) => meta,
        Err(error) => {
            let status = if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (
                status,
                Json(ErrorResponse {
                    error: if status == StatusCode::NOT_FOUND {
                        "File not found".to_string()
                    } else {
                        error.to_string()
                    },
                }),
            )
                .into_response();
        }
    };

    if metadata.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot preview directories".to_string(),
            }),
        )
            .into_response();
    }

    let ext = full_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let mime_type = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "json" => "application/json",
        "js" => "application/javascript",
        "ts" => "application/typescript",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "md" => "text/markdown",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    };

    let is_text = mime_type.starts_with("text/")
        || matches!(
            mime_type,
            "application/json" | "application/javascript" | "application/typescript" | "application/xml"
        );
    let is_image = mime_type.starts_with("image/");

    if is_image {
        return Json(serde_json::json!({
            "type": "image",
            "mimeType": mime_type,
            "url": format!("/api/fs/raw?path={}", requested_path),
            "size": metadata.len(),
        }))
        .into_response();
    }

    if is_text || metadata.len() < 1024 * 1024 {
        match fs::read_to_string(&full_path) {
            Ok(content) => {
                return Json(serde_json::json!({
                    "type": "text",
                    "content": content,
                    "language": ext,
                    "mimeType": mime_type,
                    "size": metadata.len(),
                }))
                .into_response();
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: error.to_string(),
                    }),
                )
                    .into_response();
            }
        }
    }

    Json(serde_json::json!({
        "type": "binary",
        "mimeType": mime_type,
        "size": metadata.len(),
        "humanSize": format_bytes(metadata.len()),
    }))
    .into_response()
}

async fn api_fs_raw(Query(query): Query<FsPreviewQuery>) -> impl IntoResponse {
    let Some(requested_path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path is required".to_string(),
            }),
        )
            .into_response();
    };

    let full_path = resolve_absolute_path(&requested_path);
    let metadata = match fs::metadata(&full_path) {
        Ok(meta) => meta,
        Err(error) => {
            let status = if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (
                status,
                Json(ErrorResponse {
                    error: if status == StatusCode::NOT_FOUND {
                        "File not found".to_string()
                    } else {
                        error.to_string()
                    },
                }),
            )
                .into_response();
        }
    };

    if !metadata.is_file() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "File not found".to_string(),
            }),
        )
            .into_response();
    }

    let ext = full_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let content_type = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "json" => "application/json",
        "js" => "application/javascript",
        "ts" => "application/typescript",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "md" => "text/markdown",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    };

    let mut file = match fs::File::open(&full_path) {
        Ok(file) => file,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };

    let mut bytes = Vec::new();
    if let Err(error) = file.read_to_end(&mut bytes) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response();
    }

    (
        [(header::CONTENT_TYPE, content_type)],
        bytes,
    )
        .into_response()
}

async fn api_fs_content(Query(query): Query<FsPreviewQuery>) -> impl IntoResponse {
    let Some(requested_path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path is required".to_string(),
            }),
        )
            .into_response();
    };

    let full_path = resolve_absolute_path(&requested_path);
    match fs::read_to_string(&full_path) {
        Ok(content) => Json(serde_json::json!({
            "path": requested_path,
            "content": content,
            "language": full_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default(),
        }))
        .into_response(),
        Err(error) => {
            let status = if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response()
        }
    }
}

async fn api_fs_diff(Query(query): Query<FsDiffQuery>) -> impl IntoResponse {
    let Some(requested_path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path is required".to_string(),
            }),
        )
            .into_response();
    };

    let full_path = resolve_absolute_path(&requested_path);
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let relative_path = full_path
        .strip_prefix(&cwd)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| full_path.to_string_lossy().to_string());

    match run_git(
        &cwd,
        vec![
            "diff".to_string(),
            "HEAD".to_string(),
            "--".to_string(),
            relative_path.clone(),
        ],
    ) {
        Ok((stdout, _)) => Json(serde_json::json!({
            "path": requested_path,
            "diff": stdout,
            "hasDiff": !stdout.is_empty(),
        }))
        .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: if error.stderr.is_empty() { error.message } else { error.stderr },
            }),
        )
            .into_response(),
    }
}

async fn api_fs_diff_content(Query(query): Query<FsDiffQuery>) -> impl IntoResponse {
    let Some(requested_path) = query.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path is required".to_string(),
            }),
        )
            .into_response();
    };

    let full_path = resolve_absolute_path(&requested_path);
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let relative_path = full_path
        .strip_prefix(&cwd)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| full_path.to_string_lossy().to_string());

    let current_content = fs::read_to_string(&full_path).unwrap_or_default();

    let original_content = run_git(
        &cwd,
        vec![
            "show".to_string(),
            format!("HEAD:./{relative_path}"),
        ],
    )
    .map(|(stdout, _)| stdout)
    .unwrap_or_else(|_| current_content.clone());

    Json(serde_json::json!({
        "path": requested_path,
        "originalContent": original_content,
        "modifiedContent": current_content,
        "language": full_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default(),
    }))
    .into_response()
}

async fn api_fs_mkdir(Json(payload): Json<FsMkdirRequest>) -> impl IntoResponse {
    let Some(dir_path) = payload.path.filter(|p| !p.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path and name are required".to_string(),
            }),
        )
            .into_response();
    };

    let Some(name) = payload.name.filter(|n| !n.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Path and name are required".to_string(),
            }),
        )
            .into_response();
    };

    if name.contains('/') || name.contains('\\') || name.starts_with('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid directory name".to_string(),
            }),
        )
            .into_response();
    }

    let full_path = resolve_absolute_path(&dir_path).join(name);
    match fs::create_dir_all(&full_path) {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "path": full_path.to_string_lossy().to_string(),
        }))
        .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn api_fs_completions(Query(query): Query<FsCompletionsQuery>) -> impl IntoResponse {
    let original_path = query.path.unwrap_or_default();
    let partial_path = if original_path == "~" || original_path.starts_with("~/") {
        resolve_absolute_path(&original_path).to_string_lossy().to_string()
    } else {
        original_path.clone()
    };

    let (dir_path, partial_name) = if partial_path.ends_with('/') {
        (partial_path.clone(), String::new())
    } else {
        let dir = PathBuf::from(&partial_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());
        let name = PathBuf::from(&partial_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        (dir, name)
    };

    let full_dir_path = resolve_absolute_path(&dir_path);

    let dir_stats = match fs::metadata(&full_dir_path) {
        Ok(meta) if meta.is_dir() => meta,
        _ => {
            return Json(serde_json::json!({ "completions": [] })).into_response();
        }
    };
    let _ = dir_stats;

    let mut completions = Vec::new();
    if let Ok(entries) = fs::read_dir(&full_dir_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !partial_name.is_empty() && !name.to_lowercase().starts_with(&partial_name.to_lowercase())
            {
                continue;
            }
            if !partial_name.starts_with('.') && name.starts_with('.') {
                continue;
            }

            let entry_path = entry.path();
            let is_directory = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);

            let display_path = if original_path.ends_with('/') {
                format!("{}{}", original_path, name)
            } else if let Some(last_slash) = original_path.rfind('/') {
                format!("{}{}", &original_path[..=last_slash], name)
            } else {
                name.clone()
            };

            let mut is_git_repo = false;
            let mut git_branch: Option<String> = None;
            let mut git_added_count = 0_u64;
            let mut git_modified_count = 0_u64;
            let mut git_deleted_count = 0_u64;
            let mut is_worktree = false;

            if is_directory {
                let dot_git = entry_path.join(".git");
                if let Ok(meta) = fs::metadata(&dot_git) {
                    is_git_repo = true;
                    is_worktree = meta.is_file();

                    git_branch = run_git(
                        &entry_path,
                        vec!["branch".to_string(), "--show-current".to_string()],
                    )
                    .ok()
                    .map(|(stdout, _)| stdout.trim().to_string())
                    .filter(|s| !s.is_empty());

                    if let Ok((status_stdout, _)) = run_git(
                        &entry_path,
                        vec!["status".to_string(), "--porcelain".to_string()],
                    ) {
                        for line in status_stdout.lines() {
                            if line.len() < 2 {
                                continue;
                            }
                            let status_code = &line[..2];
                            if matches!(status_code, "??" | "A " | "AM") {
                                git_added_count += 1;
                            } else if matches!(status_code, " D" | "D ") {
                                git_deleted_count += 1;
                            } else if matches!(status_code, " M" | "M " | "MM") {
                                git_modified_count += 1;
                            }
                        }
                    }
                }
            }

            let git_status_count = git_added_count + git_modified_count + git_deleted_count;

            completions.push(serde_json::json!({
                "name": name,
                "path": display_path,
                "type": if is_directory { "directory" } else { "file" },
                "suggestion": if is_directory { format!("{display_path}/") } else { display_path },
                "isRepository": is_git_repo,
                "gitBranch": git_branch,
                "gitStatusCount": git_status_count,
                "gitAddedCount": git_added_count,
                "gitModifiedCount": git_modified_count,
                "gitDeletedCount": git_deleted_count,
                "isWorktree": is_worktree,
            }));
        }
    }

    completions.sort_by(|a, b| {
        let a_type = a.get("type").and_then(|v| v.as_str()).unwrap_or("file");
        let b_type = b.get("type").and_then(|v| v.as_str()).unwrap_or("file");
        if a_type != b_type {
            return if a_type == "directory" {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        a_name.cmp(b_name)
    });

    if completions.len() > 20 {
        completions.truncate(20);
    }

    Json(serde_json::json!({
        "completions": completions,
        "partialPath": original_path,
    }))
    .into_response()
}

async fn api_files_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let uploads_dir = uploads_directory();
    if let Err(error) = fs::create_dir_all(&uploads_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create uploads directory: {error}"),
            })),
        )
            .into_response();
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    if !content_type.contains("multipart/form-data") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No file provided" })),
        )
            .into_response();
    }

    let boundary = content_type
        .split(';')
        .find_map(|part| part.trim().strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').to_string());

    let Some(boundary) = boundary else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No file provided" })),
        )
            .into_response();
    };

    let payload = body.to_vec();
    let payload_str = String::from_utf8_lossy(&payload);
    let boundary_marker = format!("--{boundary}");
    let mut original_name = "upload.bin".to_string();
    let mut file_mimetype = "application/octet-stream".to_string();
    let mut file_bytes: Option<Vec<u8>> = None;

    for part in payload_str.split(&boundary_marker) {
        if !part.contains("name=\"file\"") {
            continue;
        }

        if let Some(filename_start) = part.find("filename=\"") {
            let rest = &part[filename_start + "filename=\"".len()..];
            if let Some(end_idx) = rest.find('"') {
                let candidate = rest[..end_idx].trim();
                if !candidate.is_empty() {
                    original_name = candidate.to_string();
                }
            }
        }

        if let Some(ct_start) = part.find("Content-Type:") {
            let rest = &part[ct_start + "Content-Type:".len()..];
            let ct_line = rest.lines().next().unwrap_or_default().trim();
            if !ct_line.is_empty() {
                file_mimetype = ct_line.to_string();
            }
        }

        let marker = b"\r\n\r\n";
        let bytes = part.as_bytes();
        if let Some(header_end) = bytes.windows(marker.len()).position(|w| w == marker) {
            let data = &bytes[header_end + marker.len()..];
            let trimmed = data
                .iter()
                .copied()
                .take_while(|b| *b != b'\r' && *b != b'\n')
                .collect::<Vec<u8>>();
            if !trimmed.is_empty() {
                file_bytes = Some(trimmed);
                break;
            }
        }
    }

    let Some(file_bytes) = file_bytes else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No file provided" })),
        )
            .into_response();
    };

    let ext = Path::new(&original_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let unique_filename = format!("{}{}", uuid::Uuid::new_v4(), ext);
    let file_path = uploads_dir.join(&unique_filename);

    if let Err(error) = fs::write(&file_path, &file_bytes) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Failed to upload file: {error}") })),
        )
            .into_response();
    }

    let metadata = fs::metadata(&file_path).ok();
    let created_at = metadata
        .as_ref()
        .and_then(|m| m.created().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(now_iso);
    let modified_at = metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(now_iso);

    let entry = UploadedFileEntry {
        filename: unique_filename.clone(),
        size: file_bytes.len() as u64,
        created_at,
        modified_at,
        extension: Path::new(&unique_filename)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default(),
        absolute_path: file_path.to_string_lossy().to_string(),
    };

    {
        let mut files = state.uploaded_files.lock().await;
        files.retain(|f| f.filename != unique_filename);
        files.push(entry.clone());
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let relative_path = PathBuf::from(&entry.absolute_path)
        .strip_prefix(&cwd)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| entry.absolute_path.clone());

    Json(serde_json::json!({
        "success": true,
        "filename": unique_filename,
        "originalName": original_name,
        "size": file_bytes.len(),
        "mimetype": file_mimetype,
        "path": entry.absolute_path,
        "relativePath": relative_path,
    }))
    .into_response()
}

async fn api_files_get(AxumPath(filename): AxumPath<String>) -> impl IntoResponse {
    if !sanitize_filename(&filename) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid filename" })),
        )
            .into_response();
    }

    let uploads_dir = uploads_directory();
    let file_path = uploads_dir.join(&filename);
    let resolved_path = match fs::canonicalize(&file_path) {
        Ok(path) => path,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "File not found" })),
            )
                .into_response();
        }
    };

    let resolved_uploads = fs::canonicalize(&uploads_dir).unwrap_or(uploads_dir.clone());
    if !resolved_path.starts_with(&resolved_uploads) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid file path" })),
        )
            .into_response();
    }

    let bytes = match fs::read(&resolved_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "File not found" })),
            )
                .into_response();
        }
    };

    let mime_type = detect_mime_from_path(&resolved_path);
    ([(header::CONTENT_TYPE, mime_type)], bytes).into_response()
}

async fn api_files_list(State(state): State<AppState>) -> impl IntoResponse {
    let uploads_dir = uploads_directory();
    let _ = fs::create_dir_all(&uploads_dir);

    let files = state.uploaded_files.lock().await.clone();
    let mut payload: Vec<serde_json::Value> = files
        .iter()
        .filter(|entry| uploads_dir.join(&entry.filename).exists())
        .map(|entry| {
            serde_json::json!({
                "filename": entry.filename,
                "size": entry.size,
                "createdAt": entry.created_at,
                "modifiedAt": entry.modified_at,
                "url": format!("/api/files/{}", entry.filename),
                "extension": entry.extension,
            })
        })
        .collect();

    payload.sort_by(|a, b| {
        b.get("createdAt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .cmp(a.get("createdAt").and_then(|v| v.as_str()).unwrap_or_default())
    });

    Json(serde_json::json!({
        "files": payload,
        "count": payload.len(),
    }))
    .into_response()
}

async fn api_files_delete(
    State(state): State<AppState>,
    AxumPath(filename): AxumPath<String>,
) -> impl IntoResponse {
    if !sanitize_filename(&filename) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid filename" })),
        )
            .into_response();
    }

    let uploads_dir = uploads_directory();
    let file_path = uploads_dir.join(&filename);

    let resolved_uploads = fs::canonicalize(&uploads_dir).unwrap_or(uploads_dir.clone());
    let resolved_path = fs::canonicalize(&file_path).ok();
    if let Some(resolved) = resolved_path.as_ref() {
        if !resolved.starts_with(&resolved_uploads) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid file path" })),
            )
                .into_response();
        }
    }

    match fs::remove_file(&file_path) {
        Ok(_) => {
            let mut files = state.uploaded_files.lock().await;
            files.retain(|entry| entry.filename != filename);
            Json(serde_json::json!({
                "success": true,
                "message": "File deleted successfully",
            }))
            .into_response()
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "File not found" })),
        )
            .into_response(),
    }
}

async fn api_multiplexer_status(State(state): State<AppState>) -> impl IntoResponse {
    let now = Instant::now();

    let availability = {
        let mut cache = state.multiplexer_available_cache.lock().await;
        if cache.values.is_empty() || now >= cache.expires_at {
            let mut next = HashMap::new();
            for mux in ["tmux", "zellij", "screen", "kitty"] {
                next.insert(mux.to_string(), multiplexer_available(mux));
            }
            cache.values = next;
            cache.expires_at = now + Duration::from_secs(15);
        }
        cache.values.clone()
    };

    let current = state.multiplexer_state.lock().await.clone();
    Json(build_multiplexer_status(&current, &availability)).into_response()
}

async fn api_multiplexer_tmux_windows(
    State(state): State<AppState>,
    AxumPath(session_name): AxumPath<String>,
) -> impl IntoResponse {
    let state_guard = state.multiplexer_state.lock().await;
    let exists = state_guard.tmux.iter().any(|s| s.name == session_name);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Session not found" })),
        )
            .into_response();
    }

    Json(serde_json::json!({
        "windows": [
            {
                "session": session_name,
                "index": 0,
                "name": "main",
                "active": true,
                "panes": 1
            }
        ]
    }))
    .into_response()
}

async fn api_multiplexer_tmux_panes(
    State(state): State<AppState>,
    AxumPath(session_name): AxumPath<String>,
    Query(query): Query<MultiplexerWindowQuery>,
) -> impl IntoResponse {
    let state_guard = state.multiplexer_state.lock().await;
    let exists = state_guard.tmux.iter().any(|s| s.name == session_name);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Session not found" })),
        )
            .into_response();
    }

    let window_index = query
        .window
        .and_then(|w| w.parse::<u32>().ok())
        .unwrap_or(0);

    Json(serde_json::json!({
        "panes": [
            {
                "session": session_name,
                "window": window_index,
                "index": 0,
                "active": true,
                "title": "shell",
                "pid": serde_json::Value::Null,
                "command": "zsh",
                "width": 120,
                "height": 30,
                "currentPath": std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).to_string_lossy().to_string(),
            }
        ]
    }))
    .into_response()
}

async fn api_multiplexer_create_session(
    State(state): State<AppState>,
    Json(payload): Json<MultiplexerCreateRequest>,
) -> impl IntoResponse {
    let Some(mux_type) = payload.mux_type.filter(|t| !t.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Type and name are required" })),
        )
            .into_response();
    };
    let Some(name) = payload.name.filter(|n| !n.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Type and name are required" })),
        )
            .into_response();
    };

    let mux_available = {
        let mut cache = state.multiplexer_available_cache.lock().await;
        if cache.values.is_empty() || Instant::now() >= cache.expires_at {
            let mut next = HashMap::new();
            for mux in ["tmux", "zellij", "screen", "kitty"] {
                next.insert(mux.to_string(), multiplexer_available(mux));
            }
            cache.values = next;
            cache.expires_at = Instant::now() + Duration::from_secs(15);
        }
        cache.values.get(&mux_type).copied().unwrap_or(false)
    };

    if !mux_available {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("{mux_type} is not available") })),
        )
            .into_response();
    }

    match mux_type.as_str() {
        "tmux" => match ProcessCommand::new("tmux")
            .args(["new-session", "-d", "-s", &name])
            .output()
        {
            Ok(output) if output.status.success() => {
                let mut mux = state.multiplexer_state.lock().await;
                mux.tmux.retain(|s| s.name != name);
                mux.tmux.push(MultiplexerSession {
                    name: name.clone(),
                    session_type: "tmux".to_string(),
                    current: false,
                    attached: false,
                    windows: 1,
                    activity: now_iso(),
                    exited: false,
                });
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let message = if stderr.is_empty() {
                    "Failed to create tmux session".to_string()
                } else {
                    stderr
                };
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": message })),
                )
                    .into_response();
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("Failed to create tmux session: {error}") })),
                )
                    .into_response();
            }
        },
        "zellij" => {
            // Zellij creates session on first attach with `zellij attach -c`.
            // Keep this endpoint as a validated no-op for compatibility.
        }
        "screen" => match ProcessCommand::new("screen")
            .args(["-dmS", &name])
            .output()
        {
            Ok(output) if output.status.success() => {
                let mut mux = state.multiplexer_state.lock().await;
                mux.screen.retain(|s| {
                    if s.name == name {
                        return false;
                    }
                    if let Some((_, simple_name)) = s.name.split_once('.') {
                        return simple_name != name;
                    }
                    true
                });
                if let Some(created_name) = resolve_screen_session_name(&name) {
                    mux.screen.push(MultiplexerSession {
                        name: created_name,
                        session_type: "screen".to_string(),
                        current: false,
                        attached: false,
                        windows: 1,
                        activity: now_iso(),
                        exited: false,
                    });
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let message = if stderr.is_empty() {
                    "Failed to create screen session".to_string()
                } else {
                    stderr
                };
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": message })),
                )
                    .into_response();
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("Failed to create screen session: {error}") })),
                )
                    .into_response();
            }
        },
        "kitty" => match ProcessCommand::new("kitty")
            .args(["@", "launch", "--type=window", "--title", &name])
            .output()
        {
            Ok(output) if output.status.success() => {
                let mut mux = state.multiplexer_state.lock().await;
                mux.kitty.retain(|s| s.name != name);
                mux.kitty.push(MultiplexerSession {
                    name: name.clone(),
                    session_type: "kitty".to_string(),
                    current: false,
                    attached: true,
                    windows: 1,
                    activity: now_iso(),
                    exited: false,
                });
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let message = if stderr.is_empty() {
                    "Failed to create kitty session (is kitty remote control enabled?)".to_string()
                } else {
                    stderr
                };
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": message })),
                )
                    .into_response();
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("Failed to create kitty session: {error}") })),
                )
                    .into_response();
            }
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Unsupported multiplexer type" })),
            )
                .into_response();
        }
    }

    Json(serde_json::json!({
        "success": true,
        "type": mux_type,
        "name": name,
    }))
    .into_response()
}

async fn api_multiplexer_attach(
    State(state): State<AppState>,
    Json(payload): Json<MultiplexerAttachRequest>,
) -> impl IntoResponse {
    let Some(mux_type) = payload.mux_type.filter(|t| !t.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Type and session name are required" })),
        )
            .into_response();
    };
    let Some(session_name) = payload.session_name.filter(|n| !n.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Type and session name are required" })),
        )
            .into_response();
    };

    let mux_available = {
        let mut cache = state.multiplexer_available_cache.lock().await;
        if cache.values.is_empty() || Instant::now() >= cache.expires_at {
            let mut next = HashMap::new();
            for mux in ["tmux", "zellij", "screen", "kitty"] {
                next.insert(mux.to_string(), multiplexer_available(mux));
            }
            cache.values = next;
            cache.expires_at = Instant::now() + Duration::from_secs(15);
        }
        cache.values.get(&mux_type).copied().unwrap_or(false)
    };

    if !mux_available {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("{mux_type} is not available") })),
        )
            .into_response();
    }

    let normalized_session_name = if mux_type == "screen" {
        resolve_screen_session_name(&session_name).unwrap_or_else(|| session_name.clone())
    } else {
        session_name.clone()
    };

    if mux_type == "kitty" {
        let Some(window_id) = kitty_window_id_from_name(&normalized_session_name) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Kitty session must use id format: id:<window-id>",
                })),
            )
                .into_response();
        };

        let command = vec![
            "kitty".to_string(),
            "@".to_string(),
            "focus-window".to_string(),
            "--match".to_string(),
            format!("id:{window_id}"),
        ];

        let fallback_working_dir = std::env::current_dir()
            .unwrap_or_default()
            .display()
            .to_string();
        let working_dir_input = payload.working_dir.unwrap_or_default();
        let mut working_dir = if working_dir_input.trim().is_empty() {
            fallback_working_dir.clone()
        } else {
            resolve_absolute_path(&working_dir_input)
                .to_string_lossy()
                .to_string()
        };
        if !Path::new(&working_dir).is_dir() {
            working_dir = fallback_working_dir;
        }

        let session_id = uuid_like();
        let now = now_iso();

        let requested_cols = payload.cols.unwrap_or(80).clamp(20, 1000);
        let requested_rows = payload.rows.unwrap_or(24).clamp(10, 1000);

        state
            .session_dimensions
            .lock()
            .await
            .insert(
                session_id.clone(),
                (u32::from(requested_cols), u32::from(requested_rows)),
            );
        let initial_cols: Option<u16> = Some(requested_cols);
        let initial_rows: Option<u16> = Some(requested_rows);

        let entry = SessionEntry {
            id: session_id.clone(),
            name: format!("kitty: id:{window_id}"),
            command: command.clone(),
            working_dir: working_dir.clone(),
            status: "running".to_string(),
            started_at: now.clone(),
            last_modified: now.clone(),
            initial_cols,
            initial_rows,
            exit_code: None,
            git_modified_count: None,
            git_added_count: None,
            git_deleted_count: None,
            git_ahead_count: None,
            git_behind_count: None,
        };

        state.sessions.lock().await.push(entry);
        {
            let mut outputs = state.session_outputs.lock().await;
            outputs.entry(session_id.clone()).or_default();
        }

        if let Err(error) =
            spawn_local_session_process(&state, &session_id, &command, &working_dir).await
        {
            state.session_dimensions.lock().await.remove(&session_id);
            state.session_outputs.lock().await.remove(&session_id);

            let mut sessions = state.sessions.lock().await;
            if let Some(position) = sessions.iter().position(|s| s.id == session_id) {
                sessions.remove(position);
            }

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to attach to kitty session",
                    "details": error.to_string(),
                })),
            )
                .into_response();
        }

        let _title_mode = payload.title_mode;

        let command_text = command.join(" ");
        let event_payload = serde_json::to_vec(&serde_json::json!({
            "type": "session-start",
            "sessionId": session_id,
            "sessionName": format!("kitty: id:{window_id}"),
            "command": command_text,
            "timestamp": now,
        }))
        .unwrap_or_default();
        broadcast_to_session(&state, "", WsV3MessageType::Event, event_payload).await;

        return Json(serde_json::json!({
            "success": true,
            "sessionId": session_id,
            "target": {
                "type": mux_type,
                "session": session_name,
                "window": payload.window_index,
                "pane": payload.pane_index,
            }
        }))
        .into_response();
    }

    {
        let mut mux = state.multiplexer_state.lock().await;
        let target_list = match mux_type.as_str() {
            "tmux" => &mut mux.tmux,
            "zellij" => &mut mux.zellij,
            "screen" => &mut mux.screen,
            "kitty" => &mut mux.kitty,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "Unsupported multiplexer type" })),
                )
                    .into_response();
            }
        };

        if !target_list.iter().any(|s| s.name == normalized_session_name) {
            target_list.push(MultiplexerSession {
                name: normalized_session_name.clone(),
                session_type: mux_type.clone(),
                current: true,
                attached: true,
                windows: 1,
                activity: now_iso(),
                exited: false,
            });
        } else {
            for session in target_list.iter_mut() {
                if session.name == normalized_session_name {
                    session.current = true;
                    session.attached = true;
                    session.activity = now_iso();
                }
            }
        }
    }

    let mut command = match mux_type.as_str() {
        "tmux" => {
            let target = if let Some(window_index) = payload.window_index {
                format!("{normalized_session_name}:{window_index}")
            } else {
                normalized_session_name.clone()
            };
            vec!["tmux".to_string(), "attach-session".to_string(), "-t".to_string(), target]
        }
        "zellij" => vec![
            "zellij".to_string(),
            "attach".to_string(),
            "-c".to_string(),
            normalized_session_name.clone(),
        ],
        "screen" => vec![
            "screen".to_string(),
            "-r".to_string(),
            normalized_session_name.clone(),
        ],
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Unsupported multiplexer type" })),
            )
                .into_response();
        }
    };

    if mux_type == "screen" && !is_screen_full_session_name(&normalized_session_name) {
        command = vec!["screen".to_string(), "-R".to_string(), normalized_session_name.clone()];
    }

    let fallback_working_dir = std::env::current_dir()
        .unwrap_or_default()
        .display()
        .to_string();
    let working_dir_input = payload.working_dir.unwrap_or_default();
    let mut working_dir = if working_dir_input.trim().is_empty() {
        fallback_working_dir.clone()
    } else {
        resolve_absolute_path(&working_dir_input)
            .to_string_lossy()
            .to_string()
    };
    if !Path::new(&working_dir).is_dir() {
        working_dir = fallback_working_dir;
    }

    let session_id = uuid_like();
    let now = now_iso();

    let requested_cols = payload.cols.unwrap_or(80).clamp(20, 1000);
    let requested_rows = payload.rows.unwrap_or(24).clamp(10, 1000);

    state
        .session_dimensions
        .lock()
        .await
        .insert(
            session_id.clone(),
            (u32::from(requested_cols), u32::from(requested_rows)),
        );
    let initial_cols: Option<u16> = Some(requested_cols);
    let initial_rows: Option<u16> = Some(requested_rows);

    let entry = SessionEntry {
        id: session_id.clone(),
        name: format!("{mux_type}: {normalized_session_name}"),
        command: command.clone(),
        working_dir: working_dir.clone(),
        status: "running".to_string(),
        started_at: now.clone(),
        last_modified: now.clone(),
        initial_cols,
        initial_rows,
        exit_code: None,
        git_modified_count: None,
        git_added_count: None,
        git_deleted_count: None,
        git_ahead_count: None,
        git_behind_count: None,
    };

    state.sessions.lock().await.push(entry);
    {
        let mut outputs = state.session_outputs.lock().await;
        outputs.entry(session_id.clone()).or_default();
    }

    if let Err(error) = spawn_local_session_process(&state, &session_id, &command, &working_dir).await
    {
        state.session_dimensions.lock().await.remove(&session_id);
        state.session_outputs.lock().await.remove(&session_id);

        let mut sessions = state.sessions.lock().await;
        if let Some(position) = sessions.iter().position(|s| s.id == session_id) {
            sessions.remove(position);
        }

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to attach to session",
                "details": error.to_string(),
            })),
        )
            .into_response();
    }

    let _title_mode = payload.title_mode;

    let command_text = command.join(" ");
    let event_payload = serde_json::to_vec(&serde_json::json!({
        "type": "session-start",
        "sessionId": session_id,
        "sessionName": format!("{mux_type}: {normalized_session_name}"),
        "command": command_text,
        "timestamp": now,
    }))
    .unwrap_or_default();
    broadcast_to_session(&state, "", WsV3MessageType::Event, event_payload).await;

    Json(serde_json::json!({
        "success": true,
        "sessionId": session_id,
        "target": {
            "type": mux_type,
            "session": session_name,
            "window": payload.window_index,
            "pane": payload.pane_index,
        }
    }))
    .into_response()
}

async fn api_multiplexer_kill_session(
    State(state): State<AppState>,
    AxumPath((mux_type, session_name)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    let mux_available = {
        let mut cache = state.multiplexer_available_cache.lock().await;
        if cache.values.is_empty() || Instant::now() >= cache.expires_at {
            let mut next = HashMap::new();
            for mux in ["tmux", "zellij", "screen", "kitty"] {
                next.insert(mux.to_string(), multiplexer_available(mux));
            }
            cache.values = next;
            cache.expires_at = Instant::now() + Duration::from_secs(15);
        }
        cache.values.get(&mux_type).copied().unwrap_or(false)
    };

    if !mux_available {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("{mux_type} is not available") })),
        )
            .into_response();
    }

    let effective_session_name = if mux_type == "screen" {
        resolve_screen_session_name(&session_name).unwrap_or_else(|| session_name.clone())
    } else {
        session_name.clone()
    };

    let kill_args: Vec<String> = match mux_type.as_str() {
        "tmux" => vec![
            "kill-session".to_string(),
            "-t".to_string(),
            effective_session_name.clone(),
        ],
        "zellij" => vec![
            "delete-session".to_string(),
            "--force".to_string(),
            effective_session_name.clone(),
        ],
        "screen" => vec![
            "-S".to_string(),
            effective_session_name.clone(),
            "-X".to_string(),
            "quit".to_string(),
        ],
        "kitty" => {
            let Some(window_id) = kitty_window_id_from_name(&effective_session_name) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "Kitty session must use id format: id:<window-id>",
                    })),
                )
                    .into_response();
            };
            vec![
                "@".to_string(),
                "close-window".to_string(),
                "--match".to_string(),
                format!("id:{window_id}"),
            ]
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Unsupported multiplexer type" })),
            )
                .into_response();
        }
    };

    let command_name = match mux_type.as_str() {
        "screen" => "screen",
        "kitty" => "kitty",
        _ => mux_type.as_str(),
    };
    match ProcessCommand::new(command_name).args(&kill_args).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let message = if stderr.is_empty() {
                "Failed to kill session".to_string()
            } else {
                stderr
            };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response();
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to kill session: {error}") })),
            )
                .into_response();
        }
    }

    {
        let mut mux = state.multiplexer_state.lock().await;
        let target_list = match mux_type.as_str() {
            "tmux" => &mut mux.tmux,
            "zellij" => &mut mux.zellij,
            "screen" => &mut mux.screen,
            "kitty" => &mut mux.kitty,
            _ => unreachable!(),
        };
        target_list.retain(|s| s.name != effective_session_name);
    }

    Json(serde_json::json!({ "success": true })).into_response()
}

async fn api_multiplexer_kill_window(
    State(state): State<AppState>,
    AxumPath((session_name, _window_index)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    let mut mux = state.multiplexer_state.lock().await;
    if let Some(session) = mux.tmux.iter_mut().find(|s| s.name == session_name) {
        if session.windows > 1 {
            session.windows -= 1;
        }
        return Json(serde_json::json!({ "success": true })).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Session not found" })),
    )
        .into_response()
}

async fn api_multiplexer_kill_pane(
    State(state): State<AppState>,
    AxumPath((session_name, _pane_id)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    let mux = state.multiplexer_state.lock().await;
    if mux.tmux.iter().any(|s| s.name == session_name) {
        return Json(serde_json::json!({ "success": true })).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Session not found" })),
    )
        .into_response()
}

async fn api_multiplexer_context(State(state): State<AppState>) -> impl IntoResponse {
    let now = Instant::now();

    let availability = {
        let mut cache = state.multiplexer_available_cache.lock().await;
        if cache.values.is_empty() || now >= cache.expires_at {
            let mut next = HashMap::new();
            for mux in ["tmux", "zellij", "screen", "kitty"] {
                next.insert(mux.to_string(), multiplexer_available(mux));
            }
            cache.values = next;
            cache.expires_at = now + Duration::from_secs(15);
        }
        cache.values.clone()
    };

    let mut available = Vec::new();
    for mux in ["tmux", "zellij", "screen", "kitty"] {
        if availability.get(mux).copied().unwrap_or(false) {
            available.push(mux);
        }
    }

    Json(serde_json::json!({
        "available": available,
        "default": "tmux",
        "mode": "local",
    }))
    .into_response()
}

async fn api_tmux_available(State(state): State<AppState>) -> impl IntoResponse {
    let mux = state.multiplexer_state.lock().await;
    let available = !mux.tmux.is_empty();
    Json(serde_json::json!({ "available": available })).into_response()
}

async fn api_tmux_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let mux = state.multiplexer_state.lock().await;
    let sessions: Vec<serde_json::Value> = mux
        .tmux
        .iter()
        .map(|session| {
            serde_json::json!({
                "name": session.name,
                "windows": session.windows,
                "created": session.activity,
                "attached": session.attached,
                "activity": session.activity,
                "current": session.current,
            })
        })
        .collect();

    Json(serde_json::json!({ "sessions": sessions })).into_response()
}

async fn api_tmux_session_windows(
    State(state): State<AppState>,
    AxumPath(session_name): AxumPath<String>,
) -> impl IntoResponse {
    let mux = state.multiplexer_state.lock().await;
    let Some(session) = mux.tmux.iter().find(|s| s.name == session_name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Failed to list tmux windows" })),
        )
            .into_response();
    };

    let windows: Vec<serde_json::Value> = (0..session.windows)
        .map(|index| {
            serde_json::json!({
                "session": session_name,
                "index": index,
                "name": if index == 0 { "main" } else { "window" },
                "active": index == 0,
                "panes": 1,
            })
        })
        .collect();

    Json(serde_json::json!({ "windows": windows })).into_response()
}

async fn api_tmux_session_panes(
    State(state): State<AppState>,
    AxumPath(session_name): AxumPath<String>,
    Query(query): Query<MultiplexerWindowQuery>,
) -> impl IntoResponse {
    let mux = state.multiplexer_state.lock().await;
    if !mux.tmux.iter().any(|s| s.name == session_name) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Failed to list tmux panes" })),
        )
            .into_response();
    }

    let window_index = query
        .window
        .and_then(|w| w.parse::<u32>().ok())
        .unwrap_or(0);

    Json(serde_json::json!({
        "panes": [
            {
                "session": session_name,
                "window": window_index,
                "index": 0,
                "active": true,
                "title": "shell",
                "pid": serde_json::Value::Null,
                "command": "zsh",
                "width": 120,
                "height": 30,
                "currentPath": std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).to_string_lossy().to_string(),
            }
        ]
    }))
    .into_response()
}

async fn api_tmux_create_session(
    State(state): State<AppState>,
    Json(payload): Json<TmuxCreateSessionRequest>,
) -> impl IntoResponse {
    let Some(name) = payload.name.filter(|n| !n.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Session name is required" })),
        )
            .into_response();
    };

    let mut mux = state.multiplexer_state.lock().await;
    mux.tmux.retain(|s| s.name != name);
    mux.tmux.push(MultiplexerSession {
        name: name.clone(),
        session_type: "tmux".to_string(),
        current: false,
        attached: false,
        windows: 1,
        activity: now_iso(),
        exited: false,
    });

    let _command = payload.command;

    Json(serde_json::json!({ "success": true, "name": name })).into_response()
}

async fn api_tmux_attach(
    State(state): State<AppState>,
    Json(payload): Json<TmuxAttachRequest>,
) -> impl IntoResponse {
    let Some(session_name) = payload.session_name.filter(|n| !n.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Session name is required" })),
        )
            .into_response();
    };

    {
        let mut mux = state.multiplexer_state.lock().await;
        if !mux.tmux.iter().any(|s| s.name == session_name) {
            mux.tmux.push(MultiplexerSession {
                name: session_name.clone(),
                session_type: "tmux".to_string(),
                current: true,
                attached: true,
                windows: 1,
                activity: now_iso(),
                exited: false,
            });
        } else {
            for session in mux.tmux.iter_mut() {
                if session.name == session_name {
                    session.current = true;
                    session.attached = true;
                    session.activity = now_iso();
                }
            }
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let now = now_iso();
    let mut sessions = state.sessions.lock().await;
    sessions.push(SessionEntry {
        id: session_id.clone(),
        name: format!("tmux:{session_name}"),
        command: vec!["tmux".to_string(), "attach-session".to_string(), "-t".to_string(), session_name.clone()],
        working_dir: payload
            .working_dir
            .unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .to_string_lossy()
                    .to_string()
            }),
        status: "running".to_string(),
        started_at: now.clone(),
        last_modified: now,
        initial_cols: None,
        initial_rows: None,
        exit_code: None,
        git_modified_count: None,
        git_added_count: None,
        git_deleted_count: None,
        git_ahead_count: None,
        git_behind_count: None,
    });

    let _title_mode = payload.title_mode;
    let _cols = payload.cols;
    let _rows = payload.rows;

    Json(serde_json::json!({
        "success": true,
        "sessionId": session_id,
        "target": {
            "session": session_name,
            "window": payload.window_index,
            "pane": payload.pane_index,
        }
    }))
    .into_response()
}

async fn api_tmux_session_send(
    State(state): State<AppState>,
    AxumPath(session_name): AxumPath<String>,
    Json(payload): Json<TmuxSendRequest>,
) -> impl IntoResponse {
    let Some(command) = payload.command.filter(|c| !c.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Command is required" })),
        )
            .into_response();
    };

    let mux = state.multiplexer_state.lock().await;
    if !mux.tmux.iter().any(|s| s.name == session_name) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to send command to tmux pane" })),
        )
            .into_response();
    }

    let _window_index = payload.window_index;
    let _pane_index = payload.pane_index;
    let _command = command;

    Json(serde_json::json!({ "success": true })).into_response()
}

async fn api_tmux_delete_session(
    State(state): State<AppState>,
    AxumPath(session_name): AxumPath<String>,
) -> impl IntoResponse {
    let mut mux = state.multiplexer_state.lock().await;
    let before = mux.tmux.len();
    mux.tmux.retain(|s| s.name != session_name);
    if mux.tmux.len() == before {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to kill tmux session" })),
        )
            .into_response();
    }

    Json(serde_json::json!({ "success": true })).into_response()
}

async fn api_tmux_context() -> impl IntoResponse {
    let inside_tmux = std::env::var("TMUX").is_ok();
    let current_session = if inside_tmux {
        ProcessCommand::new("tmux")
            .args(["display-message", "-p", "#{session_name}"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    Json(serde_json::json!({
        "insideTmux": inside_tmux,
        "currentSession": current_session,
    }))
    .into_response()
}

async fn api_remotes_list(State(state): State<AppState>) -> impl IntoResponse {
    if !state.config.is_hq_mode {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Not running in HQ mode" })),
        )
            .into_response();
    }

    let remotes = state.remote_registry.lock().await.clone();
    Json(remotes).into_response()
}

async fn api_remotes_register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRemoteRequest>,
) -> impl IntoResponse {
    if !state.config.is_hq_mode {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Not running in HQ mode" })),
        )
            .into_response();
    }

    let Some(id) = payload.id.filter(|v| !v.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields: id, name, url, token" })),
        )
            .into_response();
    };
    let Some(name) = payload.name.filter(|v| !v.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields: id, name, url, token" })),
        )
            .into_response();
    };
    let Some(url) = payload.url.filter(|v| !v.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields: id, name, url, token" })),
        )
            .into_response();
    };
    let Some(token) = payload.token.filter(|v| !v.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields: id, name, url, token" })),
        )
            .into_response();
    };

    let now = now_iso();
    let mut registry = state.remote_registry.lock().await;
    if registry.iter().any(|r| r.name == name) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("Remote with name '{name}' is already registered"),
            })),
        )
            .into_response();
    }

    let remote = RemoteServerEntry {
        id,
        name,
        url,
        token,
        registered_at: now.clone(),
        last_heartbeat: now,
        session_ids: Vec::new(),
    };

    registry.push(remote.clone());

    Json(serde_json::json!({
        "success": true,
        "remote": remote,
    }))
    .into_response()
}

async fn api_remotes_delete(
    State(state): State<AppState>,
    AxumPath(remote_id): AxumPath<String>,
) -> impl IntoResponse {
    if !state.config.is_hq_mode {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Not running in HQ mode" })),
        )
            .into_response();
    }

    let mut registry = state.remote_registry.lock().await;
    let before = registry.len();
    registry.retain(|r| r.id != remote_id);

    if registry.len() == before {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Remote not found" })),
        )
            .into_response();
    }

    Json(serde_json::json!({ "success": true })).into_response()
}

async fn api_remotes_refresh_sessions(
    State(state): State<AppState>,
    AxumPath(remote_name): AxumPath<String>,
    Json(payload): Json<RefreshRemoteSessionsRequest>,
) -> impl IntoResponse {
    if !state.config.is_hq_mode {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Not running in HQ mode" })),
        )
            .into_response();
    }

    let _action = payload.action;
    let _session_id = payload.session_id;

    let mut registry = state.remote_registry.lock().await;
    let Some(remote) = registry.iter_mut().find(|r| r.name == remote_name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Remote not found" })),
        )
            .into_response();
    };

    remote.last_heartbeat = now_iso();

    Json(serde_json::json!({
        "success": true,
        "sessionCount": remote.session_ids.len(),
    }))
    .into_response()
}

async fn api_auth_tailscale_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    let auth_ctx = authenticate_headers(&state.config, &headers, None, Some(remote_addr));

    if auth_ctx.auth_method != Some("tailscale") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "This endpoint is only available for Tailscale authenticated users"
                    .to_string(),
            }),
        )
            .into_response();
    }

    let Some(user_id) = auth_ctx.user_id else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "No user ID found in Tailscale authentication".to_string(),
            }),
        )
            .into_response();
    };

    let token = format!("tailscale.{}", uuid_like());
    Json(serde_json::json!({
        "success": true,
        "token": token,
        "userId": user_id,
        "authMethod": "tailscale",
        "expiresIn": "24h"
    }))
    .into_response()
}

async fn api_list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let sessions = state.sessions.lock().await.clone();
    let processes = state.local_processes.lock().await;

    let list = sessions
        .into_iter()
        .map(|session| {
            let pid = processes.get(&session.id).map(|p| p.pid);
            let mut value = serde_json::to_value(session).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(map) = value.as_object_mut() {
                map.insert(
                    "pid".to_string(),
                    pid.map_or(serde_json::Value::Null, |id| serde_json::json!(id)),
                );
            }
            value
        })
        .collect::<Vec<_>>();

    Json(list)
}

async fn read_child_output_to_ws(
    state: AppState,
    session_id: String,
    mut reader: impl AsyncRead + Unpin,
) {
    let mut buf = vec![0u8; 8192];

    loop {
        let read = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        let chunk = &buf[..read];
        {
            let mut outputs = state.session_outputs.lock().await;
            outputs
                .entry(session_id.clone())
                .or_default()
                .extend_from_slice(chunk);
        }

        broadcast_to_session(
            &state,
            &session_id,
            WsV3MessageType::Stdout,
            chunk.to_vec(),
        )
        .await;
    }
}

fn signal_pid(pid: u32, signal: Option<&str>) {
    if pid == 0 {
        return;
    }

    let normalized = signal.map(str::trim).unwrap_or("TERM").to_ascii_uppercase();
    let sig = match normalized.as_str() {
        "SIGKILL" | "KILL" => "-KILL",
        "SIGINT" | "INT" => "-INT",
        "SIGWINCH" | "WINCH" => "-WINCH",
        "SIGTERM" | "TERM" | "" => "-TERM",
        _ => "-TERM",
    };

    let _ = ProcessCommand::new("kill")
        .arg(sig)
        .arg(pid.to_string())
        .status();
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

async fn finalize_session_exit(state: AppState, session_id: String, exit_code: i32) {
    let mut session_name = String::new();
    let mut command = String::new();
    let now = now_iso();

    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id.as_str()) {
            session.status = "exited".to_string();
            session.last_modified = now.clone();
            session.exit_code = Some(exit_code);
            session_name = session.name.clone();
            command = session.command.join(" ");
        }
    }

    state.local_processes.lock().await.remove(&session_id);
    if let Some(handle) = state.git_watchers.lock().await.remove(&session_id) {
        handle.abort();
    }

    let session_event_payload = serde_json::to_vec(&serde_json::json!({
        "kind": "exit",
        "sessionId": session_id,
        "exitCode": exit_code,
        "timestamp": now,
    }))
    .unwrap_or_default();
    broadcast_to_session(
        &state,
        &session_id,
        WsV3MessageType::Event,
        session_event_payload,
    )
    .await;

    let global_event_payload = serde_json::to_vec(&serde_json::json!({
        "type": "session-exit",
        "sessionId": session_id,
        "sessionName": session_name,
        "command": command,
        "exitCode": exit_code,
        "timestamp": now,
    }))
    .unwrap_or_default();
    broadcast_to_session(&state, "", WsV3MessageType::Event, global_event_payload).await;
}

async fn spawn_local_session_process(
    state: &AppState,
    session_id: &str,
    command: &[String],
    working_dir: &str,
) -> Result<()> {
    if command.is_empty() {
        return Err(anyhow!("Command array is required"));
    }

    let command_line = command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ");

    let (initial_cols, initial_rows) = {
        let dimensions = state.session_dimensions.lock().await;
        dimensions
            .get(session_id)
            .copied()
            .unwrap_or((80, 24))
    };
    let initial_cols = initial_cols.clamp(20, 1000) as u16;
    let initial_rows = initial_rows.clamp(10, 1000) as u16;

    // Ensure child process starts with a safe PTY size (critical for TUI startup)
    // before the first client-side resize arrives.
    let stty_prefix = format!("stty cols {} rows {} 2>/dev/null;", initial_cols, initial_rows);
    let command_line = format!("{} {}", stty_prefix, command_line);

    let mut child = TokioCommand::new("script")
        .arg("-q")
        .arg("-e")
        .arg("-c")
        .arg(command_line)
        .arg("/dev/null")
        .current_dir(working_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn local session process")?;

    let pid = child.id().unwrap_or(0);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdin = child.stdin.take();

    if let Some(stdout) = stdout {
        let state_clone = state.clone();
        let session_id_clone = session_id.to_string();
        tokio::spawn(async move {
            read_child_output_to_ws(state_clone, session_id_clone, stdout).await;
        });
    }

    if let Some(stderr) = stderr {
        let state_clone = state.clone();
        let session_id_clone = session_id.to_string();
        tokio::spawn(async move {
            read_child_output_to_ws(state_clone, session_id_clone, stderr).await;
        });
    }

    {
        let mut processes = state.local_processes.lock().await;
        processes.insert(
            session_id.to_string(),
            LocalSessionProcess {
                stdin,
                pid,
                cols: initial_cols,
                rows: initial_rows,
            },
        );
    }

    let state_clone = state.clone();
    let session_id_clone = session_id.to_string();
    tokio::spawn(async move {
        let exit_code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(0),
            Err(_) => 1,
        };

        finalize_session_exit(state_clone, session_id_clone, exit_code).await;
    });

    Ok(())
}

async fn ensure_git_watcher_for_session(state: &AppState, session_id: &str) {
    {
        let watchers = state.git_watchers.lock().await;
        if watchers.contains_key(session_id) {
            return;
        }
    }

    let session = {
        let sessions = state.sessions.lock().await;
        sessions.iter().find(|s| s.id == session_id).cloned()
    };
    let Some(session) = session else {
        return;
    };

    let session_id_owned = session_id.to_string();
    let working_dir = session.working_dir.clone();
    let state_for_task = state.clone();

    let handle = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(2));
        let mut last: Option<(u32, u32, u32, u32, u32)> = None;

        loop {
            tick.tick().await;

            let is_running = {
                let sessions = state_for_task.sessions.lock().await;
                sessions
                    .iter()
                    .any(|s| s.id == session_id_owned && s.status == "running")
            };
            if !is_running {
                break;
            }

            let has_subscribers = {
                let subs = state_for_task.session_subscriptions.lock().await;
                subs.get(&session_id_owned)
                    .map(|socket_flags| {
                        socket_flags
                            .values()
                            .any(|flags| flags & (WsV3SubscribeFlags::Events as u32) != 0)
                    })
                    .unwrap_or(false)
            };
            if !has_subscribers {
                break;
            }

            let Some(counts) = git_status_counts_for_directory(Path::new(&working_dir)) else {
                break;
            };

            if last == Some(counts) {
                continue;
            }
            last = Some(counts);

            {
                let mut sessions = state_for_task.sessions.lock().await;
                if let Some(s) = sessions.iter_mut().find(|s| s.id == session_id_owned) {
                    s.git_modified_count = Some(counts.0);
                    s.git_added_count = Some(counts.1);
                    s.git_deleted_count = Some(counts.2);
                    s.git_ahead_count = Some(counts.3);
                    s.git_behind_count = Some(counts.4);
                }
            }

            let event_payload = serde_json::to_vec(&serde_json::json!({
                "type": "git-status-update",
                "sessionId": session_id_owned,
                "gitModifiedCount": counts.0,
                "gitAddedCount": counts.1,
                "gitDeletedCount": counts.2,
                "gitAheadCount": counts.3,
                "gitBehindCount": counts.4,
            }))
            .unwrap_or_default();
            broadcast_to_session(
                &state_for_task,
                &session_id_owned,
                WsV3MessageType::Event,
                event_payload,
            )
            .await;
        }

        state_for_task.git_watchers.lock().await.remove(&session_id_owned);
    });

    state
        .git_watchers
        .lock()
        .await
        .insert(session_id.to_string(), handle);
}

async fn api_create_session(
    State(state): State<AppState>,
    Json(payload): Json<SessionCreateRequest>,
) -> impl IntoResponse {
    if payload.command.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Command array is required".to_string(),
            }),
        )
            .into_response();
    }

    let id = uuid_like();
    let now = now_iso();
    let command = payload.command;

    let fallback_working_dir = std::env::current_dir()
        .unwrap_or_default()
        .display()
        .to_string();
    let working_dir_input = payload.working_dir.unwrap_or_default();
    let mut working_dir = if working_dir_input.trim().is_empty() {
        fallback_working_dir.clone()
    } else {
        resolve_absolute_path(&working_dir_input)
            .to_string_lossy()
            .to_string()
    };
    if !Path::new(&working_dir).is_dir() {
        working_dir = fallback_working_dir.clone();
    }

    let session_name = payload.name.unwrap_or_else(|| command.join(" "));
    let command_text = command.join(" ");

    let requested_cols = payload.cols.unwrap_or(80).clamp(20, 1000);
    let requested_rows = payload.rows.unwrap_or(24).clamp(10, 1000);

    state
        .session_dimensions
        .lock()
        .await
        .insert(id.clone(), (u32::from(requested_cols), u32::from(requested_rows)));
    let initial_cols: Option<u16> = Some(requested_cols);
    let initial_rows: Option<u16> = Some(requested_rows);

    let entry = SessionEntry {
        id: id.clone(),
        name: session_name.clone(),
        command: command.clone(),
        working_dir: working_dir.clone(),
        status: "running".to_string(),
        started_at: now.clone(),
        last_modified: now.clone(),
        initial_cols,
        initial_rows,
        exit_code: None,
        git_modified_count: None,
        git_added_count: None,
        git_deleted_count: None,
        git_ahead_count: None,
        git_behind_count: None,
    };

    state.sessions.lock().await.push(entry);

    {
        let mut outputs = state.session_outputs.lock().await;
        outputs.entry(id.clone()).or_default();
    }

    if let Err(error) = spawn_local_session_process(&state, &id, &command, &working_dir).await {
        state.session_dimensions.lock().await.remove(&id);
        state.session_outputs.lock().await.remove(&id);

        let mut sessions = state.sessions.lock().await;
        if let Some(position) = sessions.iter().position(|s| s.id == id) {
            sessions.remove(position);
        }

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to create session",
                "details": error.to_string(),
            })),
        )
            .into_response();
    }

    let event_payload = serde_json::to_vec(&serde_json::json!({
        "type": "session-start",
        "sessionId": id,
        "sessionName": session_name,
        "command": command_text,
        "timestamp": now,
    }))
    .unwrap_or_default();
    broadcast_to_session(&state, "", WsV3MessageType::Event, event_payload).await;

    Json(SessionCreateResponse {
        session_id: id,
        created_at: now,
        message: None,
    })
    .into_response()
}

async fn api_get_session(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.iter().find(|s| s.id == session_id).cloned() {
        let pid = {
            let processes = state.local_processes.lock().await;
            processes.get(&session_id).map(|p| p.pid)
        };

        let mut value = serde_json::to_value(session).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(map) = value.as_object_mut() {
            map.insert(
                "pid".to_string(),
                pid.map_or(serde_json::Value::Null, |id| serde_json::json!(id)),
            );
        }
        return Json(value).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Session not found".to_string(),
        }),
    )
        .into_response()
}

async fn api_delete_session(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let mut sessions = state.sessions.lock().await;
    if let Some(position) = sessions.iter().position(|s| s.id == session_id) {
        let removed = sessions.remove(position);
        drop(sessions);

        if let Some(mut proc) = state.local_processes.lock().await.remove(&session_id) {
            let _ = proc.stdin.take();
            signal_pid(proc.pid, Some("KILL"));
        }

        state.session_outputs.lock().await.remove(&session_id);
        state.session_subscriptions.lock().await.remove(&session_id);
        state.session_dimensions.lock().await.remove(&session_id);
        if let Some(handle) = state.git_watchers.lock().await.remove(&session_id) {
            handle.abort();
        }

        let event_payload = serde_json::to_vec(&serde_json::json!({
            "type": "session-exit",
            "sessionId": session_id,
            "sessionName": removed.name,
            "command": removed.command.join(" "),
            "exitCode": 0,
            "timestamp": now_iso(),
        }))
        .unwrap_or_default();
        broadcast_to_session(&state, "", WsV3MessageType::Event, event_payload).await;

        return Json(serde_json::json!({ "success": true, "message": "Session killed" }))
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Session not found".to_string(),
        }),
    )
        .into_response()
}

async fn api_session_input(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(payload): Json<SessionInputRequest>,
) -> impl IntoResponse {
    let sessions = state.sessions.lock().await;
    let exists = sessions
        .iter()
        .any(|s| s.id == session_id && s.status == "running");
    drop(sessions);

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    let text_set = payload.text.is_some();
    let key_set = payload.key.is_some();
    if (text_set && key_set) || (!text_set && !key_set) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Either text or key must be provided, but not both".to_string(),
            }),
        )
            .into_response();
    }

    let emitted: Vec<u8> = if let Some(text) = payload.text {
        text.into_bytes()
    } else if let Some(key) = payload.key {
        decode_input_key(key.as_bytes())
            .map(|mapped| mapped.into_bytes())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    if emitted.is_empty() {
        return Json(serde_json::json!({ "success": true })).into_response();
    }

    let mut stdin_written = false;
    {
        let mut processes = state.local_processes.lock().await;
        if let Some(process) = processes.get_mut(&session_id) {
            if let Some(stdin) = process.stdin.as_mut() {
                if stdin.write_all(&emitted).await.is_ok() && stdin.flush().await.is_ok() {
                    stdin_written = true;
                }
            }
        }
    }

    if !stdin_written {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session is not running".to_string(),
            }),
        )
            .into_response();
    }

    Json(serde_json::json!({ "success": true })).into_response()
}

async fn api_session_resize(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(payload): Json<SessionResizeRequest>,
) -> impl IntoResponse {
    let sessions = state.sessions.lock().await;
    let exists = sessions
        .iter()
        .any(|s| s.id == session_id && s.status == "running");
    drop(sessions);

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    let (cols, rows) = match (payload.cols, payload.rows) {
        (Some(c), Some(r)) => (c, r),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cols and rows must be numbers".to_string(),
                }),
            )
                .into_response();
        }
    };

    if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cols and rows must be between 1 and 1000".to_string(),
            }),
        )
            .into_response();
    }

    let cols = cols.max(20);
    let rows = rows.max(10);

    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id.as_str()) {
            session.initial_cols = Some(cols);
            session.initial_rows = Some(rows);
            session.last_modified = now_iso();
        }
    }

    state
        .session_dimensions
        .lock()
        .await
        .insert(session_id.clone(), (u32::from(cols), u32::from(rows)));

    {
        let mut processes = state.local_processes.lock().await;
        if let Some(process) = processes.get_mut(&session_id) {
            process.cols = cols;
            process.rows = rows;

            let _ = ProcessCommand::new("kill")
                .arg("-WINCH")
                .arg(process.pid.to_string())
                .status();
        }
    }

    Json(serde_json::json!({ "success": true, "cols": cols, "rows": rows })).into_response()
}

async fn api_cleanup_session(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let mut sessions = state.sessions.lock().await;
    if let Some(position) = sessions.iter().position(|s| s.id == session_id) {
        let removed = sessions.remove(position);
        drop(sessions);

        if let Some(mut proc) = state.local_processes.lock().await.remove(&session_id) {
            let _ = proc.stdin.take();
            signal_pid(proc.pid, Some("KILL"));
        }

        state.session_outputs.lock().await.remove(&session_id);
        state.session_subscriptions.lock().await.remove(&session_id);
        state.session_dimensions.lock().await.remove(&session_id);
        if let Some(handle) = state.git_watchers.lock().await.remove(&session_id) {
            handle.abort();
        }

        let event_payload = serde_json::to_vec(&serde_json::json!({
            "type": "session-exit",
            "sessionId": session_id,
            "sessionName": removed.name,
            "command": removed.command.join(" "),
            "exitCode": 0,
            "timestamp": now_iso(),
        }))
        .unwrap_or_default();
        broadcast_to_session(&state, "", WsV3MessageType::Event, event_payload).await;

        return Json(serde_json::json!({ "success": true, "message": "Session cleaned up" }))
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Session not found".to_string(),
        }),
    )
        .into_response()
}

async fn api_cleanup_exited(State(state): State<AppState>) -> impl IntoResponse {
    let mut sessions = state.sessions.lock().await;
    let before = sessions.len();

    let exited_ids: Vec<String> = sessions
        .iter()
        .filter(|s| s.status == "exited")
        .map(|s| s.id.clone())
        .collect();

    let exited_snapshot: Vec<(String, String, String)> = sessions
        .iter()
        .filter(|s| s.status == "exited")
        .map(|s| (s.id.clone(), s.name.clone(), s.command.join(" ")))
        .collect();

    sessions.retain(|s| s.status != "exited");
    let cleaned = before.saturating_sub(sessions.len());
    drop(sessions);

    if !exited_ids.is_empty() {
        let mut outputs = state.session_outputs.lock().await;
        let mut subscriptions = state.session_subscriptions.lock().await;
        let mut dimensions = state.session_dimensions.lock().await;

        for (session_id, session_name, command) in exited_snapshot {
            outputs.remove(&session_id);
            subscriptions.remove(&session_id);
            dimensions.remove(&session_id);
            if let Some(mut proc) = state.local_processes.lock().await.remove(&session_id) {
                let _ = proc.stdin.take();
                signal_pid(proc.pid, Some("KILL"));
            }
            if let Some(handle) = state.git_watchers.lock().await.remove(&session_id) {
                handle.abort();
            }

            let event_payload = serde_json::to_vec(&serde_json::json!({
                "type": "session-exit",
                "sessionId": session_id,
                "sessionName": session_name,
                "command": command,
                "exitCode": 0,
                "timestamp": now_iso(),
            }))
            .unwrap_or_default();
            broadcast_to_session(&state, "", WsV3MessageType::Event, event_payload).await;
        }
    }

    Json(serde_json::json!({
        "success": true,
        "message": format!("{} exited sessions cleaned up across all servers", cleaned),
        "localCleaned": cleaned,
        "remoteResults": []
    }))
}

async fn api_session_text(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let sessions = state.sessions.lock().await;
    let exists = sessions.iter().any(|s| s.id == session_id);
    drop(sessions);

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    let text = {
        let outputs = state.session_outputs.lock().await;
        let bytes = outputs.get(&session_id).cloned().unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    };

    ([(header::CONTENT_TYPE, "text/plain")], text).into_response()
}

async fn api_patch_session(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(payload): Json<SessionPatchRequest>,
) -> impl IntoResponse {
    let Some(name) = payload.name else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Name must be a non-empty string".to_string(),
            }),
        )
            .into_response();
    };

    if name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Name must be a non-empty string".to_string(),
            }),
        )
            .into_response();
    }

    let mut sessions = state.sessions.lock().await;
    if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
        session.name = name.clone();
        session.last_modified = now_iso();
        return Json(serde_json::json!({ "success": true, "name": name })).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Session not found".to_string(),
        }),
    )
        .into_response()
}

async fn api_reset_session_size(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let sessions = state.sessions.lock().await;
    let exists = sessions
        .iter()
        .any(|s| s.id == session_id && s.status == "running");
    drop(sessions);

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id.as_str()) {
            session.initial_cols = None;
            session.initial_rows = None;
            session.last_modified = now_iso();
        }
    }

    state.session_dimensions.lock().await.remove(&session_id);

    Json(serde_json::json!({ "success": true })).into_response()
}

async fn api_session_git_status(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let session = {
        let sessions = state.sessions.lock().await;
        sessions.iter().find(|s| s.id == session_id).cloned()
    };

    let Some(session) = session else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Session not found" })),
        )
            .into_response();
    };

    let working_dir = PathBuf::from(&session.working_dir);
    if let Some(status) = get_git_status_for_directory(&working_dir) {
        let git_modified_count = status
            .get("modified")
            .and_then(|v| v.as_array())
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        let git_added_count = status
            .get("added")
            .and_then(|v| v.as_array())
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        let git_deleted_count = status
            .get("deleted")
            .and_then(|v| v.as_array())
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        let git_ahead_count = status
            .get("ahead")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0);
        let git_behind_count = status
            .get("behind")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0);

        {
            let mut sessions = state.sessions.lock().await;
            if let Some(s) = sessions.iter_mut().find(|s| s.id == session_id) {
                s.git_modified_count = Some(git_modified_count);
                s.git_added_count = Some(git_added_count);
                s.git_deleted_count = Some(git_deleted_count);
                s.git_ahead_count = Some(git_ahead_count);
                s.git_behind_count = Some(git_behind_count);
            }
        }

        let event_payload = serde_json::to_vec(&serde_json::json!({
            "type": "git-status-update",
            "sessionId": session_id,
            "gitModifiedCount": git_modified_count,
            "gitAddedCount": git_added_count,
            "gitDeletedCount": git_deleted_count,
            "gitAheadCount": git_ahead_count,
            "gitBehindCount": git_behind_count,
        }))
        .unwrap_or_default();
        broadcast_to_session(
            &state,
            &session_id,
            WsV3MessageType::Event,
            event_payload,
        )
        .await;

        Json(status).into_response()
    } else {
        Json(serde_json::json!({
            "isGitRepo": false,
            "branch": serde_json::Value::Null,
            "modified": [],
            "added": [],
            "deleted": [],
            "untracked": [],
            "ahead": 0,
            "behind": 0,
        }))
        .into_response()
    }
}

async fn api_test_notification(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let payload = serde_json::to_vec(&serde_json::json!({
        "type": "test-notification",
        "sessionId": "test-session",
        "sessionName": "Test Notification",
        "timestamp": now_iso(),
        "message": "This is a test notification from VibeTunnel server",
        "title": "VibeTunnel Test",
        "body": "Server-side notifications are working correctly!",
    }))
    .unwrap_or_default();

    let targets: Vec<String> = {
        let subs = state.session_subscriptions.lock().await;
        subs.get("")
            .map(|sockets| {
                sockets
                    .iter()
                    .filter_map(|(socket_id, flags)| {
                        if flags & (WsV3SubscribeFlags::Events as u32) == 0 {
                            return None;
                        }
                        Some(socket_id.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    if !targets.is_empty() {
        let frame = encode_frame(&WsV3Frame {
            ty: WsV3MessageType::Event,
            session_id: String::new(),
            payload: payload.clone(),
        });

        let clients = state.ws_clients.lock().await;
        for socket_id in targets {
            if let Some(tx) = clients.get(&socket_id) {
                let _ = tx.send(frame.clone());
            }
        }
    }

    Json(serde_json::json!({
        "success": true,
        "message": "Test notification sent through global WS event channel"
    }))
}

async fn api_not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "API endpoint not found".to_string(),
        }),
    )
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<WsQuery>,
) -> impl IntoResponse {
    let auth_ctx = if state.config.no_auth {
        AuthContext {
            user_id: Some("no-auth-user".to_string()),
            auth_method: Some("no-auth"),
            is_hq_request: false,
        }
    } else {
        authenticate_headers(
            &state.config,
            &headers,
            query
                .token
                .as_deref()
                .or(query.local_auth_token.as_deref()),
            Some(remote_addr),
        )
    };

    if auth_ctx.user_id.is_none() && !auth_ctx.is_hq_request {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    ws.on_upgrade(move |socket| async move {
        handle_ws(socket, state, auth_ctx).await;
    })
}

async fn handle_ws(
    socket: axum::extract::ws::WebSocket,
    state: AppState,
    auth_ctx: AuthContext,
) {
    let stdout_flag = WsV3SubscribeFlags::Stdout as u32;
    let snapshots_flag = WsV3SubscribeFlags::Snapshots as u32;
    let events_flag = WsV3SubscribeFlags::Events as u32;
    let (mut sender, mut receiver) = socket.split();

    let welcome_payload = serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "version": 3,
        "authMethod": auth_ctx.auth_method,
    }))
    .unwrap_or_default();
    let welcome_frame = encode_frame(&WsV3Frame {
        ty: WsV3MessageType::Welcome,
        session_id: String::new(),
        payload: welcome_payload,
    });
    let _ = sender.send(Message::Binary(welcome_frame.into())).await;

    let socket_id = uuid_like();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    {
        let mut clients = state.ws_clients.lock().await;
        clients.insert(socket_id.clone(), tx.clone());
    }

    let send_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sender.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
    });

    let mut ping_tick = interval_at(
        TokioInstant::now() + Duration::from_secs(20),
        Duration::from_secs(20),
    );

    loop {
        tokio::select! {
            _ = ping_tick.tick() => {
                let ping = encode_frame(&WsV3Frame {
                    ty: WsV3MessageType::Ping,
                    session_id: String::new(),
                    payload: b"ping".to_vec(),
                });
                if tx.send(ping).is_err() {
                    break;
                }
            }
            incoming = receiver.next() => {
                let Some(Ok(message)) = incoming else {
                    break;
                };

                let Message::Binary(binary) = message else {
                    continue;
                };

                let Some(frame) = decode_frame(binary.as_ref()) else {
                    continue;
                };

                match frame.ty {
                    WsV3MessageType::Ping => {
                        let pong = encode_frame(&WsV3Frame {
                            ty: WsV3MessageType::Pong,
                            session_id: frame.session_id,
                            payload: frame.payload,
                        });
                        if tx.send(pong).is_err() {
                            break;
                        }
                    }
                    WsV3MessageType::Subscribe => {
                        let Some(flags) = decode_subscribe_payload(&frame.payload).map(|p| p.flags)
                        else {
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id: frame.session_id,
                                payload: serde_json::to_vec(&serde_json::json!({
                                    "message": "Invalid SUBSCRIBE payload"
                                }))
                                .unwrap_or_default(),
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                            continue;
                        };

                        if frame.session_id.is_empty() {
                            {
                                let mut subs = state.session_subscriptions.lock().await;
                                let sockets = subs.entry(String::new()).or_default();
                                sockets.insert(socket_id.clone(), flags);
                            }

                            if flags & events_flag == 0 {
                                continue;
                            }

                            let connected_payload = serde_json::to_vec(
                                &serde_json::json!({ "type": "connected", "timestamp": now_iso() }),
                            )
                            .unwrap_or_default();
                            let ack = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Event,
                                session_id: String::new(),
                                payload: connected_payload,
                            });
                            if tx.send(ack).is_err() {
                                break;
                            }
                            continue;
                        }

                        let sessions = state.sessions.lock().await;
                        let exists = sessions.iter().any(|s| s.id == frame.session_id);
                        drop(sessions);

                        if !exists {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Session not found" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id: frame.session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                            continue;
                        }

                        {
                            let mut subs = state.session_subscriptions.lock().await;
                            let sockets = subs.entry(frame.session_id.clone()).or_default();
                            sockets.insert(socket_id.clone(), flags);
                        }

                        if flags & events_flag != 0 {
                            let connected_payload = serde_json::to_vec(
                                &serde_json::json!({
                                    "type": "connected",
                                    "sessionId": frame.session_id,
                                    "timestamp": now_iso()
                                }),
                            )
                            .unwrap_or_default();
                            let ack = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Event,
                                session_id: frame.session_id.clone(),
                                payload: connected_payload,
                            });
                            if tx.send(ack).is_err() {
                                break;
                            }

                            ensure_git_watcher_for_session(&state, &frame.session_id).await;
                        }

                        if flags & stdout_flag != 0 {
                            let output = {
                                let outputs = state.session_outputs.lock().await;
                                outputs.get(&frame.session_id).cloned().unwrap_or_default()
                            };

                            if !output.is_empty() {
                                let stdout = encode_frame(&WsV3Frame {
                                    ty: WsV3MessageType::Stdout,
                                    session_id: frame.session_id.clone(),
                                    payload: output,
                                });
                                if tx.send(stdout).is_err() {
                                    break;
                                }
                            }
                        }

                        if flags & snapshots_flag != 0 {
                            let output = {
                                let outputs = state.session_outputs.lock().await;
                                outputs.get(&frame.session_id).cloned().unwrap_or_default()
                            };
                            let (cols, rows) = {
                                let processes = state.local_processes.lock().await;
                                if let Some(process) = processes.get(&frame.session_id) {
                                    (u32::from(process.cols), u32::from(process.rows))
                                } else {
                                    drop(processes);
                                    let dimensions = state.session_dimensions.lock().await;
                                    dimensions
                                        .get(&frame.session_id)
                                        .copied()
                                        .unwrap_or((80, 24))
                                }
                            };

                            let snapshot_payload = encode_snapshot_from_output(&output, cols, rows);
                            let snapshot_frame = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::SnapshotVt,
                                session_id: frame.session_id.clone(),
                                payload: snapshot_payload,
                            });
                            if tx.send(snapshot_frame).is_err() {
                                break;
                            }
                        }
                    }
                    WsV3MessageType::Unsubscribe => {
                        let session_id = frame.session_id;

                        let mut should_stop_watcher = false;
                        {
                            let mut subs = state.session_subscriptions.lock().await;
                            if let Some(sockets) = subs.get_mut(&session_id) {
                                sockets.remove(&socket_id);
                                if sockets.is_empty() {
                                    subs.remove(&session_id);
                                    should_stop_watcher = !session_id.is_empty();
                                } else if !session_id.is_empty() {
                                    should_stop_watcher = !sockets
                                        .values()
                                        .any(|flags| flags & events_flag != 0);
                                }
                            }
                        }

                        if should_stop_watcher {
                            if let Some(handle) = state.git_watchers.lock().await.remove(&session_id) {
                                handle.abort();
                            }
                        }
                    }
                    WsV3MessageType::InputText | WsV3MessageType::InputKey => {
                        if frame.session_id.is_empty() {
                            continue;
                        }

                        let session_id = frame.session_id;

                        let sessions = state.sessions.lock().await;
                        let exists = sessions
                            .iter()
                            .any(|s| s.id == session_id && s.status == "running");
                        drop(sessions);

                        if !exists {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Session not found" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                            continue;
                        }

                        let emitted: Vec<u8> = match frame.ty {
                            WsV3MessageType::InputText => frame.payload,
                            WsV3MessageType::InputKey => decode_input_key(&frame.payload)
                                .map(|s| s.into_bytes())
                                .unwrap_or_default(),
                            _ => Vec::new(),
                        };

                        if emitted.is_empty() {
                            continue;
                        }

                        let mut stdin_written = false;
                        {
                            let mut processes = state.local_processes.lock().await;
                            if let Some(process) = processes.get_mut(&session_id) {
                                if let Some(stdin) = process.stdin.as_mut() {
                                    if stdin.write_all(&emitted).await.is_ok()
                                        && stdin.flush().await.is_ok()
                                    {
                                        stdin_written = true;
                                    }
                                }
                            }
                        }

                        if !stdin_written {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Session is not running" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                        }
                    }
                    WsV3MessageType::Kill => {
                        if frame.session_id.is_empty() {
                            continue;
                        }

                        let session_id = frame.session_id;

                        let exists = {
                            let sessions = state.sessions.lock().await;
                            sessions
                                .iter()
                                .any(|s| s.id == session_id && s.status == "running")
                        };

                        if !exists {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Session not found" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                            continue;
                        }

                        let signal = String::from_utf8(frame.payload)
                            .ok()
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or_else(|| "TERM".to_string());

                        let mut processes = state.local_processes.lock().await;
                        if let Some(process) = processes.get_mut(&session_id) {
                            let normalized = signal.trim().to_ascii_uppercase();
                            if normalized == "WINCH" || normalized == "SIGWINCH" {
                                let _ = ProcessCommand::new("kill")
                                    .arg("-WINCH")
                                    .arg(process.pid.to_string())
                                    .status();
                            } else {
                                let _ = process.stdin.take();
                                signal_pid(process.pid, Some(signal.as_str()));
                            }
                        }
                    }
                    WsV3MessageType::Resize => {
                        if frame.session_id.is_empty() {
                            continue;
                        }

                        let session_id = frame.session_id;
                        let payload = frame.payload;

                        let sessions = state.sessions.lock().await;
                        let exists = sessions
                            .iter()
                            .any(|s| s.id == session_id && s.status == "running");
                        drop(sessions);

                        if !exists {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Session not found" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                            continue;
                        }

                        if let Some(resize) = vibetunnel_rs::protocol::ws_v3::decode_resize_payload(&payload)
                        {
                            let safe_cols = resize.cols.clamp(20, 1000);
                            let safe_rows = resize.rows.clamp(10, 1000);

                            {
                                let mut sessions = state.sessions.lock().await;
                                if let Some(session) =
                                    sessions.iter_mut().find(|s| s.id == session_id.as_str())
                                {
                                    session.initial_cols = u16::try_from(safe_cols).ok();
                                    session.initial_rows = u16::try_from(safe_rows).ok();
                                    session.last_modified = now_iso();
                                }
                            }

                            state
                                .session_dimensions
                                .lock()
                                .await
                                .insert(session_id.clone(), (safe_cols, safe_rows));

                            {
                                let mut processes = state.local_processes.lock().await;
                                if let Some(process) = processes.get_mut(&session_id) {
                                    process.cols = safe_cols as u16;
                                    process.rows = safe_rows as u16;

                                    let _ = ProcessCommand::new("kill")
                                        .arg("-WINCH")
                                        .arg(process.pid.to_string())
                                        .status();
                                }
                            }

                            let event_payload = serde_json::to_vec(&serde_json::json!({
                                "kind": "resize",
                                "sessionId": session_id,
                                "dimensions": {
                                    "cols": safe_cols,
                                    "rows": safe_rows,
                                },
                            }))
                            .unwrap_or_default();
                            broadcast_to_session(
                                &state,
                                &session_id,
                                WsV3MessageType::Event,
                                event_payload,
                            )
                            .await;
                        } else {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Invalid resize payload" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                        }
                    }
                    WsV3MessageType::ResetSize => {
                        if frame.session_id.is_empty() {
                            continue;
                        }

                        let session_id = frame.session_id;

                        let sessions = state.sessions.lock().await;
                        let exists = sessions
                            .iter()
                            .any(|s| s.id == session_id && s.status == "running");
                        drop(sessions);

                        if !exists {
                            let err_payload = serde_json::to_vec(
                                &serde_json::json!({ "message": "Session not found" }),
                            )
                            .unwrap_or_default();
                            let err = encode_frame(&WsV3Frame {
                                ty: WsV3MessageType::Error,
                                session_id,
                                payload: err_payload,
                            });
                            if tx.send(err).is_err() {
                                break;
                            }
                            continue;
                        }

                        {
                            let mut sessions = state.sessions.lock().await;
                            if let Some(session) =
                                sessions.iter_mut().find(|s| s.id == session_id.as_str())
                            {
                                session.initial_cols = None;
                                session.initial_rows = None;
                                session.last_modified = now_iso();
                            }
                        }

                        state.session_dimensions.lock().await.remove(&session_id);

                        let event_payload = serde_json::to_vec(&serde_json::json!({
                            "kind": "reset-size",
                            "sessionId": session_id,
                            "dimensions": serde_json::Value::Null,
                        }))
                        .unwrap_or_default();
                        broadcast_to_session(
                            &state,
                            &session_id,
                            WsV3MessageType::Event,
                            event_payload,
                        )
                        .await;
                    }
                    WsV3MessageType::Hello
                    | WsV3MessageType::Welcome
                    | WsV3MessageType::Stdout
                    | WsV3MessageType::SnapshotVt
                    | WsV3MessageType::Event
                    | WsV3MessageType::Error
                    | WsV3MessageType::Pong
                    | WsV3MessageType::Unknown(_) => {
                        // ignored for parity scaffold
                    }
                }
            }
        }
    }

    send_task.abort();

    {
        let mut clients = state.ws_clients.lock().await;
        clients.remove(&socket_id);
    }

    let mut subs = state.session_subscriptions.lock().await;
    let mut empty_sessions = Vec::new();
    for (session_id, sockets) in subs.iter_mut() {
        sockets.remove(&socket_id);
        if sockets.is_empty() {
            empty_sessions.push(session_id.clone());
        }
    }
    for session_id in empty_sessions {
        subs.remove(&session_id);
    }
}

fn encode_snapshot_from_output(output: &[u8], cols: u32, rows: u32) -> Vec<u8> {
    let safe_cols = cols.clamp(1, 1000) as usize;
    let safe_rows = rows.clamp(1, 1000) as usize;

    let mut cells = vec![
        vec![snapshot::BufferCell {
            ch: " ".to_string(),
            width: 1,
            fg: None,
            bg: None,
            attributes: None,
        }; safe_cols];
        safe_rows
    ];

    let text = String::from_utf8_lossy(output);
    let mut x = 0usize;
    let mut y = 0usize;

    for ch in text.chars() {
        match ch {
            '\r' => {
                x = 0;
            }
            '\n' => {
                x = 0;
                if y + 1 < safe_rows {
                    y += 1;
                }
            }
            _ => {
                if y >= safe_rows {
                    break;
                }
                if x >= safe_cols {
                    x = 0;
                    if y + 1 < safe_rows {
                        y += 1;
                    } else {
                        break;
                    }
                }
                cells[y][x].ch = ch.to_string();
                x += 1;
            }
        }
    }

    let snapshot = snapshot::BufferSnapshot {
        cols: safe_cols as u32,
        rows: safe_rows as u32,
        viewport_y: 0,
        cursor_x: x.min(safe_cols.saturating_sub(1)) as i32,
        cursor_y: y.min(safe_rows.saturating_sub(1)) as i32,
        cells,
    };

    snapshot::encode_snapshot(&snapshot)
}

async fn broadcast_to_session(
    state: &AppState,
    session_id: &str,
    ty: WsV3MessageType,
    payload: Vec<u8>,
) {
    let required_flag = match ty {
        WsV3MessageType::Stdout => Some(WsV3SubscribeFlags::Stdout as u32),
        WsV3MessageType::SnapshotVt => Some(WsV3SubscribeFlags::Snapshots as u32),
        WsV3MessageType::Event => Some(WsV3SubscribeFlags::Events as u32),
        _ => None,
    };

    let targets: Vec<String> = {
        let subs = state.session_subscriptions.lock().await;
        let Some(sockets) = subs.get(session_id) else {
            return;
        };

        sockets
            .iter()
            .filter_map(|(socket_id, flags)| {
                if let Some(flag) = required_flag {
                    if flags & flag == 0 {
                        return None;
                    }
                }
                Some(socket_id.clone())
            })
            .collect()
    };

    if targets.is_empty() {
        return;
    }

    let frame = encode_frame(&WsV3Frame {
        ty,
        session_id: session_id.to_string(),
        payload,
    });

    let mut stale_clients = Vec::new();

    {
        let clients = state.ws_clients.lock().await;
        for socket_id in &targets {
            match clients.get(socket_id) {
                Some(tx) => {
                    if tx.send(frame.clone()).is_err() {
                        stale_clients.push(socket_id.clone());
                    }
                }
                None => {
                    stale_clients.push(socket_id.clone());
                }
            }
        }
    }

    if stale_clients.is_empty() {
        return;
    }

    {
        let mut clients = state.ws_clients.lock().await;
        for socket_id in &stale_clients {
            clients.remove(socket_id);
        }
    }

    {
        let mut subs = state.session_subscriptions.lock().await;
        if let Some(sockets) = subs.get_mut(session_id) {
            for socket_id in stale_clients {
                sockets.remove(&socket_id);
            }
            if sockets.is_empty() {
                subs.remove(session_id);
            }
        }
    }
}

fn embedded_asset_path(uri_path: &str) -> String {
    let trimmed = uri_path.trim_start_matches('/');
    if trimmed.is_empty() {
        "index.html".to_string()
    } else {
        trimmed.to_string()
    }
}

fn embedded_asset_response(asset_path: &str) -> Response {
    if let Some(content) = EmbeddedAssets::get(asset_path) {
        let mime_type = detect_mime_from_path(Path::new(asset_path));
        return ([(header::CONTENT_TYPE, mime_type)], content.data).into_response();
    }

    if let Some(not_found) = EmbeddedAssets::get("404.html") {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html")],
            not_found.data,
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Not found".to_string(),
        }),
    )
        .into_response()
}

async fn serve_index() -> impl IntoResponse {
    if let Some(html) = EmbeddedAssets::get("index.html") {
        return ([(header::CONTENT_TYPE, "text/html")], html.data).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "index.html not found".to_string(),
        }),
    )
        .into_response()
}

async fn serve_embedded_asset(uri: axum::http::Uri) -> impl IntoResponse {
    let asset_path = embedded_asset_path(uri.path());
    embedded_asset_response(&asset_path)
}

fn uuid_like() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_quick_start_commands_filters_invalid_items() {
        let value = serde_json::json!([
            {"name": "shell", "command": "zsh"},
            {"command": "  "},
            {"command": "pnpm run dev"},
            "invalid"
        ]);

        let parsed = parse_quick_start_commands(&value).expect("parse commands array");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name.as_deref(), Some("shell"));
        assert_eq!(parsed[0].command, "zsh");
        assert_eq!(parsed[1].name, None);
        assert_eq!(parsed[1].command, "pnpm run dev");
    }

    #[tokio::test]
    async fn parse_quick_start_commands_rejects_non_array() {
        let value = serde_json::json!({"command": "zsh"});
        assert!(parse_quick_start_commands(&value).is_none());
    }

    #[tokio::test]
    async fn parse_repository_base_path_requires_non_empty_string() {
        assert_eq!(
            parse_repository_base_path(&serde_json::json!("/tmp/repos")),
            Some("/tmp/repos".to_string())
        );
        assert_eq!(parse_repository_base_path(&serde_json::json!("   ")), None);
        assert_eq!(parse_repository_base_path(&serde_json::json!(123)), None);
    }

    #[tokio::test]
    async fn notification_patch_updates_only_provided_fields() {
        let current = NotificationPreferences::default();
        let patch = NotificationPreferencesPatch {
            enabled: Some(true),
            session_start: None,
            session_exit: None,
            command_completion: Some(false),
            command_error: None,
            bell: None,
            sound_enabled: Some(true),
            vibration_enabled: None,
        };

        let merged = apply_notification_preferences_patch(&current, patch);
        assert!(merged.enabled);
        assert!(!merged.command_completion);
        assert!(merged.sound_enabled);
        assert_eq!(merged.session_start, current.session_start);
        assert_eq!(merged.bell, current.bell);
    }

    #[tokio::test]
    async fn validate_avatar_user_id_blocks_path_traversal_chars() {
        assert!(validate_avatar_user_id("steve"));
        assert!(!validate_avatar_user_id("../../etc/passwd"));
        assert!(!validate_avatar_user_id(""));
        assert!(!validate_avatar_user_id("user name"));
    }

    #[tokio::test]
    async fn log_level_validation_matches_client_levels() {
        assert!(is_allowed_log_level("log"));
        assert!(is_allowed_log_level("info"));
        assert!(is_allowed_log_level("warn"));
        assert!(is_allowed_log_level("error"));
        assert!(is_allowed_log_level("debug"));
        assert!(!is_allowed_log_level("trace"));
    }

    #[tokio::test]
    async fn load_app_config_defaults_when_file_missing() {
        let home = std::env::temp_dir().join(format!("vt-rs-test-home-{}", uuid_like()));
        std::fs::create_dir_all(&home).expect("create temp home");
        std::env::set_var("HOME", &home);

        let loaded = load_app_config();
        assert_eq!(loaded.repository_base_path, "~/Documents");
        assert!(loaded.quick_start_commands.is_empty());
        assert!(loaded.notification_preferences.is_some());

        let _ = std::fs::remove_dir_all(home);
    }

    #[tokio::test]
    async fn install_and_uninstall_git_hooks_roundtrip_preserves_existing_hook() {
        let repo_root = std::env::temp_dir().join(format!("vt-rs-hook-test-{}", uuid_like()));
        let hooks_dir = repo_root.join(".git/hooks");
        std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");

        let post_commit_path = hooks_dir.join("post-commit");
        let original_hook = "#!/bin/sh\necho original\n";
        std::fs::write(&post_commit_path, original_hook).expect("write original hook");
        std::fs::set_permissions(&post_commit_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod original hook");

        let install_result = install_git_hooks(&repo_root);
        assert!(install_result.is_ok());
        assert!(are_hooks_installed(&repo_root));

        let installed_hook =
            std::fs::read_to_string(&post_commit_path).expect("read installed post-commit hook");
        assert!(installed_hook.contains("VibeTunnel Git hook"));
        assert!(installed_hook.contains(".vtbak"));

        let backup_path = hooks_dir.join("post-commit.vtbak");
        assert!(backup_path.exists());

        let uninstall_result = uninstall_git_hooks(&repo_root);
        assert!(uninstall_result.is_ok());

        let restored_hook =
            std::fs::read_to_string(&post_commit_path).expect("read restored post-commit hook");
        assert_eq!(restored_hook, original_hook);
        assert!(!backup_path.exists());

        let _ = std::fs::remove_dir_all(repo_root);
    }

}


#[allow(dead_code)]
fn _protocol_version() -> u8 {
    WS_V3_VERSION
}
