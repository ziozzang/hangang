use anyhow::{Context, Result, anyhow, bail};
use mlua::{ChunkMode, HookTriggers, Lua, LuaOptions, LuaSerdeExt, StdLib, Value, VmState};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    time::{Instant as TokioInstant, timeout},
};

const MAX_FRAME_BYTES: usize = 128 * 1024;
const MAX_SCRIPT_BYTES: usize = 16 * 1024;
const MAX_METHOD_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_DECISION_HEADERS: usize = 64;
const MAX_BACKEND_BYTES: usize = 1024;
const MAX_TRANSFORM_BODY_BYTES: usize = 16 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 8 * 1024;
const MAX_WORKERS: usize = 64;
const LUA_MEMORY_BYTES: usize = 8 * 1024 * 1024;
const LUA_DEADLINE: Duration = Duration::from_millis(25);
const HOOK_INTERVAL: u32 = 1_000;
const MAX_INSTRUCTIONS: usize = 100_000;
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_millis(200);
const RESTART_COOLDOWN: Duration = Duration::from_millis(25);

/// Local, fail-fast admission when every Lua worker is busy or restarting.
/// Callers can distinguish this from a script or worker execution failure
/// without inspecting an error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerCapacityUnavailable;

impl fmt::Display for WorkerCapacityUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("policy worker pool is saturated or restarting")
    }
}

impl std::error::Error for WorkerCapacityUnavailable {}

// Parent-side hard bound on a single worker operation. This is the effective
// deadline for Lua work that the in-VM 25ms instruction hook cannot interrupt —
// notably C-side string pattern matching (find/match/gmatch/gsub), which runs
// zero VM instructions. On expiry the parent SIGKILLs and respawns the worker.
// Operators fronting hostile traffic can lower it via --lua-timeout-ms to bound
// pattern-matching CPU amplification. Set once at startup in the parent.
static OPERATION_TIMEOUT_OVERRIDE: OnceLock<Duration> = OnceLock::new();

pub fn set_operation_timeout(timeout: Duration) {
    let _ = OPERATION_TIMEOUT_OVERRIDE.set(timeout);
}

fn operation_timeout() -> Duration {
    *OPERATION_TIMEOUT_OVERRIDE
        .get()
        .unwrap_or(&DEFAULT_OPERATION_TIMEOUT)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyInput {
    pub script: String,
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransformInput {
    pub script: String,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    pub phase: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub backend: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub reject: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
enum WorkerRequest {
    Evaluate(PolicyInput),
    Transform(TransformInput),
    Validate { script: String },
    Shutdown,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
enum WorkerResponse {
    Decision(Decision),
    Transformed(#[serde(with = "base64_bytes")] Vec<u8>),
    Validated,
    Error { message: String },
}

pub struct PolicyPool {
    executable: PathBuf,
    slots: Vec<Mutex<WorkerSlot>>,
    next_slot: AtomicUsize,
    closed: AtomicBool,
}

impl PolicyPool {
    pub fn new(executable: PathBuf, workers: usize) -> Self {
        let workers = workers.min(MAX_WORKERS);
        Self {
            executable,
            slots: (0..workers)
                .map(|_| Mutex::new(WorkerSlot::default()))
                .collect(),
            next_slot: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub async fn evaluate(&self, input: PolicyInput) -> Result<Decision> {
        validate_input(&input)?;
        match self.dispatch(WorkerRequest::Evaluate(input)).await? {
            WorkerResponse::Decision(decision) => Ok(decision),
            WorkerResponse::Error { message } => bail!("policy rejected: {message}"),
            WorkerResponse::Transformed(_) | WorkerResponse::Validated => {
                bail!("policy worker returned the wrong response kind")
            }
        }
    }

    pub async fn transform(&self, input: TransformInput) -> Result<Vec<u8>> {
        validate_transform_input(&input)?;
        match self.dispatch(WorkerRequest::Transform(input)).await? {
            WorkerResponse::Transformed(body) => {
                validate_transform_body(&body)?;
                Ok(body)
            }
            WorkerResponse::Error { message } => bail!("body transform rejected: {message}"),
            WorkerResponse::Decision(_) | WorkerResponse::Validated => {
                bail!("policy worker returned the wrong response kind")
            }
        }
    }

    pub async fn validate(&self, script: &str) -> Result<()> {
        validate_script_size(script)?;
        match self
            .dispatch(WorkerRequest::Validate {
                script: script.to_owned(),
            })
            .await?
        {
            WorkerResponse::Validated => Ok(()),
            WorkerResponse::Error { message } => bail!("policy validation failed: {message}"),
            WorkerResponse::Decision(_) | WorkerResponse::Transformed(_) => {
                bail!("policy worker returned the wrong response kind")
            }
        }
    }

    pub async fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        for slot in &self.slots {
            let mut slot = slot.lock().await;
            slot.shutdown().await;
        }
    }

    async fn dispatch(&self, request: WorkerRequest) -> Result<WorkerResponse> {
        if self.closed.load(Ordering::Acquire) {
            bail!("policy worker pool is shut down");
        }
        if self.slots.is_empty() {
            bail!("policy worker pool has no workers");
        }

        let start = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            let Ok(mut slot) = self.slots[index].try_lock() else {
                continue;
            };
            if self.closed.load(Ordering::Acquire) {
                bail!("policy worker pool is shut down");
            }
            if slot.is_cooling_down() {
                continue;
            }
            return slot.call(&self.executable, request).await;
        }

        Err(WorkerCapacityUnavailable.into())
    }
}

#[derive(Default)]
struct WorkerSlot {
    worker: Option<RunningWorker>,
    retry_after: Option<TokioInstant>,
}

impl WorkerSlot {
    fn is_cooling_down(&self) -> bool {
        self.retry_after.is_some_and(|at| TokioInstant::now() < at)
    }

    async fn call(&mut self, executable: &Path, request: WorkerRequest) -> Result<WorkerResponse> {
        let mut worker = self.take_running(executable)?;
        // From this point until a complete response is validated, the worker
        // belongs to this future. Cancellation drops and kills it, so its late
        // response can never be consumed by another request.
        self.retry_after = Some(TokioInstant::now() + RESTART_COOLDOWN);

        let operation = timeout(operation_timeout(), worker.transact(&request)).await;

        match operation {
            Ok(Ok(response)) if response_matches(&request, &response) => {
                self.worker = Some(worker);
                self.retry_after = None;
                Ok(response)
            }
            Ok(Ok(_)) => {
                worker.terminate().await;
                bail!("policy worker returned the wrong response kind")
            }
            Ok(Err(error)) => {
                worker.terminate().await;
                Err(error.context("policy worker protocol failed"))
            }
            Err(_) => {
                worker.terminate().await;
                bail!("policy worker operation timed out")
            }
        }
    }

    fn take_running(&mut self, executable: &Path) -> Result<RunningWorker> {
        if let Some(mut worker) = self.worker.take()
            && worker.try_wait()?.is_none()
        {
            return Ok(worker);
        }

        if self.is_cooling_down() {
            bail!("policy worker is restarting");
        }

        let mut command = Command::new(executable);
        command
            .arg("--lua-worker")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn policy worker {}", executable.display()))?;
        let stdin = child.stdin.take().context("policy worker has no stdin")?;
        let stdout = child.stdout.take().context("policy worker has no stdout")?;
        self.retry_after = None;
        Ok(RunningWorker {
            child: Some(child),
            stdin,
            stdout,
        })
    }

    async fn shutdown(&mut self) {
        let Some(mut worker) = self.worker.take() else {
            return;
        };

        let graceful = timeout(
            operation_timeout(),
            worker.transact(&WorkerRequest::Shutdown),
        )
        .await;
        if matches!(graceful, Ok(Ok(WorkerResponse::Validated))) {
            worker.wait().await;
        } else {
            worker.terminate().await;
        }
    }
}

struct RunningWorker {
    child: Option<Child>,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl RunningWorker {
    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child
            .as_mut()
            .context("policy worker process handle is missing")?
            .try_wait()
            .context("failed to inspect policy worker")
    }

    async fn transact(&mut self, request: &WorkerRequest) -> Result<WorkerResponse> {
        let payload = serde_json::to_vec(request).context("failed to encode policy request")?;
        if payload.len() > MAX_FRAME_BYTES {
            bail!("policy request exceeds {MAX_FRAME_BYTES} bytes");
        }

        self.stdin
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .context("failed to write policy request length")?;
        self.stdin
            .write_all(&payload)
            .await
            .context("failed to write policy request")?;
        self.stdin
            .flush()
            .await
            .context("failed to flush policy request")?;

        let mut length = [0_u8; 4];
        self.stdout
            .read_exact(&mut length)
            .await
            .context("failed to read policy response length")?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            bail!("invalid policy response length {length}");
        }
        let mut payload = vec![0; length];
        self.stdout
            .read_exact(&mut payload)
            .await
            .context("failed to read policy response")?;
        serde_json::from_slice(&payload).context("failed to decode policy response")
    }

    async fn terminate(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }

    async fn wait(mut self) {
        if let Some(mut child) = self.child.take()
            && timeout(operation_timeout(), child.wait()).await.is_err()
        {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}

impl Drop for RunningWorker {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

fn response_matches(request: &WorkerRequest, response: &WorkerResponse) -> bool {
    matches!(
        (request, response),
        (WorkerRequest::Evaluate(_), WorkerResponse::Decision(_))
            | (WorkerRequest::Evaluate(_), WorkerResponse::Error { .. })
            | (WorkerRequest::Transform(_), WorkerResponse::Transformed(_))
            | (WorkerRequest::Transform(_), WorkerResponse::Error { .. })
            | (WorkerRequest::Validate { .. }, WorkerResponse::Validated)
            | (WorkerRequest::Validate { .. }, WorkerResponse::Error { .. })
            | (WorkerRequest::Shutdown, WorkerResponse::Validated)
    )
}

pub fn worker_main() -> Result<()> {
    apply_worker_limits()?;
    crate::sandbox::install()?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    while let Some(payload) = read_frame(&mut reader)? {
        let request: WorkerRequest =
            serde_json::from_slice(&payload).context("failed to decode policy request")?;
        let shutdown = matches!(request, WorkerRequest::Shutdown);
        let response = match handle_worker_request(request) {
            Ok(response) => response,
            Err(error) => WorkerResponse::Error {
                message: bounded_error(&error),
            },
        };
        write_frame(&mut writer, &response)?;
        if shutdown {
            break;
        }
    }
    Ok(())
}

fn handle_worker_request(request: WorkerRequest) -> Result<WorkerResponse> {
    match request {
        WorkerRequest::Evaluate(input) => {
            validate_input(&input)?;
            Ok(WorkerResponse::Decision(evaluate_in_vm(input)?))
        }
        WorkerRequest::Transform(input) => {
            validate_transform_input(&input)?;
            Ok(WorkerResponse::Transformed(transform_in_vm(input)?))
        }
        WorkerRequest::Validate { script } => {
            validate_script_size(&script)?;
            validate_in_vm(&script)?;
            Ok(WorkerResponse::Validated)
        }
        WorkerRequest::Shutdown => Ok(WorkerResponse::Validated),
    }
}

fn evaluate_in_vm(input: PolicyInput) -> Result<Decision> {
    let lua = restricted_lua()?;
    install_budget(&lua)?;
    let decision = Arc::new(StdMutex::new(Decision::default()));
    install_host_api(&lua, &input, Arc::clone(&decision))?;

    let value = lua
        .load(&input.script)
        .set_name("=policy")
        .set_mode(ChunkMode::Text)
        .eval::<Value>()
        .context("Lua policy failed")?;
    match value {
        Value::Nil => {}
        Value::String(backend) => {
            let backend = backend
                .to_str()
                .context("returned backend is not UTF-8")?
                .to_owned();
            validate_backend(&backend)?;
            decision.lock().expect("decision lock poisoned").backend = Some(backend);
        }
        other => bail!(
            "policy must return nil or a backend string, got {}",
            other.type_name()
        ),
    }

    let result = decision
        .lock()
        .map_err(|_| anyhow!("policy decision lock was poisoned"))?
        .clone();
    Ok(result)
}

fn transform_in_vm(input: TransformInput) -> Result<Vec<u8>> {
    let lua = restricted_lua()?;
    install_budget(&lua)?;
    let transformed = Arc::new(StdMutex::new(None));
    install_transform_api(&lua, &input, Arc::clone(&transformed))?;

    let value = lua
        .load(&input.script)
        .set_name("=body_transform")
        .set_mode(ChunkMode::Text)
        .eval::<Value>()
        .context("Lua body transform failed")?;
    let body = match value {
        Value::Nil => transformed
            .lock()
            .map_err(|_| anyhow!("body transform lock was poisoned"))?
            .clone()
            .unwrap_or(input.body),
        Value::String(body) => {
            validate_transform_body(&body.as_bytes())?;
            body.as_bytes().to_vec()
        }
        other => bail!(
            "body transform must return nil or a string, got {}",
            other.type_name()
        ),
    };
    validate_transform_body(&body)?;
    Ok(body)
}

fn validate_in_vm(script: &str) -> Result<()> {
    let lua = restricted_lua()?;
    lua.load(script)
        .set_name("=policy")
        .set_mode(ChunkMode::Text)
        .into_function()
        .context("Lua policy did not compile")?;
    Ok(())
}

fn restricted_lua() -> Result<Lua> {
    let lua = Lua::new_with(
        StdLib::STRING | StdLib::TABLE | StdLib::MATH,
        LuaOptions::new().catch_rust_panics(false),
    )?;
    lua.set_memory_limit(LUA_MEMORY_BYTES)?;

    let globals = lua.globals();
    for name in [
        "collectgarbage",
        "dofile",
        "load",
        "loadfile",
        "pcall",
        "print",
        "require",
        "xpcall",
    ] {
        globals.raw_set(name, Value::Nil)?;
    }
    if let Ok(string) = globals.raw_get::<mlua::Table>("string") {
        string.raw_set("dump", Value::Nil)?;
    }
    drop(globals);
    Ok(lua)
}

fn install_budget(lua: &Lua) -> Result<()> {
    let deadline = Instant::now() + LUA_DEADLINE;
    let instructions = Arc::new(AtomicUsize::new(0));
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(HOOK_INTERVAL),
        move |_, _| {
            let used = instructions.fetch_add(HOOK_INTERVAL as usize, Ordering::Relaxed)
                + HOOK_INTERVAL as usize;
            if used > MAX_INSTRUCTIONS {
                return Err(mlua::Error::RuntimeError(
                    "policy instruction budget exceeded".to_owned(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(mlua::Error::RuntimeError(
                    "policy execution deadline exceeded".to_owned(),
                ));
            }
            Ok(VmState::Continue)
        },
    )?;
    Ok(())
}

fn install_host_api(
    lua: &Lua,
    input: &PolicyInput,
    decision: Arc<StdMutex<Decision>>,
) -> Result<()> {
    let api = lua.create_table()?;
    api.raw_set("api_version", 1)?;

    let headers = input.headers.clone();
    api.set(
        "header",
        lua.create_function(move |_, name: String| {
            if name.len() > 256 || !name.is_ascii() {
                return Err(mlua::Error::RuntimeError(
                    "invalid header lookup name".to_owned(),
                ));
            }
            Ok(headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(&name))
                .map(|(_, value)| value.clone()))
        })?,
    )?;

    let method = input.method.clone();
    api.set(
        "method",
        lua.create_function(move |_, ()| Ok(method.clone()))?,
    )?;

    let path = input.path.clone();
    api.set("path", lua.create_function(move |_, ()| Ok(path.clone()))?)?;

    let selected = Arc::clone(&decision);
    api.set(
        "select_backend",
        lua.create_function(move |_, backend: String| {
            validate_backend(&backend).map_err(mlua::Error::external)?;
            selected.lock().expect("decision lock poisoned").backend = Some(backend);
            Ok(())
        })?,
    )?;

    let response_headers = Arc::clone(&decision);
    api.set(
        "set_header",
        lua.create_function(move |_, (name, value): (String, String)| {
            let name = parse_header(&name, &value).map_err(mlua::Error::external)?;
            let mut decision = response_headers.lock().expect("decision lock poisoned");
            if !decision.headers.contains_key(&name)
                && decision.headers.len() >= MAX_DECISION_HEADERS
            {
                return Err(mlua::Error::RuntimeError(
                    "too many decision headers".to_owned(),
                ));
            }
            decision.headers.insert(name, value);
            Ok(())
        })?,
    )?;

    let rejected = Arc::clone(&decision);
    api.set(
        "reject",
        lua.create_function(move |_, status: u16| {
            let status = hyper::StatusCode::from_u16(status).map_err(mlua::Error::external)?;
            if !status.is_client_error() && !status.is_server_error() {
                return Err(mlua::Error::RuntimeError(
                    "reject status must be between 400 and 599".to_owned(),
                ));
            }
            rejected.lock().expect("decision lock poisoned").reject = Some(status.as_u16());
            Ok(())
        })?,
    )?;

    lua.globals().raw_set("hangang", api)?;
    Ok(())
}

fn install_transform_api(
    lua: &Lua,
    input: &TransformInput,
    transformed: Arc<StdMutex<Option<Vec<u8>>>>,
) -> Result<()> {
    let api = lua.create_table()?;
    api.raw_set("api_version", 1)?;

    let body = input.body.clone();
    api.set(
        "body",
        lua.create_function(move |lua, ()| lua.create_string(&body))?,
    )?;

    let phase = input.phase.clone();
    api.set(
        "phase",
        lua.create_function(move |_, ()| Ok(phase.clone()))?,
    )?;

    let destination = Arc::clone(&transformed);
    api.set(
        "set_body",
        lua.create_function(move |_, body: mlua::String| {
            validate_transform_body(&body.as_bytes()).map_err(mlua::Error::external)?;
            let body = body.as_bytes().to_vec();
            *destination.lock().expect("body transform lock poisoned") = Some(body);
            Ok(())
        })?,
    )?;

    api.set(
        "json_decode",
        lua.create_function(|lua, encoded: mlua::String| {
            if encoded.as_bytes().len() > MAX_TRANSFORM_BODY_BYTES {
                return Err(mlua::Error::RuntimeError(
                    "JSON input exceeds 16384 bytes".to_owned(),
                ));
            }
            let value: serde_json::Value =
                serde_json::from_slice(&encoded.as_bytes()).map_err(mlua::Error::external)?;
            lua.to_value(&value)
        })?,
    )?;

    api.set(
        "json_encode",
        lua.create_function(|lua, value: Value| {
            validate_lua_json(lua, &value).map_err(mlua::Error::external)?;
            let value: serde_json::Value = lua.from_value(value)?;
            let mut encoded = BoundedJsonWriter::default();
            serde_json::to_writer(&mut encoded, &value).map_err(mlua::Error::external)?;
            let encoded = encoded.into_inner();
            lua.create_string(&encoded)
        })?,
    )?;

    api.raw_set("null", lua.null())?;
    api.set(
        "array",
        lua.create_function(|lua, ()| {
            let array = lua.create_table()?;
            array.set_metatable(Some(lua.array_metatable()))?;
            Ok(array)
        })?,
    )?;

    lua.globals().raw_set("hangang", api)?;
    Ok(())
}

fn validate_lua_json(lua: &Lua, root: &Value) -> Result<()> {
    let mut pending = vec![(root.clone(), 0_usize)];
    let mut tables = HashSet::new();
    let mut nodes = 0_usize;
    let mut string_bytes = 0_usize;
    let array_metatable = lua.array_metatable();
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.checked_add(1).context("JSON node count overflow")?;
        if nodes > MAX_JSON_NODES {
            bail!("JSON value exceeds {MAX_JSON_NODES} nodes");
        }
        match value {
            Value::Nil | Value::Boolean(_) | Value::Integer(_) => {}
            Value::Number(number) => {
                if !number.is_finite() {
                    bail!("JSON numbers must be finite");
                }
            }
            Value::String(string) => {
                string
                    .to_str()
                    .context("JSON strings must be valid UTF-8")?;
                string_bytes = string_bytes
                    .checked_add(string.as_bytes().len())
                    .context("JSON string size overflow")?;
                if string_bytes > MAX_TRANSFORM_BODY_BYTES {
                    bail!("JSON strings exceed {MAX_TRANSFORM_BODY_BYTES} bytes");
                }
            }
            Value::LightUserData(pointer) if pointer.0.is_null() => {}
            Value::Table(table) => {
                if depth >= MAX_JSON_DEPTH {
                    bail!("JSON value exceeds depth {MAX_JSON_DEPTH}");
                }
                if let Some(metatable) = table.metatable()
                    && metatable.to_pointer() != array_metatable.to_pointer()
                {
                    bail!("JSON tables cannot have custom metatables");
                }
                if !tables.insert(table.to_pointer()) {
                    bail!("JSON value contains a repeated or recursive table");
                }
                for pair in table.pairs::<Value, Value>() {
                    let (key, value) = pair.context("failed to traverse JSON table")?;
                    pending.push((key, depth + 1));
                    pending.push((value, depth + 1));
                }
            }
            other => bail!("unsupported JSON value type: {}", other.type_name()),
        }
    }
    Ok(())
}

#[derive(Default)]
struct BoundedJsonWriter {
    bytes: Vec<u8>,
}

impl BoundedJsonWriter {
    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_TRANSFORM_BODY_BYTES {
            return Err(std::io::Error::other(
                "encoded JSON exceeds body transform limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_input(input: &PolicyInput) -> Result<()> {
    validate_script_size(&input.script)?;
    if input.method.is_empty() || input.method.len() > MAX_METHOD_BYTES {
        bail!("policy method has an invalid length");
    }
    if input.path.len() > MAX_PATH_BYTES {
        bail!("policy path exceeds {MAX_PATH_BYTES} bytes");
    }
    if input.headers.len() > MAX_HEADERS {
        bail!("policy input has too many headers");
    }

    let mut header_bytes = 0_usize;
    for (name, value) in &input.headers {
        parse_header(name, value)?;
        header_bytes = header_bytes
            .checked_add(name.len() + value.len())
            .context("policy header size overflow")?;
    }
    if header_bytes > MAX_HEADER_BYTES {
        bail!("policy headers exceed {MAX_HEADER_BYTES} bytes");
    }
    Ok(())
}

fn validate_transform_input(input: &TransformInput) -> Result<()> {
    validate_script_size(&input.script)?;
    validate_transform_body(&input.body)?;
    if !matches!(input.phase.as_str(), "request" | "response") {
        bail!("body transform phase must be request or response");
    }
    Ok(())
}

fn validate_transform_body(body: &[u8]) -> Result<()> {
    if body.len() > MAX_TRANSFORM_BODY_BYTES {
        bail!("body transform value exceeds {MAX_TRANSFORM_BODY_BYTES} bytes");
    }
    Ok(())
}

fn validate_script_size(script: &str) -> Result<()> {
    if script.len() > MAX_SCRIPT_BYTES {
        bail!("policy source exceeds {MAX_SCRIPT_BYTES} bytes");
    }
    Ok(())
}

fn validate_backend(backend: &str) -> Result<()> {
    if backend.is_empty() || backend.len() > MAX_BACKEND_BYTES {
        bail!("backend has an invalid length");
    }
    if backend.chars().any(char::is_control) {
        bail!("backend contains control characters");
    }
    Ok(())
}

fn parse_header(name: &str, value: &str) -> Result<String> {
    let name = hyper::header::HeaderName::from_bytes(name.as_bytes())
        .context("invalid policy header name")?;
    let value =
        hyper::header::HeaderValue::from_str(value).context("invalid policy header value")?;
    value
        .to_str()
        .context("policy header value must be visible ASCII")?;
    Ok(name.as_str().to_owned())
}

fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    let mut read = 0;
    while read < length.len() {
        match reader.read(&mut length[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => bail!("truncated policy request length"),
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("failed to read policy request length"),
        }
    }

    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        bail!("invalid policy request length {length}");
    }
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .context("failed to read policy request")?;
    Ok(Some(payload))
}

fn write_frame(writer: &mut impl Write, response: &WorkerResponse) -> Result<()> {
    let payload = serde_json::to_vec(response).context("failed to encode policy response")?;
    if payload.len() > MAX_FRAME_BYTES {
        bail!("policy response exceeds {MAX_FRAME_BYTES} bytes");
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .context("failed to write policy response length")?;
    writer
        .write_all(&payload)
        .context("failed to write policy response")?;
    writer.flush().context("failed to flush policy response")
}

fn bounded_error(error: &anyhow::Error) -> String {
    let mut message = format!("{error:#}");
    const MAX_ERROR_BYTES: usize = 4 * 1024;
    if message.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    message
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = <String as serde::Deserialize>::deserialize(deserializer)?;
        STANDARD.decode(encoded).map_err(D::Error::custom)
    }
}

#[cfg(target_os = "linux")]
fn apply_worker_limits() -> Result<()> {
    set_limit(libc::RLIMIT_AS, 256 * 1024 * 1024).context("failed to set RLIMIT_AS")?;
    set_limit(libc::RLIMIT_CORE, 0).context("failed to set RLIMIT_CORE")
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` points to a valid `rlimit` for the duration of the call.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setrlimit returned an error");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_worker_limits() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_input(script: &str) -> PolicyInput {
        PolicyInput {
            script: script.to_owned(),
            method: "POST".to_owned(),
            path: "/v1/items".to_owned(),
            headers: BTreeMap::from([("X-Tenant".to_owned(), "green".to_owned())]),
        }
    }

    #[test]
    fn vm_exposes_only_copied_request_and_decision_api() {
        let decision = evaluate_in_vm(test_input(
            r#"
                assert(hangang.method() == "POST")
                assert(hangang.path() == "/v1/items")
                assert(hangang.header("x-tenant") == "green")
                hangang.select_backend("green-api")
                hangang.set_header("x-route", "green")
            "#,
        ))
        .unwrap();
        assert_eq!(decision.backend.as_deref(), Some("green-api"));
        assert_eq!(
            decision.headers.get("x-route").map(String::as_str),
            Some("green")
        );
    }

    #[test]
    fn validation_does_not_execute_the_chunk() {
        validate_in_vm("error('not executed')").unwrap();
        assert!(validate_in_vm("function (").is_err());
    }

    #[test]
    fn sandbox_removes_loaders_io_and_protected_call_escape() {
        for script in [
            "return load('return 1')",
            "return dofile('/etc/passwd')",
            "return pcall(function() end)",
            "return os.execute('true')",
        ] {
            assert!(evaluate_in_vm(test_input(script)).is_err(), "{script}");
        }
    }

    #[test]
    fn instruction_and_memory_budgets_stop_abusive_scripts() {
        assert!(evaluate_in_vm(test_input("while true do end")).is_err());
        assert!(
            evaluate_in_vm(test_input(
                "local t = {}; for i = 1, 2000000 do t[i] = i end"
            ))
            .is_err()
        );
    }

    #[test]
    fn callback_values_are_validated() {
        assert!(evaluate_in_vm(test_input("hangang.reject(399)")).is_err());
        assert!(evaluate_in_vm(test_input("hangang.set_header('bad header', 'x')")).is_err());
        assert!(evaluate_in_vm(test_input("return ''")).is_err());
        assert!(evaluate_in_vm(test_input("return {}")).is_err());
    }

    #[test]
    fn framing_rejects_oversized_input_before_allocating_payload() {
        let length = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert!(read_frame(&mut length.as_slice()).is_err());
    }
}
