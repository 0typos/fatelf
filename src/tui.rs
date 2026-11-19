//! Terminal config editor; saving is the only path from UI state to a build.

use std::{
    env,
    io::{self, IsTerminal},
    mem::{MaybeUninit, zeroed},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::ValueEnum;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout as ScreenLayout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use serde::{Deserialize, Serialize};
use unicode_width::UnicodeWidthChar;

use crate::{
    codec::Compression,
    config::{self, BuildConfig, Document, destination},
    container::{Backend, Position},
    error::Error,
    pack::{Input, Order},
};

/// Start an editor, restore the terminal, and execute the saved config's build command.
pub(crate) fn run(input: Option<&Path>, output: Option<&Path>) -> Result<(), Error> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::Invalid(
            "configure requires an interactive terminal; use build --config FILE for automation"
                .into(),
        ));
    }
    let document = input.map(Document::load).transpose()?;
    let default_path = document
        .as_ref()
        .map(|d| d.path.as_path())
        .unwrap_or_else(|| Path::new("bundle.toml"));
    let path = destination(output.unwrap_or(default_path))?;
    let mut draft = document
        .as_ref()
        .map(|d| d.config.clone())
        .unwrap_or_else(BuildConfig::draft);
    if document.is_none() {
        let base = path
            .parent()
            .expect("invariant: destination has a canonical parent");
        draft.output = base.join("combined");
        draft.launcher = Some(env::current_exe()?.with_file_name("fatelf-launcher"));
    }
    let mut builder = Builder::new(draft)?;
    let termination = Termination::install()?;
    let outcome = (|| {
        let mut session = Session::new()?;
        let outcome = edit(
            &mut session.terminal,
            &mut builder,
            &path,
            document.as_ref(),
        )?;
        session.finish()?;
        Ok::<_, Error>(outcome)
    })();
    if termination.finish() {
        // Restore the prior disposition first so supervisors see normal termination.
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)?;
        return Ok(());
    }
    let outcome = outcome?;
    let Some(build) = outcome else { return Ok(()) };
    println!("Saved {}", path.display());
    if !build {
        return Ok(());
    }
    // Exec the real CLI after restoration. The saved file is reread by `build`,
    // preserving its exit/signal status and avoiding a second builder implementation.
    let error = Command::new(env::current_exe()?)
        .arg("build")
        .arg("--config")
        .arg(&path)
        .exec();
    Err(error.into())
}

static TERMINATED: AtomicBool = AtomicBool::new(false);
static EDITOR_SIGNAL: Mutex<()> = Mutex::new(());

extern "C" fn handle_sigterm(_: libc::c_int) {
    TERMINATED.store(true, Ordering::Relaxed);
}

/// Restore the prior process-wide SIGTERM disposition when the editor leaves.
struct Termination {
    previous: Option<libc::sigaction>,
    _lock: MutexGuard<'static, ()>,
}

impl Termination {
    /// Install a handler that records only an atomic flag for the editor loop.
    fn install() -> Result<Self, Error> {
        let lock = EDITOR_SIGNAL
            .try_lock()
            .map_err(|_| Error::Invalid("terminal editor already active".into()))?;
        TERMINATED.store(false, Ordering::Relaxed);
        // SAFETY: sigaction is a C struct of scalar fields and a signal set.
        let mut action: libc::sigaction = unsafe { zeroed() };
        action.sa_sigaction = handle_sigterm as *const () as usize;
        let mut previous = MaybeUninit::uninit();
        // SAFETY: action is initialized, sigemptyset initializes its mask, and
        // sigaction writes the old disposition to previous on success.
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGTERM, &action, previous.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self {
                previous: Some(previous.assume_init()),
                _lock: lock,
            })
        }
    }
    /// Restore the previous action before checking the flag under the editor lock.
    fn finish(mut self) -> bool {
        self.restore();
        TERMINATED.load(Ordering::Relaxed)
    }

    /// Restore the saved disposition once, including on unwind.
    fn restore(&mut self) {
        if let Some(previous) = self.previous.take() {
            // SAFETY: previous was returned by sigaction for this signal.
            unsafe { libc::sigaction(libc::SIGTERM, &previous, std::ptr::null_mut()) };
        }
    }
}

impl Drop for Termination {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Own terminal restoration on successful completion, errors, and unwinding.
struct Session {
    terminal: DefaultTerminal,
    restored: bool,
}

impl Session {
    /// Initialize raw/alternate-screen mode while cleaning up partial failures.
    fn new() -> Result<Self, Error> {
        match ratatui::try_init() {
            Ok(terminal) => Ok(Self {
                terminal,
                restored: false,
            }),
            Err(error) => {
                ratatui::restore();
                Err(error.into())
            }
        }
    }

    /// Leave the UI before starting any build, reporting restoration failures.
    fn finish(&mut self) -> Result<(), Error> {
        self.terminal.show_cursor()?;
        ratatui::try_restore()?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.restored {
            if let Err(error) = self.terminal.show_cursor() {
                eprintln!("Could not restore terminal cursor: {error}");
            }
            ratatui::restore();
        }
    }
}

/// Read events until cancellation or a successfully saved config.
fn edit(
    terminal: &mut DefaultTerminal,
    builder: &mut Builder,
    path: &Path,
    document: Option<&Document>,
) -> Result<Option<bool>, Error> {
    loop {
        terminal.draw(|frame| builder.draw(frame, path))?;
        let event = loop {
            if TERMINATED.load(Ordering::Relaxed) {
                return Ok(None);
            }
            match event::poll(Duration::from_millis(100))
                .and_then(|ready| ready.then(event::read).transpose())
            {
                Ok(Some(event)) => break event,
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        };
        let Event::Key(key) = event else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        let result = builder.handle(key);
        let decision = match result {
            Ok(decision) => decision,
            Err(error) => {
                builder.status = error.to_string();
                continue;
            }
        };
        match decision {
            Decision::Continue => {}
            Decision::Cancel => return Ok(None),
            Decision::Save { build } => {
                let result = builder.save(path, document);
                match result {
                    Ok(()) => return Ok(Some(build)),
                    Err(error) => builder.status = error.to_string(),
                }
            }
        }
    }
}

/// Editor transition, with filesystem/build actions confined to the outer loop.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Continue,
    Cancel,
    Save { build: bool },
}

/// A configurable field or one of the dynamically added payload name/path pairs.
#[derive(Clone, Copy, Debug)]
enum Field {
    Output,
    Launcher,
    Env,
    Default,
    Backend,
    Layout,
    Order,
    Dedup,
    ChunkSize,
    Seed,
    Scope,
    Values,
    ManifestPosition,
    Compression,
    Name(usize),
    Path(usize),
    PayloadShuffle(usize),
    PayloadEncryption(usize),
}

/// Fields always present before the n payload pairs.
const FIXED: [Field; 14] = [
    Field::Output,
    Field::Launcher,
    Field::Env,
    Field::Default,
    Field::Backend,
    Field::Layout,
    Field::Order,
    Field::Dedup,
    Field::ChunkSize,
    Field::Seed,
    Field::Scope,
    Field::Values,
    Field::ManifestPosition,
    Field::Compression,
];

impl Field {
    /// Human-facing label; payload fields expose their stable ordering.
    fn label(self) -> String {
        match self {
            Self::Output => "Output binary".into(),
            Self::Launcher => "Launcher".into(),
            Self::Env => "Selector variable".into(),
            Self::Default => "Default payload".into(),
            Self::Backend => "Execution".into(),
            Self::Layout => "Layout".into(),
            Self::Order => "Chunk order".into(),
            Self::Dedup => "Deduplicate".into(),
            Self::ChunkSize => "Chunk bytes".into(),
            Self::Seed => "Shuffle seed".into(),
            Self::Scope => "Shuffle scope".into(),
            Self::Values => "Scope values".into(),
            Self::ManifestPosition => "Manifest position".into(),
            Self::Compression => "Compression".into(),
            Self::PayloadShuffle(index) => format!("Payload {} shuffle", index + 1),
            Self::PayloadEncryption(index) => format!("Payload {} key", index + 1),
            Self::Name(index) => format!("Payload {} name", index + 1),
            Self::Path(index) => format!("Payload {} path", index + 1),
        }
    }

    /// Explain consequences of each setting where the user makes the choice.
    fn help(self) -> &'static str {
        match self {
            Self::Output => {
                "Prefer a full path for the new binary. Existing files are never overwritten. Relative paths use the configuration directory."
            }
            Self::Launcher => {
                "Prefer a full launcher path. Leave empty to use fatelf-launcher beside the packer. Its architecture must match the payloads."
            }
            Self::Env => {
                "Runtime variable selecting a payload by name. You choose its name; the variable need not exist during this build."
            }
            Self::Default => {
                "Leave empty for the first payload. Unknown or empty selector values fail instead of falling back."
            }
            Self::Backend => {
                "memfd: RAM-backed, requires executable memfds. file: temporary filesystem storage, requires an executable mount. Both replace the launcher and preserve PID."
            }
            Self::Layout => {
                "overlay appends storage to the launcher: simple assembly, but postprocessors must preserve appended bytes. This is the currently supported layout."
            }
            Self::Order => {
                "ordered is simplest to inspect. shuffled permutes contiguous eligible object runs and restores their original order at launch; it is not encryption."
            }
            Self::Dedup => {
                "true stores exactly identical chunks once after byte comparison. It saves space, with extra comparisons during packing."
            }
            Self::ChunkSize => {
                "256 through 1048576 bytes. Smaller chunks can find more shared fragments but increase metadata and reconstruction reads."
            }
            Self::Seed => {
                "Unsigned 64-bit seed. The same inputs, launcher and seed reproduce the same shuffled output. This is not a cryptographic key."
            }
            Self::Scope => {
                "all shuffles every eligible payload object; sections or ranges limit it. Sections/ranges require shuffled order and apply independently to every payload."
            }
            Self::Values => {
                "TOML string list: [\".text\", \".rodata\"] for sections, or [\"4096:8192\"] for half-open ranges. Decimal and 0x hex offsets work. Use [] for all."
            }
            Self::ManifestPosition => {
                "front stores the manifest immediately after the launcher; end stores it after the pool. A fixed locator footer stays at EOF in both layouts."
            }
            Self::Compression => {
                "none stores encoded bytes directly. lz4 compresses each object only if smaller, then falls back to raw encoded storage. Per-payload and region overrides are preserved."
            }
            Self::PayloadShuffle(_) => {
                "inherit follows global order and scope. true enables this payload; false anchors its objects. Enabling shuffle requires shuffled order. Region overrides are preserved."
            }
            Self::PayloadEncryption(_) => {
                "Empty inherits the global encryption policy; none disables it. Enter a configured key ID. Key files, budgets and region rules are preserved from loaded TOML; edit those advanced settings in TOML."
            }
            Self::Name(_) => {
                "Unique runtime selection label: letters, numbers, underscore, dot or hyphen; at most 64 bytes."
            }
            Self::Path(_) => {
                "Prefer the full path to the original executable ELF. Relative paths use the configuration directory. F2 adds a payload; F3 removes the selected one."
            }
        }
    }

    /// Enumerated choices cycled directly without free-form string parsing.
    fn choices(self) -> Vec<String> {
        let choices = match self {
            Self::Backend => return enum_choices::<Backend>(),
            Self::Order => return enum_choices::<Order>(),
            Self::ManifestPosition => return enum_choices::<Position>(),
            Self::Compression => return enum_choices::<Compression>(),
            Self::Dedup => &["false", "true"][..],
            Self::Scope => &["all", "sections", "ranges"],
            Self::PayloadShuffle(_) => &["inherit", "false", "true"],
            _ => &[],
        };
        choices.iter().map(|choice| (*choice).to_owned()).collect()
    }
}

/// Return the same user-facing value names Clap accepts.
fn enum_choices<T: ValueEnum>() -> Vec<String> {
    T::value_variants().iter().map(enum_name).collect()
}

/// Display the canonical spelling for an editor enum.
fn enum_name(value: &impl ValueEnum) -> String {
    value
        .to_possible_value()
        .expect("invariant: editor enum variants have names")
        .get_name()
        .to_owned()
}

/// Strict TOML string array used by the scope editor without delimiter ambiguity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeValues {
    values: Vec<String>,
}

/// Editable, typed build settings plus transient cursor/input state.
struct Builder {
    config: BuildConfig,
    scope: String,
    values: String,
    selected: usize,
    editing: Option<String>,
    status: String,
    list: ListState,
}

impl Builder {
    /// Initialize the form from a validated document or an incomplete new draft.
    fn new(config: BuildConfig) -> Result<Self, Error> {
        let (scope, values) = if !config.storage.sections.is_empty() {
            ("sections", config.storage.sections.clone())
        } else if !config.storage.ranges.is_empty() {
            ("ranges", config.storage.ranges.clone())
        } else {
            ("all", Vec::new())
        };
        let encoded = toml::to_string(&ScopeValues { values })?;
        let values = encoded
            .trim()
            .strip_prefix("values = ")
            .ok_or_else(|| Error::Invalid("cannot format scope values".into()))?
            .to_owned();
        Ok(Self {
            config,
            scope: scope.into(),
            values,
            selected: 0,
            editing: None,
            status: String::new(),
            list: ListState::default(),
        })
    }

    /// Compute the number of rows without a fixed two-payload assumption.
    fn count(&self) -> usize {
        FIXED.len() + self.config.payloads.len() * 4
    }

    /// Locate a row's typed field; selected indices are kept within count().
    fn field(&self, index: usize) -> Field {
        if let Some(field) = FIXED.get(index) {
            return *field;
        }
        let dynamic = index - FIXED.len();
        let index = dynamic / 4;
        match dynamic % 4 {
            0 => Field::Name(index),
            1 => Field::Path(index),
            2 => Field::PayloadShuffle(index),
            _ => Field::PayloadEncryption(index),
        }
    }

    /// Format a field for display and initialize its editable buffer.
    fn value(&self, field: Field) -> String {
        match field {
            Field::Output => self.config.output.to_string_lossy().into_owned(),
            Field::Launcher => self
                .config
                .launcher
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            Field::Env => self.config.selection.env.clone(),
            Field::Default => self.config.selection.default.clone().unwrap_or_default(),
            Field::Backend => enum_name(&self.config.execution.backend),
            Field::Layout => "overlay".into(),
            Field::Order => enum_name(&self.config.storage.order),
            Field::Dedup => self.config.storage.dedup.to_string(),
            Field::ChunkSize => self.config.storage.chunk_size.to_string(),
            Field::Seed => self.config.storage.seed.to_string(),
            Field::Scope => self.scope.clone(),
            Field::Values => self.values.clone(),
            Field::ManifestPosition => enum_name(&self.config.storage.manifest_position),
            Field::Compression => enum_name(&self.config.storage.compression),
            Field::PayloadShuffle(index) => self.config.payloads[index]
                .shuffle
                .map_or("inherit".into(), |v| v.to_string()),
            Field::PayloadEncryption(index) => self.config.payloads[index]
                .encryption
                .clone()
                .unwrap_or_default(),
            Field::Name(index) => self.config.payloads[index].name.clone(),
            Field::Path(index) => self.config.payloads[index]
                .path
                .to_string_lossy()
                .into_owned(),
        }
    }

    /// Apply a completed edit; invalid numeric values remain in the input buffer.
    fn set(&mut self, field: Field, value: &str) -> Result<(), Error> {
        match field {
            Field::Output => self.config.output = value.into(),
            Field::Launcher => self.config.launcher = (!value.is_empty()).then(|| value.into()),
            Field::Env => self.config.selection.env = value.into(),
            Field::Default => {
                self.config.selection.default = (!value.is_empty()).then(|| value.into())
            }
            Field::Backend => {
                self.config.execution.backend =
                    ValueEnum::from_str(value, false).map_err(Error::Invalid)?;
            }
            Field::Order => {
                self.config.storage.order =
                    ValueEnum::from_str(value, false).map_err(Error::Invalid)?;
            }
            Field::Dedup => {
                self.config.storage.dedup = value
                    .parse()
                    .map_err(|_| Error::Invalid("dedup must be true or false".into()))?
            }
            Field::ChunkSize => {
                self.config.storage.chunk_size = value.parse().map_err(|_| {
                    Error::Invalid("chunk bytes must be an unsigned 32-bit integer".into())
                })?
            }
            Field::Seed => {
                self.config.storage.seed = value
                    .parse()
                    .map_err(|_| Error::Invalid("seed must be an unsigned 64-bit integer".into()))?
            }
            Field::Scope => self.scope = value.into(),
            Field::Values => self.values = value.into(),
            Field::ManifestPosition => {
                self.config.storage.manifest_position =
                    ValueEnum::from_str(value, false).map_err(Error::Invalid)?;
            }
            Field::Compression => {
                self.config.storage.compression =
                    ValueEnum::from_str(value, false).map_err(Error::Invalid)?;
            }
            Field::PayloadShuffle(index) => {
                self.config.payloads[index].shuffle = match value {
                    "inherit" => None,
                    "false" => Some(false),
                    "true" => Some(true),
                    _ => return Err(Error::Invalid("invalid payload shuffle".into())),
                }
            }
            Field::PayloadEncryption(index) => {
                self.config.payloads[index].encryption = (!value.is_empty()).then(|| value.into())
            }
            Field::Name(index) => self.config.payloads[index].name = value.into(),
            Field::Path(index) => self.config.payloads[index].path = value.into(),
            Field::Layout => {}
        }
        Ok(())
    }

    /// Commit an active editor before movement or saving, preserving invalid input.
    fn commit(&mut self) -> Result<(), Error> {
        if let Some(value) = self.editing.clone() {
            self.set(self.field(self.selected), &value)?;
            self.editing = None;
        }
        Ok(())
    }

    /// Move focus cyclically while keeping payload row indexing valid.
    fn move_focus(&mut self, forward: bool) -> Result<(), Error> {
        self.commit()?;
        self.selected = if forward {
            (self.selected + 1) % self.count()
        } else {
            (self.selected + self.count() - 1) % self.count()
        };
        self.status.clear();
        Ok(())
    }

    /// Cycle one of the concrete supported choices in either direction.
    fn cycle(&mut self, forward: bool) -> Result<(), Error> {
        let field = self.field(self.selected);
        let choices = field.choices();
        if choices.is_empty() {
            return Ok(());
        }
        let value = self.value(field);
        let current = choices
            .iter()
            .position(|choice| choice == &value)
            .unwrap_or(0);
        let next = if forward {
            (current + 1) % choices.len()
        } else {
            (current + choices.len() - 1) % choices.len()
        };
        self.set(field, &choices[next])
    }

    /// Add a named empty payload or remove its selected name/path pair.
    fn change_payloads(&mut self, add: bool) -> Result<(), Error> {
        self.commit()?;
        if add {
            if self.config.payloads.len() >= 64 {
                return Err(Error::Invalid("at most 64 payloads are supported".into()));
            }
            let mut number = self.config.payloads.len() + 1;
            while self
                .config
                .payloads
                .iter()
                .any(|p| p.name == format!("payload{number}"))
            {
                number += 1;
            }
            self.config
                .payloads
                .push(Input::new(format!("payload{number}"), PathBuf::new()));
            self.selected = self.count() - 4;
        } else {
            if self.config.payloads.len() <= 1 {
                return Err(Error::Invalid(
                    "a container needs at least one payload".into(),
                ));
            }
            let index = match self.field(self.selected) {
                Field::Name(index)
                | Field::Path(index)
                | Field::PayloadShuffle(index)
                | Field::PayloadEncryption(index) => index,
                _ => return Err(Error::Invalid("select a payload row to remove it".into())),
            };
            self.config.payloads.remove(index);
            self.selected = self.selected.min(self.count() - 1);
        }
        Ok(())
    }

    /// Translate keyboard input into form changes or an explicit save/cancel decision.
    fn handle(&mut self, key: KeyEvent) -> Result<Decision, Error> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(Decision::Cancel);
        }
        match key.code {
            KeyCode::F(5) | KeyCode::F(6) => {
                self.commit()?;
                return Ok(Decision::Save {
                    build: key.code == KeyCode::F(6),
                });
            }
            KeyCode::F(2) => self.change_payloads(true)?,
            KeyCode::F(3) => self.change_payloads(false)?,
            KeyCode::Tab => self.move_focus(true)?,
            KeyCode::BackTab => self.move_focus(false)?,
            KeyCode::Esc if self.editing.is_some() => self.editing = None,
            KeyCode::Esc => return Ok(Decision::Cancel),
            _ if self.editing.is_some() => match key.code {
                KeyCode::Enter => self.commit()?,
                KeyCode::Backspace => {
                    if let Some(value) = &mut self.editing {
                        value.pop();
                    }
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(value) = &mut self.editing {
                        value.clear();
                    }
                }
                KeyCode::Char(c)
                    if !c.is_control() && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if let Some(value) = &mut self.editing {
                        if value.len() + c.len_utf8() > 4096 {
                            return Err(Error::Invalid("field exceeds 4096 bytes".into()));
                        }
                        value.push(c);
                    }
                }
                _ => {}
            },
            KeyCode::Up => self.move_focus(false)?,
            KeyCode::Down => self.move_focus(true)?,
            KeyCode::Left => self.cycle(false)?,
            KeyCode::Right | KeyCode::Char(' ') => self.cycle(true)?,
            KeyCode::Enter => {
                let field = self.field(self.selected);
                if !field.choices().is_empty() {
                    self.cycle(true)?;
                } else if !matches!(field, Field::Layout) {
                    self.editing = Some(self.value(field));
                }
            }
            _ => {}
        }
        Ok(Decision::Continue)
    }

    /// Produce config settings from the form, then use shared validation and atomic save.
    fn save(&self, path: &Path, document: Option<&Document>) -> Result<(), Error> {
        let mut config = self.config.clone();
        let values: ScopeValues = toml::from_str(&format!("values = {}", self.values))?;
        config.storage.sections.clear();
        config.storage.ranges.clear();
        if self.scope != "all" && values.values.is_empty() {
            return Err(Error::Invalid(
                "sections/ranges scope needs at least one value".into(),
            ));
        }
        match self.scope.as_str() {
            "sections" => config.storage.sections = values.values,
            "ranges" => config.storage.ranges = values.values,
            "all" if values.values.is_empty() => {}
            "all" => {
                return Err(Error::Invalid(
                    "scope values must be [] when scope is all".into(),
                ));
            }
            _ => return Err(Error::Invalid("invalid shuffle scope".into())),
        }
        config.options(document.map_or(Path::new("."), Document::base))?;
        if let Some(document) = document
            && path.parent() != Some(document.base())
        {
            config.rebase(document.base());
        }
        config::save(&config, path, document)
    }

    /// Render a scrolling form with setting-specific tradeoffs and visible save actions.
    fn draw(&mut self, frame: &mut Frame, path: &Path) {
        let areas = ScreenLayout::vertical([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(5),
            Constraint::Length(2),
        ])
        .split(frame.area());
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    format!("fatelf builder · {} payloads", self.config.payloads.len()),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("Config: {}", path.display())),
            ]),
            areas[0],
        );
        let width = areas[1].width.saturating_sub(24) as usize;
        let items: Vec<_> = (0..self.count())
            .map(|index| {
                let field = self.field(index);
                let editing = self.editing.as_ref().filter(|_| index == self.selected);
                let value = editing.cloned().unwrap_or_else(|| self.value(field));
                let visible: String = value
                    .chars()
                    .map(|c| if c.is_control() { '�' } else { c })
                    .collect();
                let visible = if editing.is_some() {
                    format!("{}▌", tail(&visible, width.saturating_sub(1)))
                } else if visible.is_empty() {
                    "(empty)".into()
                } else {
                    visible
                };
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{:<19} ", field.label())),
                    Span::raw(visible),
                ]))
            })
            .collect();
        self.list.select(Some(self.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title("Settings · Enter edits · ←/→ choices"))
                .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
                .highlight_symbol("› "),
            areas[1],
            &mut self.list,
        );
        frame.render_widget(
            Paragraph::new(self.field(self.selected).help())
                .wrap(Wrap { trim: true })
                .block(Block::bordered().title("Tradeoffs / help")),
            areas[2],
        );
        let status = if self.status.is_empty() {
            "Tab move · F2 add · F3 remove · F5 save · F6 save+build · Esc cancel"
        } else {
            &self.status
        };
        let style = if self.status.is_empty() {
            Style::default()
        } else {
            Style::default().fg(Color::Red)
        };
        frame.render_widget(
            Paragraph::new(status)
                .style(style)
                .wrap(Wrap { trim: true }),
            areas[3],
        );
    }
}

/// Keep an editing cursor and its trailing Unicode text visible in narrow value columns.
fn tail(value: &str, width: usize) -> &str {
    let mut used = 0;
    let mut start = value.len();
    for (index, character) in value.char_indices().rev() {
        used += character.width().unwrap_or(0);
        if used > width {
            break;
        }
        start = index;
    }
    &value[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};
    use std::fs;
    use tempfile::tempdir;

    /// A valid portable document keeps keyboard tests independent of real executable files.
    fn settings() -> BuildConfig {
        BuildConfig::parse(
            "version = 2\noutput = 'combined'\n\
             [[payloads]]\nname = 'a'\npath = 'one'\n\
             [[payloads]]\nname = 'b'\npath = 'two'\n",
        )
        .unwrap()
    }

    /// Send ordinary keys through the same handler used by the terminal event loop.
    fn key(builder: &mut Builder, code: KeyCode) -> Decision {
        builder
            .handle(KeyEvent::new(code, KeyModifiers::NONE))
            .unwrap()
    }

    /// Replace the focused text field using visible editor controls.
    fn replace(builder: &mut Builder, value: &str) {
        key(builder, KeyCode::Enter);
        builder
            .handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        for c in value.chars() {
            key(builder, KeyCode::Char(c));
        }
        key(builder, KeyCode::Enter);
    }

    #[test]
    fn keyboard_added_payload_is_saved_and_removable() {
        let directory = tempdir().unwrap();
        let mut builder = Builder::new(settings()).unwrap();
        key(&mut builder, KeyCode::F(2));
        replace(&mut builder, "third");
        key(&mut builder, KeyCode::Tab);
        replace(&mut builder, "/full/path/third");
        assert_eq!(
            key(&mut builder, KeyCode::F(5)),
            Decision::Save { build: false }
        );
        let added = directory.path().join("added.toml");
        builder.save(&added, None).unwrap();
        let saved: toml::Value = toml::from_str(&fs::read_to_string(added).unwrap()).unwrap();
        assert_eq!(saved["payloads"].as_array().unwrap().len(), 3);
        assert_eq!(saved["payloads"][2]["name"].as_str(), Some("third"));
        assert_eq!(
            saved["payloads"][2]["path"].as_str(),
            Some("/full/path/third")
        );
        key(&mut builder, KeyCode::F(3));
        let removed = directory.path().join("removed.toml");
        builder.save(&removed, None).unwrap();
        let saved: toml::Value = toml::from_str(&fs::read_to_string(removed).unwrap()).unwrap();
        assert_eq!(saved["payloads"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn save_as_rejects_cleared_required_paths_before_rebasing() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("elsewhere");
        fs::create_dir(&destination).unwrap();
        let original = directory.path().join("bundle.toml");
        config::save(&settings(), &original, None).unwrap();
        let document = Document::load(&original).unwrap();
        for row in [0, FIXED.len() + 1] {
            let mut builder = Builder::new(document.config.clone()).unwrap();
            for _ in 0..row {
                key(&mut builder, KeyCode::Tab);
            }
            replace(&mut builder, "");
            let path = destination.join("saved.toml");
            assert!(builder.save(&path, Some(&document)).is_err());
            assert!(
                !path.exists(),
                "a cleared required path must prevent Save As"
            );
            replace(&mut builder, "/full/path/repaired");
            builder.save(&path, Some(&document)).unwrap();
            // Each row gets its own successful destination, preserving no-clobber semantics.
            fs::rename(path, destination.join(format!("repaired-{row}.toml"))).unwrap();
        }
    }

    #[test]
    fn editing_basic_fields_preserves_advanced_region_key_and_budget_settings() {
        let config = BuildConfig::parse(
            "version = 2\noutput = 'combined'\n\
             [[keys]]\nname = 'protected'\nkey_file = 'unlock.key'\nenv = 'KEY_FILE'\n\
             [[payloads]]\nname = 'one'\npath = 'one'\nencryption = 'protected'\n\
             [[payloads.regions]]\nrange = '4096:8192'\ncompression = 'lz4'\n\
             [budgets]\nmax_payload_bytes = 123456\n",
        )
        .unwrap();
        let directory = tempdir().unwrap();
        let mut builder = Builder::new(config).unwrap();
        builder.set(Field::Compression, "lz4").unwrap();
        builder.set(Field::ManifestPosition, "front").unwrap();
        builder.set(Field::PayloadShuffle(0), "false").unwrap();
        let path = directory.path().join("advanced.toml");
        builder.save(&path, None).unwrap();
        let saved = Document::load(&path).unwrap().config;
        assert_eq!(saved.storage.compression, Compression::Lz4);
        assert_eq!(saved.storage.manifest_position, Position::Front);
        assert_eq!(saved.payloads[0].shuffle, Some(false));
        assert_eq!(saved.payloads[0].encryption.as_deref(), Some("protected"));
        assert_eq!(
            saved.payloads[0].regions[0].range.as_deref(),
            Some("4096:8192")
        );
        assert_eq!(saved.keys[0].key_file, Path::new("unlock.key"));
        assert_eq!(saved.budgets.max_payload_bytes, 123456);
    }

    #[test]
    fn rendered_editor_keeps_long_unicode_input_cursor_visible() {
        let mut builder = Builder::new(settings()).unwrap();
        key(&mut builder, KeyCode::Enter);
        builder
            .handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        for c in "/a/long/路径/with/another/long/component/尾巴".chars() {
            key(&mut builder, KeyCode::Char(c));
        }
        let mut terminal = Terminal::new(TestBackend::new(50, 20)).unwrap();
        terminal
            .draw(|frame| builder.draw(frame, Path::new("/config.toml")))
            .unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            screen.contains("尾 巴 ▌"),
            "editing cursor and trailing text must remain visible: {screen}"
        );
        assert!(screen.contains("Tradeoffs / help"));
        assert_eq!(key(&mut builder, KeyCode::Esc), Decision::Continue);
        assert_eq!(key(&mut builder, KeyCode::Esc), Decision::Cancel);
    }
}
