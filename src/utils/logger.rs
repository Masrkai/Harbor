use crate::cli::color::*;

const COLOR_INFO: Color = Color::from_hex(b"#50C878");
const COLOR_DEBUG: Color = Color::from_hex(b"#508CFF");
const COLOR_ERROR: Color = Color::from_hex(b"#FF5050");
const COLOR_FATAL: Color = Color::from_hex(b"#8B0000");

#[derive(Debug, Clone, PartialEq)]
pub enum LogState {
    Info,
    Debug,
    Error,
    Fatal,
}

impl LogState {
    /// Colored label — pulls directly from the constants at the top of the file.
    pub fn label(&self) -> String {
        match self {
            LogState::Info => COLOR_INFO.paint("[INFO ]"),
            LogState::Debug => COLOR_DEBUG.paint("[DEBUG]"),
            LogState::Error => COLOR_ERROR.paint("[ERROR]"),
            LogState::Fatal => COLOR_FATAL.paint("[FATAL]"),
        }
    }

    fn severity(&self) -> u8 {
        match self {
            LogState::Info => 0,
            LogState::Debug => 1,
            LogState::Error => 2,
            LogState::Fatal => 3,
        }
    }

    /// Transitions enforce one-way severity escalation.
    /// Downgrading (e.g. Fatal → Info) is rejected with an Err.
    pub fn transition(&self, next: LogState) -> Result<LogState, String> {
        if next.severity() >= self.severity() {
            Ok(next)
        } else {
            Err(format!(
                "illegal downgrade: {:?} (severity {}) → {:?} (severity {})",
                self,
                self.severity(),
                next,
                next.severity(),
            ))
        }
    }
}

pub struct Logger {
    state: LogState,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            state: LogState::Info,
        }
    }

    /// Explicit state transition — returns Err if the move would lower severity.
    pub fn set_state(&mut self, next: LogState) -> Result<(), String> {
        self.state = self.state.transition(next)?;
        Ok(())
    }

    pub fn state(&self) -> &LogState {
        &self.state
    }

    pub fn log_fmt(&self, args: std::fmt::Arguments) {
        println!("{} {}", self.state.label(), args);
    }

    pub fn info_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Info);
        println!("{} {}", LogState::Info.label(), args);
    }

    pub fn debug_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Debug);
        println!("{} {}", LogState::Debug.label(), args);
    }

    pub fn error_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Error);
        println!("{} {}", LogState::Error.label(), args);
    }

    pub fn fatal_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Fatal);
        println!("{} {}", LogState::Fatal.label(), args);
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}
