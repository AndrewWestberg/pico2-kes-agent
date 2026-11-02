use std::io::{self, IsTerminal, Stdout};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::{cursor, execute, terminal};
use ratatui::{Terminal, backend::CrosstermBackend};

static OWNER: AtomicBool = AtomicBool::new(false);
static RAW: AtomicBool = AtomicBool::new(false);
static ALTERNATE: AtomicBool = AtomicBool::new(false);
static CURSOR: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK: Once = Once::new();

fn combine(first: io::Error, second: io::Error) -> io::Error {
    io::Error::new(
        first.kind(),
        format!("{first}; terminal restoration: {second}"),
    )
}

fn handoff_result<T>(result: io::Result<T>, resume: io::Result<()>) -> io::Result<T> {
    match (result, resume) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(resume_error)) => Err(combine(error, resume_error)),
    }
}

fn restore() -> io::Result<()> {
    let mut error = None;
    for (flag, result) in [
        (
            &CURSOR,
            if CURSOR.load(Ordering::SeqCst) {
                execute!(io::stdout(), cursor::Show)
            } else {
                Ok(())
            },
        ),
        (
            &ALTERNATE,
            if ALTERNATE.load(Ordering::SeqCst) {
                execute!(io::stdout(), terminal::LeaveAlternateScreen)
            } else {
                Ok(())
            },
        ),
        (
            &RAW,
            if RAW.load(Ordering::SeqCst) {
                terminal::disable_raw_mode()
            } else {
                Ok(())
            },
        ),
    ] {
        match result {
            Ok(()) => flag.store(false, Ordering::SeqCst),
            Err(next) => {
                error = Some(match error {
                    Some(previous) => combine(previous, next),
                    None => next,
                })
            }
        }
    }
    error.map_or(Ok(()), Err)
}

fn enter() -> io::Result<()> {
    RAW.store(true, Ordering::SeqCst);
    terminal::enable_raw_mode()?;
    ALTERNATE.store(true, Ordering::SeqCst);
    execute!(io::stdout(), terminal::EnterAlternateScreen)?;
    CURSOR.store(true, Ordering::SeqCst);
    execute!(io::stdout(), cursor::Hide)
}

/// The sole owner of the manager's terminal state.
///
/// The caller must stop and join terminal input and observation activity before
/// suspension or foreground handoff, and restart it only after a successful resume.
pub struct TerminalOwner {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    suspended: bool,
    closed: bool,
}

impl TerminalOwner {
    pub fn acquire() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::other("interactive terminal required"));
        }
        if OWNER
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(io::Error::other(
                "terminal already owned or restoration failed",
            ));
        }
        PANIC_HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if let Err(error) = restore() {
                    eprintln!("terminal restoration failed during panic: {error}");
                }
                previous(info);
            }));
        });

        let result = (|| {
            if terminal::is_raw_mode_enabled()? {
                return Err(io::Error::other("terminal raw mode is already owned"));
            }
            enter()?;
            Ok(Self {
                terminal: Terminal::new(CrosstermBackend::new(io::stdout()))?,
                suspended: false,
                closed: false,
            })
        })();
        match result {
            Ok(owner) => Ok(owner),
            Err(error) => match restore() {
                Ok(()) => {
                    OWNER.store(false, Ordering::SeqCst);
                    Err(error)
                }
                Err(restore_error) => Err(combine(error, restore_error)),
            },
        }
    }

    pub fn terminal(&mut self) -> io::Result<&mut Terminal<CrosstermBackend<Stdout>>> {
        if self.suspended || self.closed {
            return Err(io::Error::other("terminal is not active"));
        }
        Ok(&mut self.terminal)
    }

    /// Caller must first stop and join terminal input and observation activity.
    pub fn suspend(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::other("terminal is closed"));
        }
        self.suspended = true;
        restore()
    }

    pub fn resume(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::other("terminal is closed"));
        }
        if !self.suspended {
            return Ok(());
        }
        // Complete any failed prior restoration before taking ownership again.
        restore()?;
        let result = enter().and_then(|()| self.terminal.clear());
        if let Err(error) = result {
            return match restore() {
                Ok(()) => Err(error),
                Err(restore_error) => Err(combine(error, restore_error)),
            };
        }
        self.suspended = false;
        Ok(())
    }

    /// The caller must pause input/observations first and must not put passphrases
    /// in the command's arguments or environment. The child receives direct stdio.
    pub fn foreground(
        &mut self,
        command: &mut Command,
        acknowledge: bool,
    ) -> io::Result<ExitStatus> {
        self.suspend()?;
        let result = command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .and_then(|status| {
                if acknowledge || !status.success() {
                    eprintln!("Child exit: {status}. Press Enter to return.");
                    let mut byte = [0];
                    loop {
                        match rustix::io::read(io::stdin(), &mut byte) {
                            Ok(0) => break,
                            Ok(_) if byte[0] == b'\n' => break,
                            Ok(_) | Err(rustix::io::Errno::INTR) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                Ok(status)
            });
        handoff_result(result, self.resume())
    }

    /// Explicitly close to report restoration errors; Drop retries on failure.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.suspended = true;
        restore()?;
        self.closed = true;
        OWNER.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Drop for TerminalOwner {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("terminal restoration failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::handoff_result;
    use std::io;

    #[test]
    fn handoff_reports_spawn_and_resume_failures() {
        let spawn = io::Error::new(io::ErrorKind::NotFound, "spawn failed");
        let resume = io::Error::other("resume failed");
        let error = handoff_result::<()>(Err(spawn), Err(resume)).unwrap_err();
        assert!(error.to_string().contains("spawn failed"));
        assert!(error.to_string().contains("resume failed"));
        assert!(handoff_result(Ok(()), Err(io::Error::other("resume failed"))).is_err());
        assert_eq!(handoff_result(Ok(42), Ok(())).unwrap(), 42);
    }
}
