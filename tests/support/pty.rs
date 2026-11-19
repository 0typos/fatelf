//! A Linux pseudo-terminal for testing child processes without using the runner's terminal.

use std::{
    ffi::{CStr, OsStr},
    fs::File,
    io::{Error, ErrorKind, Read},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt, process::CommandExt},
    },
    process::Command,
};

pub struct Pty {
    pub master: File,
    slave: File,
}

impl Pty {
    pub fn open() -> Self {
        let master = File::options()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open("/dev/ptmx")
            .unwrap();
        let mut name = [0; 128];
        // SAFETY: the master descriptor is open and the name buffer is writable.
        let slave_name = unsafe {
            assert_eq!(libc::grantpt(master.as_raw_fd()), 0);
            assert_eq!(libc::unlockpt(master.as_raw_fd()), 0);
            assert_eq!(
                libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()),
                0
            );
            CStr::from_ptr(name.as_ptr())
        };
        // File::open sets O_CLOEXEC atomically, including when other tests spawn children.
        let slave = File::options()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(OsStr::from_bytes(slave_name.to_bytes()))
            .unwrap();
        let window = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads the initialized winsize while the slave is open.
        unsafe {
            assert_eq!(
                libc::ioctl(
                    slave.as_raw_fd(),
                    libc::TIOCSWINSZ,
                    std::ptr::from_ref(&window).cast::<libc::c_void>()
                ),
                0
            );
        }
        Self { master, slave }
    }

    pub fn attach(&self, command: &mut Command, controlling: bool) {
        command
            .env("TERM", "xterm")
            .stdin(self.slave.try_clone().unwrap())
            .stdout(self.slave.try_clone().unwrap());
        // SAFETY: the child only uses async-signal-safe syscalls before exec.
        unsafe {
            command.pre_exec(move || {
                let mut signals = MaybeUninit::<libc::sigset_t>::zeroed();
                if libc::setsid() == -1
                    || (controlling
                        && libc::ioctl(0, libc::TIOCSCTTY, std::ptr::null::<libc::c_void>()) == -1)
                    || libc::signal(libc::SIGTERM, libc::SIG_DFL) == libc::SIG_ERR
                    || libc::sigemptyset(signals.as_mut_ptr()) == -1
                    || libc::sigaddset(signals.as_mut_ptr(), libc::SIGTERM) == -1
                    || libc::sigprocmask(libc::SIG_UNBLOCK, signals.as_ptr(), std::ptr::null_mut())
                        == -1
                {
                    return Err(Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    pub fn settings(&self) -> libc::termios {
        let mut termios = MaybeUninit::<libc::termios>::zeroed();
        // SAFETY: zero initialization covers fields the kernel may leave untouched.
        unsafe {
            assert_eq!(
                libc::tcgetattr(self.slave.as_raw_fd(), termios.as_mut_ptr()),
                0
            );
            termios.assume_init()
        }
    }

    pub fn is_raw(&self) -> bool {
        self.settings().c_lflag & libc::ICANON == 0
    }

    pub fn assert_restored(&self, before: &libc::termios) {
        let after = self.settings();
        assert_eq!(after.c_iflag, before.c_iflag);
        assert_eq!(after.c_oflag, before.c_oflag);
        assert_eq!(after.c_cflag, before.c_cflag);
        assert_eq!(after.c_lflag, before.c_lflag);
        assert_eq!(after.c_cc, before.c_cc);
    }

    pub fn drain(&mut self, transcript: &mut Vec<u8>) {
        let mut buffer = [0; 4096];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => transcript.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("could not read editor output: {error}"),
            }
        }
    }
}
