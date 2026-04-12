use std::fmt::Display;
use std::time::Duration;

use console::Style;

// -- Style constructors (kept for direct use in templates, metadata, etc.) --

pub fn success() -> Style {
    Style::new().green()
}

pub fn error() -> Style {
    Style::new().red().bold()
}

pub fn warning() -> Style {
    Style::new().yellow()
}

pub fn label() -> Style {
    Style::new().cyan().bold()
}

pub fn bold() -> Style {
    Style::new().bold()
}

pub fn dim() -> Style {
    Style::new().dim()
}

// -- Output helpers --

/// Print a status line to stderr: `Label: message`
pub fn log(lbl: &str, msg: impl Display) {
    eprintln!("{} {msg}", label().apply_to(format!("{lbl}:")));
}

/// Print a completion line to stderr: `prefix elapsed`
pub fn log_done(prefix: &str, elapsed: Duration) {
    eprintln!(
        "{} {}",
        success().apply_to(prefix),
        success().bold().apply_to(format!("{elapsed:.2?}"))
    );
}

/// Print a verification OK line to stdout.
pub fn print_ok(name: &str, detail: &str) {
    if detail.is_empty() {
        println!(
            "  {}    {}",
            success().apply_to("OK"),
            bold().apply_to(name)
        );
    } else {
        println!(
            "  {}    {} ({detail})",
            success().apply_to("OK"),
            bold().apply_to(name)
        );
    }
}

/// Print a verification FAIL line to stdout.
pub fn print_fail(name: &str, detail: &str) {
    println!(
        "  {}  {} ({detail})",
        error().apply_to("FAIL"),
        bold().apply_to(name)
    );
}

/// Print a verification ERR line to stdout.
pub fn print_err(name: &str, detail: impl Display) {
    println!(
        "  {}   {}: {detail}",
        error().apply_to("ERR"),
        bold().apply_to(name)
    );
}

/// Print a SKIP line to stdout.
pub fn print_skip(name: &str, detail: &str) {
    println!(
        "  {}  {}: {detail}",
        warning().apply_to("SKIP"),
        bold().apply_to(name)
    );
}

/// Print a SKIP line to stderr.
pub fn elog_skip(name: &str, detail: &str) {
    eprintln!(
        "  {}  {}: {detail}",
        warning().apply_to("SKIP"),
        bold().apply_to(name)
    );
}

/// Print a status tag + name to stderr (e.g. "HASH  init_boot").
pub fn elog_ok(tag: &str, name: &str) {
    eprintln!("  {}  {}", success().apply_to(tag), bold().apply_to(name));
}

// -- Formatting --

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
