use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
pub struct BuildInfo {
    pub schema_version: u32,
    pub component: &'static str,
    pub version: &'static str,
    pub build_id: &'static str,
    pub source_commit: &'static str,
}

pub const fn identity(component: &'static str) -> BuildInfo {
    BuildInfo {
        schema_version: 1,
        component,
        version: env!("P2KES_EMBEDDED_VERSION"),
        build_id: env!("P2KES_EMBEDDED_BUILD_ID"),
        source_commit: env!("P2KES_EMBEDDED_SOURCE_COMMIT"),
    }
}

pub fn write_version(
    mut output: impl Write,
    component: &'static str,
    json: bool,
) -> io::Result<()> {
    let info = identity(component);
    if json {
        serde_json::to_writer(&mut output, &info)?;
        writeln!(output)?;
    } else {
        writeln!(
            output,
            "{} {} (build {}, source {})",
            info.component, info.version, info.build_id, info.source_commit
        )?;
    }
    output.flush()
}
