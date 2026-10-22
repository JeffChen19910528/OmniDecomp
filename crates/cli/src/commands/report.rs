//! `report`: the combined analysis in JSON, text, CSV or HTML.

use crate::args::ReportFmt;
use crate::session::Session;
use omnidecomp_app as app;
use omnidecomp_core::Error;
use std::path::Path;

pub(super) fn report(s: &Session, file: &Path, format: ReportFmt, output: Option<&Path>) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let kind = match format {
        ReportFmt::Json => app::ExportFormat::Json,
        ReportFmt::Text => app::ExportFormat::Text,
        ReportFmt::Csv => app::ExportFormat::Csv,
        ReportFmt::Html => app::ExportFormat::Html,
    };
    let text = app::export_report(&a, &s.ctx, kind)?;
    match output {
        Some(path) => app::write_output(path, text.as_bytes(), file)?,
        None => println!("{text}"),
    }
    Ok(())
}
