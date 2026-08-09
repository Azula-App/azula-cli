//! `azula ui render|update|delete|catalog`.

use anyhow::Result;

#[derive(Debug, Clone, clap::Args)]
pub(super) struct UiArgs {
    #[command(subcommand)]
    pub(super) action: UiAction,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub(super) enum UiAction {
    /// Render an A2UI declarative surface on a device.
    Render(UiRenderArgs),
    /// Update a rendered surface's data model at an RFC 6901 pointer.
    Update(UiUpdateArgs),
    /// Remove a rendered surface from a device.
    Delete(UiDeleteArgs),
    /// Print the A2UI component catalog (same source the render_ui MCP tool uses).
    Catalog(UiCatalogArgs),
}

/// `long_about` here is a short placeholder; `cli::build_command` overwrites
/// it at startup with the full `catalog::A2UI_CATALOG` prose (the
/// `#[command(long_about = ...)]` attribute only accepts a string literal, so
/// it can't reference that `const` directly — see `catalog`'s module docs
/// for the same constraint on the MCP tool description).
#[derive(Debug, Clone, clap::Args)]
#[command(long_about = "Render an A2UI declarative surface on a device. Components JSON comes from FILE or stdin (`-`). Run `azula ui catalog` for the full component vocabulary; this command's own --help carries it too.")]
pub(super) struct UiRenderArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// Surface id. A unique one is generated if omitted; pass an existing id
    /// to replace that card.
    #[arg(long = "surface", value_name = "ID")]
    surface: Option<String>,
    /// Optional initial data model as inline JSON, backing `{"path":...}` bindings.
    #[arg(long = "data-model", value_name = "JSON")]
    data_model: Option<String>,
    /// Path to a JSON file holding the components array, or `-` for stdin.
    file: String,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct UiUpdateArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// The surface id returned by `ui render`.
    #[arg(long = "surface", value_name = "ID", required = true)]
    surface: String,
    /// RFC 6901 JSON pointer into the data model (`""` targets the whole model).
    pointer: String,
    /// The new value to set at `pointer`, as JSON.
    value: String,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct UiDeleteArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// The surface id to remove.
    #[arg(long = "surface", value_name = "ID", required = true)]
    surface: String,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct UiCatalogArgs {
    /// Machine-readable output (wraps the catalog prose in a JSON object).
    #[arg(long)]
    json: bool,
}

/// Parse a components JSON payload (as `ui render` reads from FILE or stdin)
/// and apply the same client-side root-component validation `SessionCore::
/// render_ui` applies — cli-surface spec: "Invalid component trees SHALL be
/// rejected client-side with the same root-component validation the MCP tool
/// applies", and the "Missing root rejected locally" scenario: rejected
/// before anything is sent. A standalone, `std::process::exit`-free function
/// so it's directly unit-testable.
fn parse_and_validate_components(raw: &str) -> std::result::Result<serde_json::Value, String> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON in components: {e}"))?;
    crate::core::validate_a2ui_components(&value).map_err(|e| e.to_string())?;
    Ok(value)
}

pub(super) async fn render(args: UiRenderArgs) -> Result<()> {
    let raw = match read_input(&args.file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read '{}': {e}", args.file);
            std::process::exit(2);
        }
    };
    let components = match parse_and_validate_components(&raw) {
        Ok(v) => v,
        Err(msg) => {
            // Validation runs before any endpoint is bound or device dialed
            // — nothing is sent on rejection.
            eprintln!("error: {msg}");
            std::process::exit(2);
        }
    };

    let data_model = match &args.data_model {
        Some(s) => match serde_json::from_str(s) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("error: invalid JSON in --data-model: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est = crate::core::establish("cli", vec![], None, Some(session_name)).await?;
    let core = est.core;
    let device = super::resolve_or_exit(&core, args.device.device.as_deref()).await;

    match core.render_ui(&device, components, data_model, args.surface).await {
        Ok(surface_id) => {
            if args.json {
                super::print_json(&serde_json::json!({"status": "rendered", "device": device, "surface": surface_id}));
            } else {
                println!("rendered surface '{surface_id}' on '{device}'");
            }
        }
        Err(e) => super::exit_core_error(&e),
    }
    Ok(())
}

pub(super) async fn update(args: UiUpdateArgs) -> Result<()> {
    let value: serde_json::Value = match serde_json::from_str(&args.value) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid JSON value: {e}");
            std::process::exit(2);
        }
    };

    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est = crate::core::establish("cli", vec![], None, Some(session_name)).await?;
    let core = est.core;
    let device = super::resolve_or_exit(&core, args.device.device.as_deref()).await;

    match core.update_ui(&device, &args.surface, &args.pointer, value).await {
        Ok(()) => {
            if args.json {
                super::print_json(&serde_json::json!({
                    "status": "updated", "device": device, "surface": args.surface, "pointer": args.pointer,
                }));
            } else {
                println!("updated surface '{}' at '{}'", args.surface, args.pointer);
            }
        }
        Err(e) => super::exit_core_error(&e),
    }
    Ok(())
}

pub(super) async fn delete(args: UiDeleteArgs) -> Result<()> {
    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est = crate::core::establish("cli", vec![], None, Some(session_name)).await?;
    let core = est.core;
    let device = super::resolve_or_exit(&core, args.device.device.as_deref()).await;

    match core.delete_ui(&device, &args.surface).await {
        Ok(()) => {
            if args.json {
                super::print_json(&serde_json::json!({"status": "deleted", "device": device, "surface": args.surface}));
            } else {
                println!("deleted surface '{}'", args.surface);
            }
        }
        Err(e) => super::exit_core_error(&e),
    }
    Ok(())
}

pub(super) fn catalog(args: UiCatalogArgs) -> Result<()> {
    if args.json {
        super::print_json(&serde_json::json!({"catalog": crate::catalog::A2UI_CATALOG}));
    } else {
        println!("{}", crate::catalog::A2UI_CATALOG);
    }
    Ok(())
}

fn read_input(file: &str) -> std::io::Result<String> {
    if file == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulates `azula ui render -` piping a valid components array with a
    /// root component: the same parse+validate path `render()` runs before
    /// ever binding an endpoint should accept it.
    #[test]
    fn stdin_payload_with_root_component_is_accepted() {
        let stdin_payload = r#"[{"id":"root","component":"Text","text":"hi"}]"#;
        let result = parse_and_validate_components(stdin_payload);
        assert!(result.is_ok(), "{result:?}");
    }

    /// cli-surface spec, "Missing root rejected locally": a piped components
    /// array with no `"id":"root"` entry is rejected before anything would
    /// be sent — `render()` never reaches `SessionCore::establish`/dialing
    /// for a payload that fails here.
    #[test]
    fn stdin_payload_missing_root_is_rejected() {
        let stdin_payload = r#"[{"id":"not-root","component":"Text","text":"hi"}]"#;
        let err = parse_and_validate_components(stdin_payload).unwrap_err();
        assert!(err.contains("\"id\":\"root\""), "{err}");
    }

    #[test]
    fn stdin_payload_that_is_not_a_json_array_is_rejected() {
        let stdin_payload = r#"{"id":"root"}"#;
        let err = parse_and_validate_components(stdin_payload).unwrap_err();
        assert!(err.contains("JSON array"), "{err}");
    }

    #[test]
    fn stdin_payload_with_invalid_json_is_rejected() {
        let stdin_payload = "not json at all";
        let err = parse_and_validate_components(stdin_payload).unwrap_err();
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn valid_components_with_root_pass_core_validation() {
        let components = serde_json::json!([{"id": "root", "component": "Text", "text": "hi"}]);
        assert!(crate::core::validate_a2ui_components(&components).is_ok());
    }

    #[test]
    fn missing_root_is_rejected_by_core_validation() {
        let components = serde_json::json!([{"id": "not-root", "component": "Text", "text": "hi"}]);
        let err = crate::core::validate_a2ui_components(&components).unwrap_err();
        assert!(matches!(err, crate::core::CoreError::Usage(_)));
        assert!(err.to_string().contains("\"id\":\"root\""), "{err}");
    }

    #[test]
    fn non_array_components_is_rejected_by_core_validation() {
        let components = serde_json::json!({"id": "root"});
        let err = crate::core::validate_a2ui_components(&components).unwrap_err();
        assert!(matches!(err, crate::core::CoreError::Usage(_)));
        assert!(err.to_string().contains("JSON array"), "{err}");
    }
}
