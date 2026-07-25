//! The single source of truth for the A2UI component catalog text.
//!
//! `cli-multi-session-relay` design.md D4: "azula ui catalog and the long
//! --help texts embed the same component catalog the render_ui MCP tool
//! description carries (single source in the crate, referenced by both)".
//!
//! [`A2UI_CATALOG`] is that one string. Three consumers reference it instead
//! of duplicating it:
//! - `bridge::tools::AzulaBridge::new` sets the `render_ui` MCP tool's
//!   description at runtime (the `#[tool(description = "...")]` attribute
//!   only accepts a string literal — see that constructor's comment for why
//!   the description is instead assembled and attached programmatically).
//! - `azula ui catalog` prints it directly.
//! - `azula ui render --help` carries it in the command's `long_about`,
//!   attached programmatically for the same literal-attribute reason (see
//!   `cli::build_command`).
//!
//! Keep this the *only* copy of the catalog prose in the crate — grepping the
//! source for a distinctive substring (e.g. "STRUCTURE:") should find exactly
//! one hit.

/// The A2UI basic-catalog component/prop vocabulary, in prose form, shared by
/// the MCP `render_ui` tool description, `azula ui catalog`, and
/// `azula ui render --help`.
pub const A2UI_CATALOG: &str = r##"STRUCTURE: `components` is a flat JSON array; each element is {"id":"...","component":"<Type>", ...props}. Exactly one must have "id":"root". Containers reference children by id — `child` (single id) or `children` (array of ids); never nest component objects. Optional `data_model` is a JSON object; any prop value may be a literal OR a binding {"path":"/rfc6901/pointer"} into the data model.

The app renders these in azula's "neon-glass" style (rounded, pink accent). Text is Markdown-rendered.

COMPONENTS (props):
- Text: text (string|binding; Markdown: ### headings, - bullets, **bold**, *italic*, `code`); variant: h1|h2|h3|h4|h5|h6|body(default)|caption(italic, dimmed).
- Row: children[]; justify: start|center|end|spaceBetween|spaceAround|spaceEvenly; align: start|center|end.
- Column: children[]; justify (vertical), align (horizontal).
- List: children[]; direction: vertical(default)|horizontal(scrolls); align.
- Card: child; variant: (default, filled surface) | nested (transparent + outline).
- Divider: axis: horizontal(default)|vertical.
- Tabs: tabs: [{"title":"...","child":"<id>"}] (underline style; local selection).
- Modal: trigger:<id>, content:<id> (tapping the trigger opens content in a glass sheet with a ✕ close).
- Button: child:<id> (its label, usually a Text); variant: default|primary(gradient)|borderless; action:{"event":{"name":"<event>","context":{...}}}.
- TextField: label; value:{"path":"/f"} (two-way — edits write to the data model); variant: shortText(default)|longText|number|obscured.
- CheckBox: label; value:{"path":"/flag"} (boolean, two-way).
- ChoicePicker: label; value:{"path":"/sel"} (array); options:[{"value","label","description"?}]; variant: mutuallyExclusive(default,single)|multipleSelection; displayStyle: chips(default, pills)|checkbox (radio for single, tick for multi).
- Slider: label; value:{"path":"/n"}; min(default 0); max(default 100).
- DateTimeInput: label; value:{"path":"/dt"} (ISO 8601 string).
- Image: url — MUST be a data URI ("data:image/png;base64,...."); http URLs render a themed placeholder. variant (size preset): icon|avatar(round)|smallFeature|mediumFeature(default)|largeFeature|header. fit: contain(default)|cover|stretch.
- Icon: name — vector icons: bolt|terminal|lock|link|chat|controls (others: check|close|add|settings|star|warning|home|search|…); inherits text color.
- Video: url — styled mock player (play button + scrubber; no live playback).
- AudioPlayer: url — a `data:audio/...;base64,...` URI plays for real (play/pause + seekable waveform); a remote http url or no url renders the same static mock player as before (no live playback).

INTERACTION: A Button tap emits a `ui-event: {"name","surfaceId","sourceComponentId","context"}` line you receive via wait_for_reply / get_messages (context bindings are resolved against the current data model). Input components (TextField/CheckBox/ChoicePicker/Slider) write into the data model at their bound path; to READ those values, reference them in a Button's action `context` (e.g. "context":{"note":{"path":"/note"}}) — the tap's ui-event then carries the resolved values. Respond by calling update_ui (change the data model at a JSON-pointer) or render_ui (a new surface).

EXAMPLE (a name form):
components: [
  {"id":"root","component":"Card","child":"col"},
  {"id":"col","component":"Column","children":["t","f","btn"],"align":"center"},
  {"id":"t","component":"Text","text":"What's your name?","variant":"h2"},
  {"id":"f","component":"TextField","label":"name","value":{"path":"/name"}},
  {"id":"lbl","component":"Text","text":"Submit"},
  {"id":"btn","component":"Button","child":"lbl","variant":"primary","action":{"event":{"name":"submit","context":{"name":{"path":"/name"}}}}}
]
data_model: {"name":""}"##;

/// The short, tool-specific sentence prefixed to [`A2UI_CATALOG`] to build the
/// full `render_ui` MCP tool description (see `bridge::tools::AzulaBridge::new`).
pub const RENDER_UI_INTRO: &str =
    "Render an interactive A2UI surface in the azula app on a device. Returns the surfaceId (pass it to update_ui / delete_ui).";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_documents_every_known_component() {
        for name in [
            "Text", "Row", "Column", "List", "Card", "Divider", "Tabs", "Modal", "Button",
            "TextField", "CheckBox", "ChoicePicker", "Slider", "DateTimeInput", "Image", "Icon",
            "Video", "AudioPlayer",
        ] {
            assert!(A2UI_CATALOG.contains(name), "catalog missing component: {name}");
        }
    }
}
