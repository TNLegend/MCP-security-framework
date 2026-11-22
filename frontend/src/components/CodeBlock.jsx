import { useId, useState } from "react";

const COLLAPSE_LINES = 14;

export function formatCodeValue(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

/**
 * Read-only evidence viewer for JSON and other technical payloads.
 * Keeps indentation (no wrapping), scrolls horizontally for long tokens, offers
 * Copy, and collapses verbose payloads behind an explicit disclosure.
 */
export default function CodeBlock({ value, label, collapsed, tall = false, emptyText = "Not recorded" }) {
  const text = formatCodeValue(value);
  const lines = text ? text.split("\n").length : 0;
  const collapsible = collapsed ?? lines > COLLAPSE_LINES;
  const [open, setOpen] = useState(!collapsible);
  const [copied, setCopied] = useState("");
  const regionId = useId();

  if (!text) return <span className="code-empty">{emptyText}</span>;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied("Copied");
    } catch {
      setCopied("Copy unavailable");
    }
    window.setTimeout(() => setCopied(""), 2000);
  }

  return (
    <div className={"code-viewer" + (tall ? " is-tall" : "")}>
      <div className="code-viewer-head">
        <span>{label ? label + " · " : ""}{lines} {lines === 1 ? "line" : "lines"}</span>
        <span className="code-viewer-actions">
          {copied && <span role="status" className="code-viewer-status">{copied}</span>}
          {collapsible && (
            <button type="button" className="tiny-action" aria-expanded={open} aria-controls={regionId}
              onClick={() => setOpen((value) => !value)}>
              {open ? "Hide" : "Show"}
            </button>
          )}
          <button type="button" className="tiny-action" onClick={copy}
            aria-label={"Copy " + (label || "value")}>Copy</button>
        </span>
      </div>
      {open && (
        <pre id={regionId} tabIndex={0} aria-label={label ? label + " value" : "Technical value"}>{text}</pre>
      )}
    </div>
  );
}
