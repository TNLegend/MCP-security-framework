import { useEffect } from "react";

const FOCUSABLE = [
  "a[href]", "button:not([disabled])", "input:not([disabled])",
  "select:not([disabled])", "textarea:not([disabled])",
  "[tabindex]:not([tabindex=\"-1\"])",
].join(", ");

export function useDialogFocus(active, dialogRef) {
  useEffect(() => {
    if (!active || !dialogRef.current) return undefined;
    const dialog = dialogRef.current;
    const previousFocus = document.activeElement;
    const focusable = () => [...dialog.querySelectorAll(FOCUSABLE)]
      .filter((item) => !item.hasAttribute("hidden") && item.getAttribute("aria-hidden") !== "true");
    const items = focusable();
    (items[0] || dialog).focus();

    function retainFocus(event) {
      if (event.key !== "Tab") return;
      const nextItems = focusable();
      if (nextItems.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = nextItems[0];
      const last = nextItems[nextItems.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    dialog.addEventListener("keydown", retainFocus);
    return () => {
      dialog.removeEventListener("keydown", retainFocus);
      if (previousFocus?.isConnected && typeof previousFocus.focus === "function") {
        previousFocus.focus();
      }
    };
  }, [active, dialogRef]);
}
