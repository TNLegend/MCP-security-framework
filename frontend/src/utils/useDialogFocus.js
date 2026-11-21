import { useLayoutEffect } from "react";

const FOCUSABLE = [
  "a[href]", "button:not([disabled])", "input:not([disabled])",
  "select:not([disabled])", "textarea:not([disabled])",
  "[tabindex]:not([tabindex=\"-1\"])",
].join(", ");

export function useDialogFocus(active, dialogRef, { focusContainer = false } = {}) {
  useLayoutEffect(() => {
    if (!active || !dialogRef.current) return undefined;
    const dialog = dialogRef.current;
    const previousFocus = document.activeElement;
    const focusable = () => [...dialog.querySelectorAll(FOCUSABLE)].filter((item) =>
      item.tabIndex >= 0 && !item.matches(":disabled") && !item.closest("[hidden], [inert], [aria-hidden='true']")
      && item.getClientRects().length > 0 && getComputedStyle(item).visibility === "visible",
    );
    const blockedElements = [];
    for (let branch = dialog; branch.parentElement; branch = branch.parentElement) {
      for (const sibling of branch.parentElement.children) {
        if (sibling !== branch && sibling instanceof HTMLElement && !sibling.inert) {
          sibling.inert = true;
          blockedElements.push(sibling);
        }
      }
      if (branch.parentElement === document.body) break;
    }
    (focusContainer ? dialog : focusable()[0] || dialog).focus();

    function retainFocus(event) {
      if (event.key !== "Tab") return;
      const nextItems = focusable();
      if (nextItems.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const focusIndex = nextItems.indexOf(document.activeElement);
      if (event.shiftKey && focusIndex <= 0) {
        event.preventDefault();
        nextItems.at(-1).focus();
      } else if (!event.shiftKey && (focusIndex < 0 || focusIndex === nextItems.length - 1)) {
        event.preventDefault();
        nextItems[0].focus();
      }
    }

    document.addEventListener("keydown", retainFocus, true);
    return () => {
      document.removeEventListener("keydown", retainFocus, true);
      for (const element of blockedElements) element.inert = false;
      if (previousFocus?.isConnected && typeof previousFocus.focus === "function") {
        previousFocus.focus({ preventScroll: true });
      }
    };
  }, [active, dialogRef, focusContainer]);
}
