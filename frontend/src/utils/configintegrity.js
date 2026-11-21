/**
 * Trust only the backend's actual signature verification, and only for the
 * same exact active revision that this view currently displays.
 * This never asserts that a live Gateway has loaded the revision.
 */
export function displayedConfigIntegrity(activeRevision, proof) {
  if (!activeRevision) return { status: "NO_ACTIVE", message: "No published security revision is available." };
  if (!proof) return { status: "NOT_CHECKED", message: "Published revision verification has not completed." };
  if (proof.status !== "VERIFIED") {
    return { status: "NOT_VERIFIED", message: "The published revision could not be cryptographically verified." };
  }
  const same =
    proof.revision_id === activeRevision.id
    && proof.revision_number === activeRevision.revision_number
    && proof.content_hash === activeRevision.content_hash
    && activeRevision.status === "PUBLISHED";
  if (!same) {
    return { status: "MISMATCH", message: "The verified backend revision differs from the revision displayed here. Refresh before relying on it." };
  }
  return {
    status: "VERIFIED",
    message: "Backend verification passed for the exact displayed published revision, its content and its signature chain.",
  };
}
