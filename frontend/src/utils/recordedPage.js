// An offset page can shift when new evidence is written. Keep previously displayed
// results until a fresh read establishes the new ordering.
export function validateRecordedPage(page, previousItems, collection) {
  if (!Array.isArray(page?.items) || page.offset !== previousItems.length ||
      page.returned !== page.items.length ||
      !Number.isInteger(page.total) || page.total < page.offset + page.returned ||
      typeof page.has_more !== "boolean" ||
      page.has_more !== (page.offset + page.returned < page.total) ||
      (page.has_more && page.items.length === 0) ||
      (collection && page.collection !== collection)) {
    throw new Error("Recorded results page did not match the request.");
  }
  const ids = new Set(previousItems.map((item) => item.id));
  for (const item of page.items) {
    if (item?.id == null || ids.has(item.id)) {
      throw new Error("Recorded results changed while loading. Refresh before continuing.");
    }
    ids.add(item.id);
  }
}
