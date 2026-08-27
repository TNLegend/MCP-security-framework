export function schemaLeafPaths(schema) {
  const paths = [];
  function visit(node, prefix) {
    if (!node || typeof node !== "object") return;
    const properties = node.properties || {};
    Object.entries(properties).forEach(([key, child]) => {
      const path = [...prefix, key];
      if (child?.type === "object" || child?.properties) visit(child, path);
      else if (child?.type === "array" && child?.items) visit(child.items, [...path, "*"]);
      else paths.push(path.join("."));
    });
  }
  visit(schema || {}, []);
  return paths;
}

export function hasRecordedInputSchema(schema) {
  return Boolean(
    schema
    && typeof schema === "object"
    && !Array.isArray(schema)
    && Object.keys(schema).length > 0
  );
}

export function cleanMappings(mappings) {
  return Object.fromEntries(
    Object.entries(mappings).filter(([, path]) => Array.isArray(path) && path.length > 0),
  );
}
