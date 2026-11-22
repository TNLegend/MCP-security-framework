import { nestedPathDiff } from "../utils/nestedPathDiff.js";

export default function NestedChanges({ before, after, label }) {
  const { rows, unchanged, omitted } = nestedPathDiff(before, after);
  return <section className="nested-changes" aria-label={label}>
    <h4>{label}</h4>
    <p>{unchanged} unchanged keys or positions omitted.{omitted > 0 && ` ${omitted} additional changes omitted.`}</p>
    {rows.length === 0 ? <p>No recorded field differences.</p> : <ul>
      {rows.map((row) => (
        <li key={row.path}>
          <div><code>{row.path}</code> <strong>{row.kind}</strong></div>
          <dl>
            <div><dt>Before · {row.beforeType}</dt><dd><code>{row.before}</code></dd></div>
            <div><dt>After · {row.afterType}</dt><dd><code>{row.after}</code></dd></div>
          </dl>
        </li>
      ))}
    </ul>}
  </section>;
}
