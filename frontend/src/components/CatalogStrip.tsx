import { useState } from "react";
import type { Catalog, RegistryItem } from "../types/trace";

interface Props {
  catalog: Catalog;
}

// A data-driven view of the capability/attack registry (GET /api/catalog).
// Phase 0 runs none of these, but the picker mechanism renders entirely from
// the registry, so adding a feature later needs no UI change. Collapsible so it
// stays out of the way of the primary flow.
export function CatalogStrip({ catalog }: Props) {
  const [open, setOpen] = useState(false);
  const items = [...catalog.capabilities, ...catalog.attacks];
  return (
    <section className="catalog">
      <button
        className="catalog-toggle"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {open ? "▾" : "▸"} Capability &amp; attack roadmap ({items.length})
      </button>
      {open && (
        <div className="catalog-body">
          <Group title="Capabilities" items={catalog.capabilities} />
          <Group title="Attacks" items={catalog.attacks} />
        </div>
      )}
    </section>
  );
}

function Group({ title, items }: { title: string; items: RegistryItem[] }) {
  return (
    <div className="catalog-group">
      <h3 className="catalog-group-title">{title}</h3>
      <ul className="catalog-items">
        {items.map((it) => (
          <li key={it.id}>
            <button
              className="catalog-chip"
              disabled={!it.available}
              title={`${it.description} — ${it.spec_ref.rfc} ${it.spec_ref.section}`}
            >
              <span className="catalog-chip-label">{it.label}</span>
              <span className="catalog-chip-phase">
                {it.available ? "available" : `phase ${it.phase}`}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
