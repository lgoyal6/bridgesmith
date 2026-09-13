/**
 * iMessage connector (tier local-store). Reads ~/Library/Messages/chat.db
 * READ-ONLY. Everything here is a SELECT; no write path exists.
 *
 * Apple stores message dates as nanoseconds since the Cocoa epoch (2001-01-01),
 * offset 978307200 seconds from Unix. Post-Ventura the plain-text body often
 * lives in `attributedBody` (a typedstream blob) rather than `text`; for the
 * agent-facing operations we expose here (recent conversations, top contacts,
 * counts) we read `text` and metadata, which is sufficient and avoids shipping a
 * typedstream decoder. Full message-body extraction is a documented not-now.
 */
import { homedir } from "node:os";
import { join } from "node:path";
import type { LocalOp } from "./localstore.js";

// Live path. A consistent copy (sqlite3 .backup) can be used instead when FDA is
// attributed to a different process than the one running the driver.
export const IMESSAGE_DB = join(homedir(), "Library", "Messages", "chat.db");
export const IMESSAGE_DB_COPY = join(homedir(), "toolsmith", ".agent-work", "chat.copy.db");
// Sentinel origin: a parseable http URL so URL.origin works. No HTTP is ever
// made - the local-store driver installs a custom fetcher that runs SQL.
export const IMESSAGE_ORIGIN = "http://imessage.local";

const COCOA_OFFSET = 978307200;

/** Cocoa-nanosecond -> ISO. Guards the pre/post-Sierra ns-vs-s ambiguity. */
export function cocoaToIso(raw: number): string {
  const seconds = raw > 1e11 ? raw / 1e9 : raw; // ns after ~2011 vs legacy seconds
  return new Date((seconds + COCOA_OFFSET) * 1000).toISOString();
}

export const IMESSAGE_OPS: LocalOp[] = [
  {
    id: "recent_messages",
    path: "/recent_messages",
    params: [{ name: "limit", default: "20" }],
    sql: (p) => `
      SELECT
        m.ROWID            AS id,
        COALESCE(h.id,'')  AS contact,
        m.is_from_me       AS is_from_me,
        COALESCE(m.text,'') AS text,
        (m.date/1000000000.0 + ${COCOA_OFFSET}) AS unix_seconds
      FROM message m
      LEFT JOIN handle h ON m.handle_id = h.ROWID
      ORDER BY m.date DESC
      LIMIT ${clampInt(p.limit, 1, 200, 20)}`,
  },
  {
    id: "top_contacts",
    path: "/top_contacts",
    params: [{ name: "limit", default: "10" }],
    sql: (p) => `
      SELECT
        COALESCE(h.id,'') AS contact,
        COUNT(*)          AS message_count
      FROM message m
      JOIN handle h ON m.handle_id = h.ROWID
      GROUP BY h.id
      ORDER BY message_count DESC
      LIMIT ${clampInt(p.limit, 1, 100, 10)}`,
  },
];

function clampInt(raw: string | undefined, min: number, max: number, dflt: number): number {
  const n = Number.parseInt(raw ?? "", 10);
  if (Number.isNaN(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}
