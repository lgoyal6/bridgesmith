/**
 * Synthetic HAR generators for deterministic pipeline tests. Two capture
 * sessions (A = derive, B = holdout) of a fake "events API" with realistic
 * shape: a list endpoint and a by-id endpoint, stable schema, id-like path
 * segments, an enum field, a nullable field.
 */

interface Event {
  id: string;
  title: string;
  status: "draft" | "published" | "cancelled";
  startDate: string;
  capacity: number;
  venue: string | null;
}

function evt(n: number, over: Partial<Event> = {}): Event {
  return {
    id: `evt_${1000 + n}`,
    title: `Event ${n}`,
    status: n % 3 === 0 ? "cancelled" : "published",
    startDate: `2026-09-${String((n % 27) + 1).padStart(2, "0")}T18:00:00Z`,
    capacity: 50 + n,
    venue: n % 4 === 0 ? null : `Venue ${n}`,
    ...over,
  };
}

function entry(method: string, url: string, body: unknown) {
  return {
    startedDateTime: "2026-09-13T10:00:00Z",
    request: { method, url, headers: [{ name: "Accept", value: "application/json" }], queryString: [] },
    response: {
      status: 200,
      headers: [{ name: "Content-Type", value: "application/json" }],
      content: { mimeType: "application/json", text: JSON.stringify(body) },
    },
  };
}

function har(entries: unknown[]) {
  return { log: { version: "1.2", entries } };
}

/** Capture A: derive the spec from these. Enough by-id samples that the status
 *  enum and the nullable venue are both inferred. */
export function captureA() {
  const base = "https://api.example-events.com";
  const byId = [1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => entry("GET", `${base}/api/events/evt_${1000 + n}`, evt(n)));
  const entries = [
    entry("GET", `${base}/api/events?limit=10`, { events: [evt(1), evt(2), evt(3)], total: 3 }),
    entry("GET", `${base}/api/events?limit=10&offset=10`, { events: [evt(4), evt(5)], total: 5 }),
    ...byId,
    // noise: non-JSON asset and a 4xx, both should be filtered out
    {
      startedDateTime: "2026-09-13T10:00:00Z",
      request: { method: "GET", url: `${base}/static/app.js`, headers: [], queryString: [] },
      response: { status: 200, headers: [{ name: "Content-Type", value: "application/javascript" }], content: { mimeType: "application/javascript", text: "console.log(1)" } },
    },
  ];
  return har(entries);
}

/** Capture B: independent session, same schema, DIFFERENT ids/values. The holdout. */
export function captureB() {
  const base = "https://api.example-events.com";
  const entries = [
    entry("GET", `${base}/api/events?limit=10`, { events: [evt(7), evt(8, { venue: null }), evt(9)], total: 3 }),
    entry("GET", `${base}/api/events/evt_1007`, evt(7)),
    entry("GET", `${base}/api/events/evt_1008`, evt(8, { venue: null })),
    entry("GET", `${base}/api/events/evt_1012`, evt(12, { status: "draft" })),
  ];
  return har(entries);
}

/** A poisoned holdout: an extra required field is MISSING and a type is flipped.
 *  Certification must refuse the affected op. */
export function capturePoisoned() {
  const base = "https://api.example-events.com";
  const broken = { id: "evt_2001", title: 12345, startDate: "2026-09-20T18:00:00Z", capacity: 60, venue: "V" }; // title wrong type, status missing
  const entries = [
    entry("GET", `${base}/api/events/evt_2001`, broken),
  ];
  return har(entries);
}
