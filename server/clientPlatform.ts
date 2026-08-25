import type { AnnouncementDevice } from "./announcementStore.js";

// Which kind of client is on the other end of a connection — the buckets
// live usage is broken down into on /metrics (see metrics.ts's
// clientsByPlatformGauge).
//
// Two independent sources feed this, and they answer different halves of
// the question:
//
//   1. The User-Agent of the WebSocket upgrade request. Present for every
//      connection the moment it opens, and the only thing that can tell an
//      embedded WebView from a real browser — an in-app browser is the same
//      engine with the same APIs, so nothing the page itself can measure
//      separates the two.
//   2. The client's own `device` report, sent with "register" (see the
//      website's lib/announcement.ts's currentAnnouncementDevice, the same
//      value announcement targeting already uses). This is the better
//      answer for the other half — desktop-vs-mobile and app-vs-web —
//      because it can check for the Electron bridge directly instead of
//      guessing, and because iPadOS 13+ deliberately reports a desktop
//      Safari User-Agent that no amount of server-side parsing can tell
//      apart from a real Mac (the touch-point count that gives it away is
//      only readable in the page).
//
// classifyClientPlatform below combines them, each deciding the half it is
// actually good at. Note that the report is client-controlled and therefore
// forgeable — which is fine here and nowhere else: this feeds a usage
// gauge, never an access or moderation decision.
export const CLIENT_PLATFORMS = [
  "desktop-browser",
  "desktop-webview",
  "desktop-app",
  "mobile-browser",
  "mobile-webview",
  // A connection whose kind genuinely couldn't be established: no
  // User-Agent at all, or one that isn't a browser's (monitoring probes,
  // scrapers, a hand-rolled WebSocket client). Deliberately its own bucket
  // rather than folded into desktop-browser — "we don't know" and "someone
  // on a PC" are different answers, and quietly merging them would inflate
  // the one number here anybody actually plans around.
  "unknown",
] as const;

export type ClientPlatform = (typeof CLIENT_PLATFORMS)[number];

const ANNOUNCEMENT_DEVICES = new Set<AnnouncementDevice>([
  "desktop-browser",
  "desktop-app",
  "mobile-browser",
  "mobile-app",
]);

/** Validates the `device` field of a "register" message. null when absent or unrecognized. */
export function parseDeviceReport(raw: unknown): AnnouncementDevice | null {
  return typeof raw === "string" && ANNOUNCEMENT_DEVICES.has(raw as AnnouncementDevice)
    ? (raw as AnnouncementDevice)
    : null;
}

// In-app browsers that identify themselves by name. Not exhaustive and
// never will be — anything missing here simply reads as an ordinary
// browser, which is the right direction to be wrong in: over-matching would
// move real Chrome/Safari users into a bucket that is supposed to mean
// "embedded inside someone else's app".
const NAMED_IN_APP_BROWSERS = [
  "FBAN", "FBAV", "FB_IAB", "FBIOS", // Facebook and Messenger
  "Instagram",
  "TikTok", "musical_ly", "BytedanceWebview",
  "Twitter",
  "Line/",
  "MicroMessenger", // WeChat
  "KAKAOTALK",
  "Snapchat",
  "Pinterest",
  "WhatsApp",
  "GSA/", // the Google app's built-in browser on iOS
];

function hasNamedInAppBrowser(ua: string): boolean {
  return NAMED_IN_APP_BROWSERS.some((token) => ua.includes(token));
}

function isMobileWebView(ua: string): boolean {
  if (hasNamedInAppBrowser(ua)) return true;
  // Android's WebView component tags itself in the platform section. The
  // "Version/… Chrome/" pair is the same thing from older Android releases,
  // which predate the "wv" token — Chrome itself never emits "Version/".
  if (/;\s*wv[;)]/.test(ua)) return true;
  if (/Android/.test(ua) && /Version\/[\d.]+\s+Chrome\//.test(ua)) return true;
  // An unnamed WKWebView on iOS: same engine as Safari, minus the "Safari/"
  // token Safari itself always ends with. The real browsers that aren't
  // Safari still carry it (Chrome is "CriOS/… Safari/604.1", Firefox
  // "FxiOS/… Safari/605.1.15"), so its absence is what's left over.
  if (/iPhone|iPad|iPod/.test(ua) && /AppleWebKit/.test(ua) && !/Safari\//.test(ua)) return true;
  return false;
}

function isDesktopWebView(ua: string): boolean {
  if (hasNamedInAppBrowser(ua)) return true;
  // Desktop embedding frameworks that announce themselves. Electron is
  // handled before this is ever reached (see classifyClientPlatform).
  return /QtWebEngine|CefSharp|AtomShell|MSAppHost|WebView2|;\s*wv[;)]/.test(ua);
}

// Phones and tablets, from the User-Agent alone. Used only as the fallback
// for a client that sent no `device` report — see the iPadOS caveat in this
// file's header for why the report is the better answer when there is one.
function isMobileUserAgent(ua: string): boolean {
  return /Android|iPhone|iPad|iPod|IEMobile|Windows Phone|BlackBerry|BB10|Opera Mini/i.test(ua);
}

/**
 * The bucket this connection belongs in.
 *
 * `reportedDevice` is the client's own answer (null for a connection that
 * hasn't registered yet, or an older client that predates the field) and
 * decides desktop-vs-mobile and app-vs-web; the User-Agent decides
 * browser-vs-WebView within whichever of those it lands in.
 */
export function classifyClientPlatform(
  userAgent: string | undefined,
  reportedDevice: AnnouncementDevice | null
): ClientPlatform {
  const ua = userAgent ?? "";

  // The desktop shell is the one bucket with a definitive tell, and it has
  // two independent ones. The report is exact — it means the renderer
  // actually found the preload bridge (see the website's lib/desktop.ts) —
  // and the User-Agent backs it up for a connection that never registers,
  // since the shell loads the real site without overriding its UA.
  if (reportedDevice === "desktop-app") return "desktop-app";
  if (/Electron\//.test(ua)) return "desktop-app";

  // "mobile-app" has no client reporting it today (see announcementStore's
  // AnnouncementDevice). If a native mobile shell ever ships it will be
  // rendering this site in a WebView, which is exactly what that bucket
  // means here — so it needs no separate one.
  if (reportedDevice === "mobile-app") return "mobile-webview";

  const mobile = reportedDevice ? reportedDevice === "mobile-browser" : isMobileUserAgent(ua);

  // No usable User-Agent and nothing reported: don't guess. A registered
  // client always reports, so this is a probe or a scraper, not a person.
  if (!reportedDevice && !/Mozilla\//.test(ua)) return "unknown";

  if (mobile) return isMobileWebView(ua) ? "mobile-webview" : "mobile-browser";
  return isDesktopWebView(ua) ? "desktop-webview" : "desktop-browser";
}
