import type { FastifyInstance, FastifyRequest } from "fastify";
import type { WebSocket } from "ws";
import { randomInt } from "node:crypto";
import {
  registerStatsProvider,
  wsConnectionsTotal,
  wsDisconnectionsTotal,
  heartbeatReapedTotal,
  registerErrorsTotal,
  roomsCreatedTotal,
  signalsRelayedTotal,
  bannedIpConnectionsRejectedTotal,
  chatMessagesBlockedTotal,
  autoBansTotal,
  turnstileVerificationsTotal,
  type LocationStats,
} from "./metrics.js";
import { recordViolation } from "./rateLimiter.js";
import { verifyTurnstileToken, TURNSTILE_ENABLED } from "./turnstile.js";
import { lookupConnectionLocation, type ConnectionLocation } from "./geoip.js";
import { signToken, verifyToken, requireAdmin, getBearerToken } from "./auth.js";
import {
  createAccount,
  verifyAccountLogin,
  refreshAccountFromMongo,
  getAccountConnections,
  isNameReserved,
  getPublicAccountById,
  addAccountPoints,
  addAccountCallStats,
  USERNAME_RE,
} from "./accountStore.js";
import {
  loadPersistedChat,
  savePersistedChat,
  deletePersistedChat,
  type ChatMessage,
} from "./chatStore.js";
import { loadRoomRecord, saveRoomRecord, deleteRoomRecord, type RoomRecord } from "./roomStore.js";
import {
  loadPersistedAnnouncement,
  savePersistedAnnouncement,
  deletePersistedAnnouncement,
  type Announcement,
  type AnnouncementButtonAction,
  type AnnouncementColor,
  type AnnouncementVisibility,
  type AnnouncementSound,
} from "./announcementStore.js";
import {
  loadPersistedPartnerConfig,
  savePersistedPartnerConfig,
  loadPersistedPartnerStats,
  incrementPersistedPartnerStats,
  deletePersistedPartnerStats,
  recordPersistedPartnerViewer,
  loadPersistedPartnerUniqueCounts,
  claimPersistedPartnerReward,
  PARTNER_CLICK_REWARD_PLACEMENTS,
  deletePersistedPartnerRewardClaims,
  loadPersistedPartnerRewardClaimCounts,
  type Partner,
  type PartnerConfig,
} from "./partnerStore.js";
import {
  loadPersistedSupporters,
  savePersistedSupporters,
  type Supporter,
} from "./supporterStore.js";
import {
  isIpBanned,
  isBanned,
  isValidBanValue,
  listBans,
  countBans,
  addBan,
  removeBan,
  banIp,
  unbanIp,
  type BanSubject,
  listBannedWords,
  setBannedWords,
  findBannedWord,
  isAntiSpamEnabled,
  setAntiSpamEnabled,
} from "./moderationStore.js";
import { MONGO_ENABLED, isMongoConnected } from "./mongo.js";
import {
  wsGlobalLimiter,
  wsRegisterLimiter,
  wsJoinLimiter,
  wsChatLimiter,
  wsSignalLimiter,
  wsToggleLimiter,
  wsVideoSourceLimiter,
  consumeRateLimit,
} from "./rateLimiter.js";

const HANDLE_RE = /^[a-zA-Z0-9_-]{1,32}$/;
const CLIENT_ID_RE = /^[a-zA-Z0-9-]{8,64}$/;
const HEARTBEAT_INTERVAL_MS = 25_000;
const CHAT_MAX_LEN = 500;
const ANNOUNCEMENT_TEXT_MAX_LEN = 300;
const ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN = 40;
const PARTNER_TITLE_MAX_LEN = 80;
const PARTNER_DESCRIPTION_MAX_LEN = 400;
const PARTNER_BUTTON_LABEL_MAX_LEN = 40;
const PARTNER_REWARD_POINTS_MIN = 1;
const PARTNER_REWARD_POINTS_MAX = 100_000;
const BAN_REASON_MAX_LEN = 200;
const MAX_SUPPORTER_NAME_LEN = 80;
const MAX_SUPPORTERS = 500;
// How many rate-limit violations (across chat/join/register combined) the
// same IP can rack up before it's treated as automated abuse rather than one
// over-eager human and auto-banned the same way an admin doing it by hand
// would (see banIp/disconnectClientsByIp) — this is what actually stops a
// bot that just keeps reconnecting/retrying after being rate-limited.
const AUTO_BAN_VIOLATION_LIMIT = 6;
const AUTO_BAN_VIOLATION_WINDOW_MS = 60_000;
const AUTO_BAN_DURATION_MINUTES = 60;
// How long a passed Turnstile challenge is remembered per connection (see
// ClientInfo.turnstileVerifiedAt) before the next join requires a fresh one
// again — without an expiry, a single solved challenge would cover that
// connection's joins forever (a WS socket doesn't expire on its own, and a
// scripted client answers heartbeat pings same as a browser), letting a bot
// pay for one challenge and then spam indefinitely at just-under-rate-limit
// pace without ever tripping the auto-ban above. 10 minutes comfortably
// covers a real person hopping between a few rooms in one sitting while
// still capping how long one solve keeps paying off for a bot.
const TURNSTILE_REVERIFY_INTERVAL_MS = 10 * 60_000;
// Wall-clock time this process came up — used only for the startup grace
// window right below.
const SERVER_START_TIME = Date.now();
// A deploy/restart drops every open connection at once; every client's own
// reconnect logic (see lib/signalingClient.ts's scheduleReconnect) brings
// them all back within seconds of each other, and each one is a brand-new
// socket with no info.turnstileVerifiedAt yet — so with TURNSTILE_ENABLED
// on, a restart used to turn into every single reconnecting person being
// challenged for a fresh token at once, right as the process is still
// coming back up. For this long after start, a join that doesn't present a
// token is let through anyway (same as TURNSTILE_ENABLED being off) — see
// mustVerifyTurnstile below. A join that *does* present one is still fully
// verified regardless, same principle as TURNSTILE_ENABLED's own doc
// comment: there's no reason to wave through a client actively claiming to
// have passed the challenge, restart or not. Comfortably covers a restart's
// reconnect burst (seconds, not minutes) while being short enough that it's
// not a standing way to skip verification — a bot would have to specifically
// time itself to this narrow window after every deploy, and only gains
// "no token required", not "not verified if one is sent".
const TURNSTILE_STARTUP_GRACE_MS = 2 * 60_000;
// Close code used to reject a connection from a banned IP — distinct from
// SUPERSEDED_CLOSE_CODE below so the client can tell them apart and show the
// right message instead of quietly retrying (see signalingClient.ts).
const BANNED_CLOSE_CODE = 4003;
// Chat history is kept in memory for the room's lifetime (until it empties
// out — see leaveRoom) and mirrored via chatStore.ts (Redis if configured,
// otherwise a per-room disk file) so it also survives the signaling process
// itself restarting (deploy, crash) while the room stays populated. Capped
// so a long-lived room's history can't grow forever.
const ROOM_CHAT_HISTORY_LIMIT = 300;

// Any handle starting with this is private: excluded from the public /rooms
// listing. This is the only thing that makes a room private — there's no
// separate flag to keep in sync, so it can't drift from the handle itself.
const PRIVATE_PREFIX = "priv-";

function isPrivateRoom(room: string): boolean {
  return room.startsWith(PRIVATE_PREFIX);
}

// 6-digit code generated for a private room's RoomRecord (see roomStore.ts)
// when the handle doesn't already carry one — see roomCodeFromHandle below,
// which is now where the code normally comes from. Cryptographically random,
// on the assumption that it'll gate something eventually and guessability
// will matter then even if it doesn't now.
function generateRoomCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, "0");
}

// A private room's code lives in its own handle: "priv-<nome>-<123456>".
// The client mints it when creating the room (see the home page's private
// "Criar sala"), which is what makes the room's URL the whole of its
// secret — hand someone the link and they're in, with nothing else to pass
// along and nothing for this server to hand back out.
//
// Parsed rather than generated here so the two can never disagree: a URL
// typed or pasted straight into the browser creates exactly the room it
// names, code included, instead of a room whose stored code is some other
// number nobody has seen. Falls back to generateRoomCode() only for a
// private handle with no trailing code at all — every such room predates
// this scheme, and inventing one keeps the record's shape honest.
const PRIVATE_ROOM_CODE_RE = /-(\d{6})$/;

function roomCodeFromHandle(room: string): string | null {
  const match = PRIVATE_ROOM_CODE_RE.exec(room);
  return match ? match[1] : null;
}

// A non-updated ("old format") client — and any guest before its very first
// guest-token round-trip — never presents a token at all, so the only thing
// it can offer to reclaim a stale connection is the plain clientId it was
// given (see the "register" handler's existingProtected check below). That
// bare match is inherently spoofable by anyone who has merely seen that id
// (it's visible in every room's peer list), which is exactly the attack the
// token system exists to close — but *only once a session has actually
// verified a token*. Set this to "false" to close that residual gap
// entirely: reclaiming an existing session then always requires proving it
// via a matching account/guest token (see isSameOwner), full stop. The
// trade-off is that a non-updated client — which will never have such a
// token to present — loses seamless reconnect: a reload or a rename no
// longer reclaims its old spot, it just starts over as a new guest each
// time. Registration itself is never refused either way; this only governs
// how strictly *reclaiming* an existing one is guarded. Defaults to "true"
// so existing, non-updated clients keep working exactly as they always
// have.
const ALLOW_OLD_CLIENTS_GUEST_SYSTEM = process.env.ALLOW_OLD_CLIENTS_GUEST_SYSTEM !== "false";

interface ClientInfo {
  id: string;
  name: string | null;
  room: string | null;
  sharing: boolean;
  // Which of the two video channels this connection is actually
  // broadcasting, as reported by the "sharing" message. `sharing` above
  // stays what it has always been (screen || camera) so nothing that only
  // cares "is this person transmitting" has to change; these exist so the
  // admin panel can tell a screen share from a camera one.
  //
  // undefined means the client never reported the breakdown — an older
  // client only ever sends the single boolean. That's deliberately distinct
  // from `false`: "not sharing a camera" and "we don't know what they're
  // sharing" are different answers, and the admin payload passes the
  // difference through as null rather than flattening it into a wrong
  // "screen" label.
  sharingScreen?: boolean;
  sharingCamera?: boolean;
  mic: boolean;
  isAlive: boolean;
  socket: WebSocket;
  // The connecting IP (see request.ip in the "/ws" handler below). Never
  // sent to regular participants — only /admin/rooms exposes it, so a
  // moderator can ban whoever's misbehaving straight from the room list.
  ip: string;
  // GeoIP-derived approximate location of `ip` (see geoip.ts), resolved
  // once at connect time — null when it couldn't be placed (private/local
  // address, unroutable range, etc.). Read by registerStatsProvider's
  // locations breakdown (see metrics.ts's connectionsByLocationGauge) on
  // every Prometheus scrape; cached here just to avoid re-doing the lookup
  // on every single scrape (it's deterministic for a given `ip`, so once is
  // enough for this connection's whole lifetime).
  geoLocation: ConnectionLocation | null;
  // Set for a moderator connection opened via "admin-join" (see
  // registerAdminRoutes below). Moderator sockets ride the exact same room
  // machinery as a real participant — they're added to the room's socket
  // set and included unfiltered in the peers array sent to real
  // participants, which is what makes broadcasters' existing
  // "open a connection to every peer I see" logic transparently push them
  // an offer too. The `role: "moderator"` tag on that peer entry (see
  // peerSummary) is what the *client* then uses to hide it from the visible
  // participant list and count — nothing server-side ever filters a
  // moderator out of a room, only out of numbers/lists real users see.
  isModerator?: boolean;
  // Set when this connection registered with a valid account JWT (see the
  // "register" case below) — lets the reserved-name check tell a genuine
  // account owner apart from anyone else trying to use their name, and is
  // what admin-join checks in place of a separate admin token system.
  accountId?: string;
  flags?: string[];
  // Timestamp of the last passed Turnstile challenge on this connection —
  // later joins on the *same* socket (switching rooms) skip re-verifying as
  // long as it's within TURNSTILE_REVERIFY_INTERVAL_MS. Deliberately
  // per-connection, not persisted anywhere: a new socket (reload, reconnect)
  // always starts unverified, since that's exactly the moment a bot would
  // use to open a fresh connection and dodge the check.
  turnstileVerifiedAt?: number;
  // Every non-account connection gets a guest identity (see "register"
  // below) — either freshly minted for this connection, or recovered from a
  // guest token the client already had. `guestVerified` is what separates
  // the two: true only when `guestId` came from a token this connection
  // actually presented (proof it's the same guest as before), false when it
  // was just made up now because nothing was presented. That distinction is
  // the whole point of isSameOwner below — a freshly-made-up id never
  // matches anyone else's, guessed or not, so it can't be used to claim
  // someone else's session.
  guestId?: string;
  guestVerified?: boolean;
  // Hash of a handful of stable browser/device traits, computed client-side
  // and sent with "register" (see the client's lib/fingerprint.ts). The
  // point of banning on it is that it survives what the other two subjects
  // don't: a new guest identity, a fresh account, a different IP. It is not
  // a secret and not proof of anything — a modified client can withhold or
  // fake it — so it's strictly an extra handle for moderation, never an
  // identity anything is trusted on.
  fingerprint?: string;
  // Stable per-connection key for the message-rate limiters in
  // rateLimiter.ts — set once at connect time and never touched again.
  // Deliberately *not* the same as `id`: `id` can be reassigned mid-life
  // when this connection reclaims a previous session's clientId (see
  // "register" below), and a rate-limit bucket should stay tied to this one
  // physical socket regardless of what identity it's currently wearing —
  // otherwise reclaiming an id would also silently inherit (or hand off)
  // whatever budget that id's bucket happened to have left.
  rateLimitKey: string;
  // Wall-clock start of the currently-open segment of each, in ms since
  // epoch — undefined whenever that segment isn't open (out of a room / mic
  // off / not sharing). See flushClientStats, which turns these into deltas
  // added to the account's cumulative stats (accountStore.ts's
  // addAccountCallStats) the moment each segment closes. Never set at all
  // for a moderator's admin-join ghost connection — surveilling a room isn't
  // "being in a call."
  joinedAt?: number;
  micOnAt?: number;
  sharingOnAt?: number;
}

// Extends RoomRecord (ownerId/private/flags/code — see roomStore.ts) with
// this process's own in-memory bookkeeping for the room. Keeping the
// persisted fields as one embedded block, rather than spread loose among
// the in-memory-only ones, is what lets leaveRoom's ownership handoff and
// the "join" handler's room-creation save the *whole* persisted record back
// with a plain object spread instead of having to know which fields matter.
// A video someone added to the room from an external service — a YouTube
// video/livestream or a Twitch channel today, the `kind` tag is what keeps
// room for the next one. It is *not* a WebRTC transmission: nothing streams
// through this server or between peers. Every client embeds the same video
// itself, and what actually travels is this little record — which video,
// whether it's playing, and where it is — so that everyone's player lands
// on the same frame. Room-scoped and in-memory, exactly like the peer list:
// a source belongs to a room while that room exists (see the deletion grace
// period) and is gone with it.
export interface RoomVideoSource {
  id: string;
  kind: "youtube" | "twitch";
  // The 11-character YouTube id for a "youtube" source, or the channel login
  // for a "twitch" one — never the URL someone pasted: parsed and validated
  // here (see parseYouTubeVideoId/parseTwitchChannel) so no client can talk
  // another client's embed into loading an arbitrary address.
  videoId: string;
  // Whoever added it — always the one "video-source-remove" and the
  // leaveRoom cleanup below key off, regardless of controlMode. Steering
  // (play/pause/seek, in the "video-source-state" handler) is keyed off this
  // *unless* controlMode is "anyone", in which case anyone in the room may.
  addedById: string;
  addedByName: string;
  // "owner" (the default, and the only mode before this field existed) means
  // only addedById may play/pause/seek — everyone else's player just follows
  // along, one person's playback rather than a tug of war. "anyone" opens
  // that up to the whole room, for a source someone added expecting to share
  // the wheel rather than hand out a read-only copy.
  controlMode: "owner" | "anyone";
  playing: boolean;
  // Playback speed, shared like everything else here — and part of the
  // position arithmetic, not just a display setting: at 1.5x a video covers
  // 1.5 seconds per second, so a client extrapolating without it drifts
  // further out the longer it plays.
  playbackRate: number;
  // Where the video was at `updatedAt`. Clients extrapolate from the pair
  // (see the client's videoSourcePosition) rather than being told a position
  // continuously — a playing video's position is a function of time, so
  // sending it repeatedly would be sending something both sides can compute.
  positionSeconds: number;
  // This server's clock, so everyone extrapolates from the same origin.
  updatedAt: number;
}

interface RoomInfo extends RoomRecord {
  sockets: Set<WebSocket>;
  createdAt: number;
  messages: ChatMessage[];
  // See RoomVideoSource. Capped at MAX_ROOM_VIDEO_SOURCES.
  videoSources: RoomVideoSource[];
  // Room-scoped display-name reservations — separate from any other room,
  // so the same name can be used freely in two different rooms at once (see
  // isSameOwner and the "join"/"register" handlers). Keyed the same way the
  // old global `namesInUse` map used to be (lowercased name -> holder).
  names: Map<string, WebSocket>;
}

// The stable identity a room's ownership is keyed on — an account's id if
// logged in, otherwise the guest id minted for this connection in
// "register". By the time "join" runs, info.name is required and only ever
// gets set from "register", which always ends up populating one of the two
// — the fallback to info.id (the ephemeral per-connection id) only matters
// for a hypothetical connection that reached here without ever registering,
// which the "join" handler already rejects before this could be called.
function stableUserId(info: ClientInfo): string {
  return info.accountId ?? info.guestId ?? info.id;
}

// Whether `challenger` may take over `existing`'s session/room slot — used
// wherever that has to be told apart from a stranger merely presenting the
// same display name or a guessed/observed connection id (see the "register"
// and "join" handlers). Only `challenger`'s side of the proof matters: for
// an account, its accountId (always proven — it only ever comes from a
// verified account JWT); for a guest, a *verified* guestId matching
// `existing`'s (proven by having just presented the exact token that was
// privately handed to whoever `existing` is — nobody else could produce
// it). `existing` itself doesn't need to be verified — plenty of live
// sessions never re-prove themselves after their first connection, and
// that's fine, since it's `challenger` making the claim here. What must
// never count is an *unverified* guestId on the challenger's side, freshly
// made up for this connection: unlike a verified one, that proves nothing
// about who's on the other end.
function isSameOwner(existing: ClientInfo, challenger: ClientInfo): boolean {
  if (existing.accountId || challenger.accountId) {
    return Boolean(challenger.accountId) && existing.accountId === challenger.accountId;
  }
  return Boolean(challenger.guestVerified) && existing.guestId === challenger.guestId;
}

// Announcement/AnnouncementButtonAction/AnnouncementColor/
// AnnouncementVisibility/AnnouncementSound come from announcementStore.js
// (imported above) — that's also where the persisted copy lives, so both
// sides of the load/save round-trip share one type definition.
const ANNOUNCEMENT_ACTIONS = new Set<AnnouncementButtonAction>([
  "open-new-tab",
  "open-same-tab",
  "reload",
]);
const ANNOUNCEMENT_COLORS = new Set<AnnouncementColor>(["green", "red", "blue"]);
const ANNOUNCEMENT_VISIBILITIES = new Set<AnnouncementVisibility>(["online-only", "all"]);
const ANNOUNCEMENT_SOUNDS = new Set<AnnouncementSound>(["always", "live-only", "off"]);
// Custom admin-chosen announcement id (see POST /admin/announcement) — kept
// distinct from HANDLE_RE/CLIENT_ID_RE since it's a different namespace, but
// the same conservative charset.
const ANNOUNCEMENT_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// Real-time engagement counters for whichever announcement is currently
// active — intentionally not history: replaced/cleared wholesale alongside
// currentAnnouncement (see setAnnouncement/clearAnnouncementStats below), so
// there's exactly one bucket to reason about and nothing to sweep. `viewerIds`
// dedupes by connection id so one visitor toggling tabs/focus repeatedly
// can't inflate the view count — a "view" only counts once per connection,
// the first time its tab is actually visible while the banner is showing
// (see the "announcement-view" case and AnnouncementBanner.tsx).
interface AnnouncementStatsEntry {
  viewerIds: Set<string>;
  buttonClicks: number;
  xClicks: number;
}
let announcementStats: AnnouncementStatsEntry | null = null;

function announcementStatsSummary() {
  if (!announcementStats) return null;
  return {
    views: announcementStats.viewerIds.size,
    buttonClicks: announcementStats.buttonClicks,
    xClicks: announcementStats.xClicks,
  };
}

const clients = new Map<WebSocket, ClientInfo>();
const clientsById = new Map<string, ClientInfo>();
// Enough for "the stream we're all watching" plus a couple of extras, few
// enough that nobody can bury a room's own transmissions under a wall of
// embedded players.
const MAX_ROOM_VIDEO_SOURCES = 4;
const YOUTUBE_VIDEO_ID_RE = /^[A-Za-z0-9_-]{11}$/;

// Accepts anything someone is likely to paste — a watch URL, youtu.be, an
// embed/live/shorts path, or the bare id — and returns the id, or null if it
// isn't recognizably a YouTube video. Done here rather than trusted from the
// client because this id ends up in every other participant's iframe src.
function parseYouTubeVideoId(raw: string): string | null {
  const trimmed = raw.trim();
  if (YOUTUBE_VIDEO_ID_RE.test(trimmed)) return trimmed;
  let url: URL;
  try {
    url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
  const host = url.hostname.replace(/^www\./, "").toLowerCase();
  let id: string | null = null;
  if (host === "youtu.be") {
    id = url.pathname.split("/")[1] ?? null;
  } else if (host === "youtube.com" || host === "m.youtube.com" || host === "music.youtube.com" || host === "youtube-nocookie.com") {
    if (url.pathname === "/watch") id = url.searchParams.get("v");
    else {
      const [, section, value] = url.pathname.split("/");
      if (section === "embed" || section === "live" || section === "shorts" || section === "v") {
        id = value ?? null;
      }
    }
  }
  return id && YOUTUBE_VIDEO_ID_RE.test(id) ? id : null;
}

// Twitch login names: 4-25 characters, letters/digits/underscore, never
// starting with a digit — Twitch's own registration rule, which doubles here
// as the shape check for a bare channel name typed with no URL at all.
const TWITCH_CHANNEL_RE = /^[A-Za-z][A-Za-z0-9_]{3,24}$/;

// Only a channel — the live broadcast, which is the only thing this room
// knows how to keep a room synchronized on (see RoomVideoSource.controlMode
// and the client's isLiveBroadcast: there is no timeline to seek a channel
// embed to, only play/pause). A VOD or clip URL has more path segments than
// a channel's `/<name>` and is deliberately rejected rather than guessed at.
function parseTwitchChannel(raw: string): string | null {
  const trimmed = raw.trim();
  if (TWITCH_CHANNEL_RE.test(trimmed)) return trimmed;
  let url: URL;
  try {
    url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
  const host = url.hostname.replace(/^www\./, "").replace(/^m\./, "").toLowerCase();
  if (host !== "twitch.tv") return null;
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length !== 1) return null;
  const channel = segments[0];
  return TWITCH_CHANNEL_RE.test(channel) ? channel : null;
}

function hasOwn(obj: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

// YouTube's own speed menu, which is what any honest client is reporting.
// Anything else is clamped to the nearest end rather than rejected: this is
// a viewing preference, and refusing the whole update over it would leave
// the room's play/pause unapplied for something nobody would notice.
const MIN_PLAYBACK_RATE = 0.25;
const MAX_PLAYBACK_RATE = 2;
function normalizePlaybackRate(raw: unknown): number {
  if (typeof raw !== "number" || !Number.isFinite(raw)) return 1;
  return Math.min(MAX_PLAYBACK_RATE, Math.max(MIN_PLAYBACK_RATE, Math.round(raw * 100) / 100));
}

const rooms = new Map<string, RoomInfo>();
// Pending "really delete this now-empty room" timers, keyed by room — see
// scheduleRoomDeletion.
const roomDeletionTimers = new Map<string, NodeJS.Timeout>();
// A page reload (Ctrl+R) closes the old socket and opens a new one a moment
// later — long enough that an *immediate* delete-on-empty would wipe the
// room's chat history out from under that reconnect. This grace period
// covers a reload/brief network drop; only if the room is still empty once
// it elapses do we actually tear it down.
const ROOM_DELETION_GRACE_MS = 20_000;
// Single site-wide banner, independent of any room — broadcastToAll below
// pushes it to every open socket regardless of what room (if any) they're
// in, and a fresh connection gets whatever's currently active appended
// right after "welcome" so it isn't missed by someone who (re)connects
// while it's up.
let currentAnnouncement: Announcement | null = null;

// Sidebar partner-ad slot (see components/PartnerCard.tsx) — unlike the
// announcement banner above, more than one can be active at once (see
// activePartners/pickWeightedPartner/assignPartnersToConnections below for
// how one gets chosen for a given request/connection). Loaded from
// partnerStore.js at startup, just like currentAnnouncement.
let partnerConfig: PartnerConfig = { partners: [], emptyPercent: 0 };

// Shown on hover over the "Apoiar projeto" button (see WatchRoom.tsx) — the
// whole list, replaced wholesale on every admin edit, same "one flat list"
// shape as bannedWords in moderationStore.ts. Loaded from supporterStore.js
// at startup, just like currentAnnouncement/partnerConfig above. Kept
// sorted by amount descending at rest, so every reader (the public GET, the
// admin GET, every "supporters" broadcast) gets it pre-sorted for free —
// see sortSupporters, the only place that ordering is ever decided.
let currentSupporters: Supporter[] = [];

function sortSupporters(supporters: Supporter[]): Supporter[] {
  return [...supporters].sort((a, b) => b.amount - a.amount);
}

// Engagement counters per partner ad, keyed by id — mirrors
// AnnouncementStatsEntry above (same dedupe-by-connection reasoning), but
// per-partner rather than a single active slot, and kept around for as long
// as the partner itself exists in partnerConfig.partners (including past its
// expiresAt — see Partner.expiresAt's doc comment) rather than being
// wholesale-reset the way announcementStats is.
//
// Unlike announcementStats these are *totals*, hydrated at startup from and
// written through to partnerStore.js, so a restart (deploy, crash) doesn't
// zero out an advertiser's numbers mid-campaign. Both counts are therefore
// running counts rather than a set's size: `viewerIds` only dedupes the
// connections this process has seen since it started (a connection id can't
// outlive the process that issued it), while the counts also carry over
// everything counted before the last restart — see PartnerStats.
interface PartnerStatsEntry {
  // Connections that have already been counted as a session for this ad.
  viewerIds: Set<string>;
  // Every serve — see the "partner-view" case.
  views: number;
  // One per connection — see the "partner-session-view" case.
  sessionViews: number;
  // CTA clicks, split by where the button was — see PartnerStats in
  // partnerStore.ts for why these are two numbers and not one.
  clicks: number;
  clicksByVideo: number;
  // Watch-to-earn funnel (see PartnerRewardModal.tsx) — see PartnerStats in
  // partnerStore.ts for what these do and don't dedupe.
  rewardVideoOpens: number;
  rewardVideoCompletions: number;
}
const partnerStats = new Map<string, PartnerStatsEntry>();

function getPartnerStats(id: string): PartnerStatsEntry {
  let entry = partnerStats.get(id);
  if (!entry) {
    entry = {
      viewerIds: new Set(),
      views: 0,
      sessionViews: 0,
      clicks: 0,
      clicksByVideo: 0,
      rewardVideoOpens: 0,
      rewardVideoCompletions: 0,
    };
    partnerStats.set(id, entry);
  }
  return entry;
}

function partnerStatsSummary(id: string) {
  const entry = partnerStats.get(id);
  return {
    views: entry?.views ?? 0,
    sessionViews: entry?.sessionViews ?? 0,
    clicks: entry?.clicks ?? 0,
    clicksByVideo: entry?.clicksByVideo ?? 0,
    rewardVideoOpens: entry?.rewardVideoOpens ?? 0,
    rewardVideoCompletions: entry?.rewardVideoCompletions ?? 0,
  };
}

// Who counts as one person, for the unique-viewer set.
//
// The account id when there is one, and the connecting IP otherwise. Both are
// approximations and it is worth being blunt about which way each one errs: a
// household or an office behind one NAT collapses into a single "person",
// while the same person on wifi and then on mobile data counts twice. It is
// the best identity this server actually has — the same one it already trusts
// for IP bans — and it is stable across reloads and reconnects, which is the
// property the number depends on.
//
// Prefixed so an account id can never collide with an IP in the same set.
function partnerViewerKey(info: ClientInfo): string {
  return info.accountId ? `acct:${info.accountId}` : `ip:${info.ip}`;
}

// The same summary plus the unique-viewer and reward-claim counts, both of
// which live in the store rather than in this process — a set that restarted
// empty would recount every returning visitor on each deploy (see
// partnerStore's recordPersistedPartnerViewer) or, worse, let an account
// collect a reward a second time after a restart (see
// claimPersistedPartnerReward).
async function partnerStatsSummaries(ids: string[]) {
  const [uniques, rewardClaims, clickRewardClaims] = await Promise.all([
    loadPersistedPartnerUniqueCounts(ids),
    loadPersistedPartnerRewardClaimCounts(ids, "video"),
    loadPersistedPartnerRewardClaimCounts(ids, "click"),
  ]);
  return Object.fromEntries(
    ids.map((id) => [
      id,
      {
        ...partnerStatsSummary(id),
        uniqueViews: uniques[id] ?? 0,
        rewardClaims: rewardClaims[id] ?? 0,
        clickRewardClaims: clickRewardClaims[id] ?? 0,
      },
    ])
  );
}

// Partners whose expiresAt hasn't passed yet — the only ones eligible for
// selection (HTTP or socket). An expired partner stays in partnerConfig.partners
// (see its doc comment) but never shows up here again.
function activePartners(): Partner[] {
  const now = Date.now();
  return partnerConfig.partners.filter((p) => p.expiresAt === null || p.expiresAt > now);
}

// One weighted-random pick for a single HTTP request — independent per
// call, so across many requests the split between partners converges to
// their relative weights (see Partner.weight's doc comment) without needing
// to know how many other requests are happening concurrently, unlike
// assignPartnersToConnections below which deals with a fixed, known set of
// connections all at once.
function pickWeightedPartner(pool: Partner[]): Partner | null {
  if (pool.length === 0) return null;
  const totalWeight = pool.reduce((sum, p) => sum + p.weight, 0);
  if (totalWeight <= 0) return pool[Math.floor(Math.random() * pool.length)];
  let roll = Math.random() * totalWeight;
  for (const p of pool) {
    roll -= p.weight;
    if (roll <= 0) return p;
  }
  return pool[pool.length - 1]; // floating-point fallback, should be unreachable
}

// Only the fields a visitor actually needs — weight/createdAt are admin
// bookkeeping, not part of what gets rendered or sent over the wire to a
// regular client.
function publicPartner(p: Partner) {
  return {
    id: p.id,
    title: p.title,
    description: p.description,
    imageUrl: p.imageUrl,
    buttonLabel: p.buttonLabel,
    buttonUrl: p.buttonUrl,
    backgroundColor: p.backgroundColor,
    textColor: p.textColor,
    buttonBackgroundColor: p.buttonBackgroundColor,
    buttonTextColor: p.buttonTextColor,
    expiresAt: p.expiresAt,
    rewardVideoUrl: p.rewardVideoUrl,
    rewardPoints: p.rewardPoints,
    // `?? null` rather than a bare read: ads stored before click rewards
    // existed have no such field at all, and the client distinguishes "no
    // click reward" by null, not by undefined.
    clickRewardPoints: p.clickRewardPoints ?? null,
    clickRewardPlacement: p.clickRewardPlacement ?? null,
  };
}

// Splits `count` connections across `pool` proportionally to weight, using
// the largest-remainder method so the split is exact (not just
// probabilistically close, the way independent per-request random picks —
// see pickWeightedPartner — would be for a small connection count) even
// when count doesn't divide evenly. Order is shuffled afterward so which
// *specific* connections land on which partner isn't correlated with
// pool/iteration order every time this runs. Returns an array of length
// `count`; empty pool returns an all-null array.
function assignPartnersToConnections(pool: Partner[], count: number): (Partner | null)[] {
  if (count === 0) return [];
  if (pool.length === 0) return new Array(count).fill(null);
  const totalWeight = pool.reduce((sum, p) => sum + p.weight, 0);
  const shares = pool.map((p) => (totalWeight > 0 ? (p.weight / totalWeight) * count : count / pool.length));
  const bucketCounts = shares.map((s) => Math.floor(s));
  let assigned = bucketCounts.reduce((sum, n) => sum + n, 0);
  const remainders = shares
    .map((s, i) => ({ i, remainder: s - bucketCounts[i] }))
    .sort((a, b) => b.remainder - a.remainder);
  let r = 0;
  while (assigned < count) {
    bucketCounts[remainders[r % remainders.length].i] += 1;
    assigned += 1;
    r += 1;
  }
  const bag: Partner[] = [];
  pool.forEach((p, i) => {
    for (let k = 0; k < bucketCounts[i]; k += 1) bag.push(p);
  });
  for (let i = bag.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [bag[i], bag[j]] = [bag[j], bag[i]];
  }
  return bag;
}

// Pushes a fresh partner assignment to *every* currently connected socket —
// called after every admin create/edit/delete so already-open tabs update
// immediately, without waiting for a reload. Deliberately bypasses
// partnerConfig.emptyPercent entirely (that only governs the HTTP GET
// /partner roll for a brand new/reloaded page — see the route below) and
// deliberately doesn't scope to non-moderator/registered connections the
// way room broadcasts do, matching broadcastToAll's announcement semantics:
// any open socket might have a PartnerCard mounted, and one that doesn't
// simply ignores a message type it has no handler for.
function broadcastPartnerUpdate() {
  const pool = activePartners();
  const sockets = [...clients.keys()];
  const assignment = assignPartnersToConnections(pool, sockets.length);
  sockets.forEach((socket, i) => {
    const partner = assignment[i];
    send(socket, { type: "partner", partner: partner ? publicPartner(partner) : null });
  });
}

// A WebRTC offer/answer/ICE candidate is only useful for a few seconds, but
// `send()` below silently drops it if the target's socket isn't OPEN right
// then — which happens constantly on mobile (screen lock, wifi/cell
// handoff, a brief signal drop triggering a reconnect). A dropped offer is
// never resent by anything else, so it permanently stranded that one
// viewer's connection (peer shows in the room, but no video ever arrives).
// Queuing briefly and flushing once the target (re)joins closes that gap.
interface PendingSignal {
  from: string;
  data: unknown;
  queuedAt: number;
}
const PENDING_SIGNAL_TTL_MS = 15_000;
const MAX_PENDING_SIGNALS_PER_TARGET = 32;
const pendingSignals = new Map<string, PendingSignal[]>();

registerStatsProvider(() => {
  const registeredPeers = [...clients.values()].filter((c) => c.name !== null && !c.isModerator);
  const identities = { accounts: 0, guestsWithToken: 0, guestsWithoutToken: 0 };
  for (const c of registeredPeers) {
    if (c.accountId) identities.accounts += 1;
    else if (c.guestVerified) identities.guestsWithToken += 1;
    else identities.guestsWithoutToken += 1;
  }
  // Keyed by "country|lat|lon" purely to dedupe while counting — the actual
  // label values are read back out of each entry below, not parsed from the
  // key. Only ever holds entries for locations with a connection *right
  // now* (see connectionsByLocationGauge's doc comment for why that's the
  // point of recomputing this fresh on every scrape instead of tracking it
  // incrementally).
  const locationCounts = new Map<string, LocationStats>();
  for (const c of clients.values()) {
    if (!c.geoLocation) continue;
    const key = `${c.geoLocation.country}|${c.geoLocation.lat}|${c.geoLocation.lon}`;
    const entry = locationCounts.get(key);
    if (entry) entry.count += 1;
    else locationCounts.set(key, { ...c.geoLocation, count: 1 });
  }
  return {
    connectedSockets: clients.size,
    registeredPeers: registeredPeers.length,
    identities,
    rooms: [...rooms.entries()].map(([handle, info]) => ({
      handle,
      peopleCount: realPeopleCount(info),
      sharingCount: realSharingCount(info),
      isPrivate: isPrivateRoom(handle),
    })),
    locations: [...locationCounts.values()],
  };
});

function isValidDisplayName(name: string): boolean {
  if (name.length < 1 || name.length > 24) return false;
  for (let i = 0; i < name.length; i += 1) {
    const code = name.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Same control-character guard as isValidDisplayName, but newlines (10) are
// allowed since chat text is reasonably multi-line.
function isValidChatText(text: string): boolean {
  if (text.length < 1 || text.length > CHAT_MAX_LEN) return false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 10) continue;
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Restricted to Giphy's own domain since this URL is trusted straight into
// an <img src> on every client in the room — accepting arbitrary URLs here
// would turn chat into an open image/tracking-pixel relay.
function isValidGifUrl(url: string): boolean {
  if (url.length > 500) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return parsed.protocol === "https:" && parsed.hostname.endsWith(".giphy.com");
}

// Same control-character guard as isValidDisplayName (no newlines — these
// are meant to be short single-line fields), parameterized on max length —
// reused for the announcement text/button label and the partner ad's
// title/description/button label.
function isValidShortText(text: string, maxLen: number): boolean {
  if (text.length < 1 || text.length > maxLen) return false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Restricted to http(s) so a "javascript:" (or other) URL scheme can never
// reach a button's href/window.open target or an <img src> — this comes
// straight from an admin-supplied form field (announcement buttonUrl, or a
// partner ad's buttonUrl/imageUrl) and gets used client-side without further
// sanitization.
function isValidHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

// Partner ad color fields (backgroundColor/textColor/buttonBackgroundColor/
// buttonTextColor) are admin-supplied and rendered straight into a React
// inline `style` object (see PartnerCard.tsx) — React sets those through
// CSSOM property setters rather than string-concatenating HTML, so there's
// no injection risk either way, but this still keeps garbage input from
// silently breaking the card's styling. Permissive enough for hex
// (#rgb/#rrggbb/#rrggbbaa), rgb()/rgba()/hsl()/hsla(), and named colors.
const CSS_COLOR_RE = /^[a-zA-Z0-9#(),.%\s-]{1,40}$/;
function isValidCssColor(value: string): boolean {
  return CSS_COLOR_RE.test(value);
}

type ParsedAnnouncementFields = Omit<Announcement, "id" | "version">;

// Shared body-parsing/validation for POST (create) and PUT (edit) — both
// take the exact same editable fields, just differ in what happens to
// id/version/stats around the result (see the two route handlers below).
function parseAnnouncementBody(
  body: Record<string, unknown>
): ParsedAnnouncementFields | { error: string } {
  const text = typeof body.text === "string" ? body.text.trim().slice(0, ANNOUNCEMENT_TEXT_MAX_LEN) : "";
  if (!isValidShortText(text, ANNOUNCEMENT_TEXT_MAX_LEN)) {
    return { error: "Texto inválido." };
  }
  const color = typeof body.color === "string" ? body.color : "";
  if (!ANNOUNCEMENT_COLORS.has(color as AnnouncementColor)) {
    return { error: "Cor inválida." };
  }
  const visibility = typeof body.visibility === "string" ? body.visibility : "all";
  if (!ANNOUNCEMENT_VISIBILITIES.has(visibility as AnnouncementVisibility)) {
    return { error: "Visibilidade inválida." };
  }
  const sound = typeof body.sound === "string" ? body.sound : "always";
  if (!ANNOUNCEMENT_SOUNDS.has(sound as AnnouncementSound)) {
    return { error: "Opção de som inválida." };
  }
  const dismissible = Boolean(body.dismissible);
  const persistent = Boolean(body.persistent);
  // Defaults to true (button shown) when omitted, so an old admin client
  // that's never heard of this field keeps behaving exactly as before.
  const hasButton = body.hasButton !== false;

  if (!hasButton) {
    return {
      text,
      hasButton: false,
      buttonLabel: "",
      buttonAction: "reload",
      buttonUrl: null,
      color: color as AnnouncementColor,
      dismissible,
      visibility: visibility as AnnouncementVisibility,
      sound: sound as AnnouncementSound,
      persistent,
    };
  }

  const buttonLabel =
    typeof body.buttonLabel === "string"
      ? body.buttonLabel.trim().slice(0, ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN)
      : "";
  if (!isValidShortText(buttonLabel, ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN)) {
    return { error: "Label do botão inválido." };
  }
  const buttonAction = typeof body.buttonAction === "string" ? body.buttonAction : "";
  if (!ANNOUNCEMENT_ACTIONS.has(buttonAction as AnnouncementButtonAction)) {
    return { error: "Ação do botão inválida." };
  }
  const needsUrl = buttonAction !== "reload";
  const rawUrl = typeof body.buttonUrl === "string" ? body.buttonUrl.trim() : "";
  if (needsUrl && !isValidHttpUrl(rawUrl)) {
    return { error: "Link inválido — use uma URL http(s) completa." };
  }

  return {
    text,
    hasButton: true,
    buttonLabel,
    buttonAction: buttonAction as AnnouncementButtonAction,
    buttonUrl: needsUrl ? rawUrl : null,
    color: color as AnnouncementColor,
    dismissible,
    visibility: visibility as AnnouncementVisibility,
    sound: sound as AnnouncementSound,
    persistent,
  };
}

type ParsedPartnerFields = Omit<Partner, "id" | "createdAt">;
type PartnerClickRewardPlacement = NonNullable<Partner["clickRewardPlacement"]>;
const PARTNER_WEIGHT_MIN = 1;
const PARTNER_WEIGHT_MAX = 100;
const PARTNER_COLOR_FIELDS = [
  "backgroundColor",
  "textColor",
  "buttonBackgroundColor",
  "buttonTextColor",
] as const;

// Shared body-parsing/validation for POST (create) and PUT (edit) of a
// single partner ad — mirrors parseAnnouncementBody's shape/reasoning above.
function parsePartnerBody(body: Record<string, unknown>): ParsedPartnerFields | { error: string } {
  const title = typeof body.title === "string" ? body.title.trim().slice(0, PARTNER_TITLE_MAX_LEN) : "";
  if (!isValidShortText(title, PARTNER_TITLE_MAX_LEN)) {
    return { error: "Título inválido." };
  }
  const description =
    typeof body.description === "string" ? body.description.trim().slice(0, PARTNER_DESCRIPTION_MAX_LEN) : "";
  if (!isValidShortText(description, PARTNER_DESCRIPTION_MAX_LEN)) {
    return { error: "Descrição inválida." };
  }
  const buttonLabel =
    typeof body.buttonLabel === "string" ? body.buttonLabel.trim().slice(0, PARTNER_BUTTON_LABEL_MAX_LEN) : "";
  if (!isValidShortText(buttonLabel, PARTNER_BUTTON_LABEL_MAX_LEN)) {
    return { error: "Label do botão inválido." };
  }
  const buttonUrl = typeof body.buttonUrl === "string" ? body.buttonUrl.trim() : "";
  if (!isValidHttpUrl(buttonUrl)) {
    return { error: "Link do botão inválido — use uma URL http(s) completa." };
  }
  const rawImageUrl = typeof body.imageUrl === "string" ? body.imageUrl.trim() : "";
  if (rawImageUrl && !isValidHttpUrl(rawImageUrl)) {
    return { error: "URL da imagem inválida — use uma URL http(s) completa." };
  }

  const colors: Record<(typeof PARTNER_COLOR_FIELDS)[number], string | null> = {
    backgroundColor: null,
    textColor: null,
    buttonBackgroundColor: null,
    buttonTextColor: null,
  };
  for (const field of PARTNER_COLOR_FIELDS) {
    const value = body[field];
    const raw = typeof value === "string" ? value.trim() : "";
    if (raw && !isValidCssColor(raw)) {
      return { error: "Cor inválida." };
    }
    colors[field] = raw || null;
  }

  const rawWeight = typeof body.weight === "number" && Number.isFinite(body.weight) ? Math.round(body.weight) : 1;
  const weight = Math.min(PARTNER_WEIGHT_MAX, Math.max(PARTNER_WEIGHT_MIN, rawWeight));
  const expiresAt =
    typeof body.expiresAt === "number" && Number.isFinite(body.expiresAt) ? body.expiresAt : null;

  // Watch-to-earn reward — both optional, but only ever a pair: a reward
  // amount with no video to earn it from (or vice versa) would just be a
  // dangling config the admin form can't even produce, so this is enforced
  // here rather than trusted from the request.
  const rawRewardVideoUrl = typeof body.rewardVideoUrl === "string" ? body.rewardVideoUrl.trim() : "";
  if (rawRewardVideoUrl && !isValidHttpUrl(rawRewardVideoUrl)) {
    return { error: "Link do vídeo de recompensa inválido — use uma URL http(s) completa." };
  }
  const rewardVideoUrl = rawRewardVideoUrl || null;
  let rewardPoints: number | null = null;
  if (rewardVideoUrl) {
    const rawRewardPoints =
      typeof body.rewardPoints === "number" && Number.isFinite(body.rewardPoints)
        ? Math.round(body.rewardPoints)
        : NaN;
    if (
      !Number.isFinite(rawRewardPoints) ||
      rawRewardPoints < PARTNER_REWARD_POINTS_MIN ||
      rawRewardPoints > PARTNER_REWARD_POINTS_MAX
    ) {
      return { error: `Pontos da recompensa devem ser entre ${PARTNER_REWARD_POINTS_MIN} e ${PARTNER_REWARD_POINTS_MAX}.` };
    }
    rewardPoints = rawRewardPoints;
  }

  // Click-to-earn reward — points for clicking the ad's own CTA, independent
  // of the video above (an ad can have either, both, or neither). Absent or
  // empty means "no click reward", and the placement only exists alongside a
  // points value, same pairing rule as the video reward.
  const hasClickReward =
    body.clickRewardPoints !== undefined &&
    body.clickRewardPoints !== null &&
    body.clickRewardPoints !== "";
  let clickRewardPoints: number | null = null;
  let clickRewardPlacement: PartnerClickRewardPlacement | null = null;
  if (hasClickReward) {
    const rawClickRewardPoints =
      typeof body.clickRewardPoints === "number" && Number.isFinite(body.clickRewardPoints)
        ? Math.round(body.clickRewardPoints)
        : NaN;
    if (
      !Number.isFinite(rawClickRewardPoints) ||
      rawClickRewardPoints < PARTNER_REWARD_POINTS_MIN ||
      rawClickRewardPoints > PARTNER_REWARD_POINTS_MAX
    ) {
      return {
        error: `Pontos por clique devem ser entre ${PARTNER_REWARD_POINTS_MIN} e ${PARTNER_REWARD_POINTS_MAX}.`,
      };
    }
    const rawPlacement = typeof body.clickRewardPlacement === "string" ? body.clickRewardPlacement : "";
    if (rawPlacement && !PARTNER_CLICK_REWARD_PLACEMENTS.includes(rawPlacement as PartnerClickRewardPlacement)) {
      return { error: "Onde vale o ponto por clique é inválido." };
    }
    clickRewardPoints = rawClickRewardPoints;
    // Defaults to the least surprising of the three: an admin who filled in
    // an amount and nothing else means "pay for the click", not "pay for the
    // click in one of the two places I didn't pick".
    clickRewardPlacement = (rawPlacement as PartnerClickRewardPlacement) || "both";
  }

  return {
    title,
    description,
    imageUrl: rawImageUrl || null,
    buttonLabel,
    buttonUrl,
    ...colors,
    weight,
    expiresAt,
    rewardVideoUrl,
    rewardPoints,
    clickRewardPoints,
    clickRewardPlacement,
  };
}

function send(socket: WebSocket, msg: unknown) {
  if (socket.readyState === socket.OPEN) {
    socket.send(JSON.stringify(msg));
  }
}

function broadcastToRoom(room: string, msg: unknown, exclude?: WebSocket) {
  const roomInfo = rooms.get(room);
  if (!roomInfo) return;
  for (const s of roomInfo.sockets) {
    if (s !== exclude) send(s, msg);
  }
}

// Every open socket on the signaling server, regardless of room — used only
// for the site-wide announcement banner, which is deliberately not
// room-scoped.
function broadcastToAll(msg: unknown) {
  for (const s of clients.keys()) send(s, msg);
}

function queueSignal(targetId: string, from: string, data: unknown) {
  const queue = pendingSignals.get(targetId) ?? [];
  queue.push({ from, data, queuedAt: Date.now() });
  while (queue.length > MAX_PENDING_SIGNALS_PER_TARGET) queue.shift();
  pendingSignals.set(targetId, queue);
}

// Delivers a relayed signal immediately if the target is reachable in the
// same room right now; otherwise queues it for flushPendingSignals to
// deliver once that peer (re)joins. Deliberately keyed by client id (not
// looked up via clientsById), since a silently-watching moderator socket
// (see "admin-join") never registers a name and so never gets a clientsById
// entry at all.
function deliverOrQueueSignal(room: string, targetId: string, from: string, data: unknown) {
  const roomInfo = rooms.get(room);
  const target = roomInfo
    ? [...roomInfo.sockets].map((s) => clients.get(s)).find((c) => c?.id === targetId)
    : undefined;
  if (target && target.socket.readyState === target.socket.OPEN) {
    send(target.socket, { type: "signal", from, data });
    return;
  }
  queueSignal(targetId, from, data);
}

function flushPendingSignals(info: ClientInfo) {
  const queue = pendingSignals.get(info.id);
  if (!queue) return;
  pendingSignals.delete(info.id);
  const now = Date.now();
  for (const item of queue) {
    if (now - item.queuedAt > PENDING_SIGNAL_TTL_MS) continue;
    send(info.socket, { type: "signal", from: item.from, data: item.data });
  }
}

function peerSummary(info: ClientInfo) {
  return {
    id: info.id,
    name: info.name,
    sharing: info.sharing,
    // See ClientInfo.sharingScreen/sharingCamera — null when unknown.
    screen: info.sharingScreen ?? null,
    camera: info.sharingCamera ?? null,
    mic: info.mic,
    // Not logged into a registered account — the client renders this as a
    // "(guest)" suffix wherever the name is shown (see lib/displayName.ts).
    isGuest: !info.accountId,
    // Account flags (e.g. "VERIFIED") — always [] for a guest, since
    // info.flags is only ever set alongside accountId (see the "register"
    // handler). The client shows a badge when this includes "VERIFIED".
    flags: info.flags ?? [],
    // Stable per-account/per-guest id — see stableUserId. The client only
    // ever treats this as a real, viewable profile when `isGuest` is false;
    // for a guest it's a guest id, not an account, and GET /users/:id below
    // would just 404 on it.
    userId: stableUserId(info),
    ...(info.isModerator ? { role: "moderator" as const } : {}),
  };
}

// Real (non-moderator) headcount for a room — used everywhere a number or
// list is shown to an ordinary user, so a moderator watching never inflates
// what participants see.
function realPeopleCount(roomInfo: RoomInfo): number {
  let count = 0;
  for (const s of roomInfo.sockets) {
    if (!clients.get(s)?.isModerator) count += 1;
  }
  return count;
}

// Same real-people rule as realPeopleCount, but counting only those actually
// broadcasting their screen/camera right now (info.sharing), for the
// sharescreen_room_sharing_screen / sharescreen_sharing_screen_total metrics.
function realSharingCount(roomInfo: RoomInfo): number {
  let count = 0;
  for (const s of roomInfo.sockets) {
    const client = clients.get(s);
    if (client && !client.isModerator && client.sharing) count += 1;
  }
  return count;
}

// Whether `accountId` currently has a live connection in a *public* room —
// used by GET /users/:id below to show "está numa sala pública agora"
// (see the user profile page). Deliberately never reports a private room:
// unlike a public one, being in a private room isn't something a stranger
// looking someone up should be able to discover. A moderator's admin-join
// ghost connection is skipped too — surveilling a room isn't "being" in it.
function findLivePublicRoomForAccount(
  accountId: string
): { room: string; peopleCount: number } | null {
  for (const info of clientsById.values()) {
    if (info.accountId !== accountId || !info.room || info.isModerator) continue;
    if (isPrivateRoom(info.room)) continue;
    const roomInfo = rooms.get(info.room);
    return { room: info.room, peopleCount: roomInfo ? realPeopleCount(roomInfo) : 1 };
  }
  return null;
}

// Cancels a pending scheduleRoomDeletion for `room`, if any — called
// whenever someone (re)joins it, since that proves it didn't really empty
// out for good.
function clearRoomDeletionTimer(room: string) {
  const timer = roomDeletionTimers.get(room);
  if (timer) {
    clearTimeout(timer);
    roomDeletionTimers.delete(room);
  }
}

// Tears the room down — both in memory and its persisted chat file — only
// if it's still empty once ROOM_DELETION_GRACE_MS has elapsed, giving a
// reload/brief drop time to reconnect and reclaim it first.
function scheduleRoomDeletion(room: string) {
  clearRoomDeletionTimer(room);
  const timer = setTimeout(() => {
    roomDeletionTimers.delete(room);
    const roomInfo = rooms.get(room);
    if (roomInfo && roomInfo.sockets.size === 0) {
      rooms.delete(room);
      deletePersistedChat(room);
      void deleteRoomRecord(room);
    }
  }, ROOM_DELETION_GRACE_MS);
  roomDeletionTimers.set(room, timer);
}

// Whole seconds elapsed since `start` (ms since epoch) — never negative,
// since a clock oddity or a start stamped this same instant shouldn't ever
// credit (or debit) an account for negative time.
function secondsSince(start: number, now: number): number {
  return Math.max(0, Math.round((now - start) / 1000));
}

// Closes out whatever segments are currently open on `info` (call time, and
// mic/share time if either was left on) and credits the account for them —
// called from every place a connection actually stops being "in a room":
// leaveRoom and detachSession below. Also the only place these three
// timestamps ever get cleared, so it's safe to call unconditionally even
// when nothing is actually open (a plain no-op delta is dropped rather than
// sent as a zero-valued update).
//
// Deliberately keyed off the timestamps alone, not info.mic/info.sharing —
// those may or may not have been reset to false by the caller already
// (leaveRoom resets them right after this runs), and a timestamp is only
// ever set while the thing it tracks is genuinely on, so checking for its
// presence is equivalent and doesn't depend on call order.
function flushClientStats(info: ClientInfo) {
  const now = Date.now();
  const delta: { callSeconds?: number; micSeconds?: number; shareSeconds?: number } = {};
  if (info.joinedAt !== undefined) delta.callSeconds = secondsSince(info.joinedAt, now);
  if (info.micOnAt !== undefined) delta.micSeconds = secondsSince(info.micOnAt, now);
  if (info.sharingOnAt !== undefined) delta.shareSeconds = secondsSince(info.sharingOnAt, now);
  info.joinedAt = undefined;
  info.micOnAt = undefined;
  info.sharingOnAt = undefined;
  if (info.accountId && (delta.callSeconds || delta.micSeconds || delta.shareSeconds)) {
    void addAccountCallStats(info.accountId, delta);
  }
}

function leaveRoom(info: ClientInfo) {
  flushClientStats(info);
  if (!info.room) return;
  const room = info.room;
  const roomInfo = rooms.get(room);
  if (roomInfo) {
    roomInfo.sockets.delete(info.socket);
    if (info.name && roomInfo.names.get(info.name.toLowerCase()) === info.socket) {
      roomInfo.names.delete(info.name.toLowerCase());
    }
    if (roomInfo.sockets.size === 0) {
      // The room *looks* empty, but don't wipe its chat history yet — see
      // scheduleRoomDeletion. (A same-identity reconnect that briefly
      // overlaps the old socket goes through detachSession instead, which
      // deliberately does NOT delete the file either, since that's not a
      // real departure — see detachSession's comment.)
      scheduleRoomDeletion(room);
    } else if (roomInfo.ownerId === stableUserId(info)) {
      // The owner left but the room isn't empty — hand ownership to
      // whoever's been here longest of who's left. `sockets` is a Set,
      // which preserves insertion order, so its first remaining entry is
      // exactly that (modulo a reconnect re-inserting someone at the back —
      // an accepted approximation, same spirit as isSameOwner's
      // guest-identity heuristics elsewhere in this file). One extra Redis
      // write for an event this rare (an owner actually leaving a room that
      // still has people in it) is nothing next to what it'd cost to do
      // this on every join instead.
      const nextSocket = roomInfo.sockets.values().next().value;
      const nextOwner = nextSocket ? clients.get(nextSocket) : undefined;
      if (nextOwner) {
        roomInfo.ownerId = stableUserId(nextOwner);
        void saveRoomRecord(room, {
          ownerId: roomInfo.ownerId,
          private: roomInfo.private,
          flags: roomInfo.flags,
          code: roomInfo.code,
        });
      }
    }
  }
  // A video source belongs to whoever added it — they're the only one who
  // can steer or remove it — so it goes when they do, rather than sitting
  // there frozen with nobody able to touch it. Only once their *last*
  // connection to this room is gone: a second tab, or a reconnect that
  // briefly overlaps, must not take the video down.
  if (roomInfo) {
    const leaverId = stableUserId(info);
    const stillHere = [...roomInfo.sockets]
      .map((sock) => clients.get(sock))
      .some((other) => other !== undefined && stableUserId(other) === leaverId);
    if (!stillHere) {
      const orphaned = roomInfo.videoSources.filter((v) => v.addedById === leaverId);
      if (orphaned.length > 0) {
        roomInfo.videoSources = roomInfo.videoSources.filter((v) => v.addedById !== leaverId);
        for (const source of orphaned) {
          broadcastToRoom(room, { type: "video-source-removed", id: source.id });
        }
      }
    }
  }
  info.room = null;
  info.sharing = false;
  info.sharingScreen = undefined;
  info.sharingCamera = undefined;
  info.mic = false;
  broadcastToRoom(room, { type: "peer-left", id: info.id }, info.socket);
}

// Close code used when a second connection reclaims a client id out from
// under a still-live socket (see detachSession below) — lets the displaced
// client tell "I was intentionally superseded" apart from an ordinary
// network drop, so it knows not to reconnect and reclaim the id right back.
// Without this distinction the two sockets would keep alternately kicking
// each other off forever (each successful reconnect resets its own
// exponential backoff, so the fight never settles). 4000 is in the
// private-use range reserved by RFC 6455 for application-defined codes.
const SUPERSEDED_CLOSE_CODE = 4000;

// Used when a reconnect (same persisted client id) shows up before the old
// socket has been reaped yet — e.g. a brief network blip, or a second tab.
// Removes the stale session from every bookkeeping structure and closes it
// *without* broadcasting peer-left, since this identity is carried over
// seamlessly to the new socket rather than actually leaving the room.
function detachSession(info: ClientInfo) {
  // A reconnect still ends this connection's open call/mic/share segments —
  // the new socket that reclaims this identity starts fresh ones of its own
  // in "join" below, rather than this old ClientInfo (about to be discarded)
  // silently losing whatever it had accumulated.
  flushClientStats(info);
  if (info.room) {
    const roomInfo = rooms.get(info.room);
    if (roomInfo) {
      roomInfo.sockets.delete(info.socket);
      if (info.name && roomInfo.names.get(info.name.toLowerCase()) === info.socket) {
        roomInfo.names.delete(info.name.toLowerCase());
      }
      // Deliberately leaves the persisted chat file alone even if this was
      // the room's last socket: the new connection taking over this
      // identity is about to "join" the same room again, and will reload
      // this exact history from disk when it recreates the RoomInfo.
      if (roomInfo.sockets.size === 0) rooms.delete(info.room);
    }
    info.room = null;
  }
  if (clientsById.get(info.id) === info) clientsById.delete(info.id);
  clients.delete(info.socket);
  // A graceful close (not terminate()) so the close frame with our code
  // actually reaches the displaced client instead of the connection just
  // dying silently.
  info.socket.close(SUPERSEDED_CLOSE_CODE, "superseded-by-new-connection");
}

// Terminates every socket currently matching a freshly-created ban — called
// right after one is issued, so it takes effect immediately instead of only
// blocking that subject's *next* connection or register.
function disconnectBannedClients(subject: BanSubject, value: string) {
  for (const info of clients.values()) {
    const matches =
      subject === "ip"
        ? info.ip === value
        : subject === "account"
          ? info.accountId === value
          : info.fingerprint === value;
    if (matches) info.socket.close(BANNED_CLOSE_CODE, `${subject}-banned`);
  }
}

function disconnectClientsByIp(ip: string) {
  disconnectBannedClients("ip", ip);
}

// Absent means "ip": the ban endpoints predate subjects, and every caller
// that doesn't name one is talking about an IP.
function parseBanSubject(raw: unknown): BanSubject | null {
  if (raw === undefined || raw === null || raw === "") return "ip";
  if (raw === "ip" || raw === "account" || raw === "fingerprint") return raw;
  return null;
}

// Tracks rate-limit *violations* (not hits — those are already counted by
// consumeRateLimit/wsRateLimitedTotal in rateLimiter.ts) for the categories
// that actually indicate spam (chat/join/register — as opposed to
// signal/toggle bursts, which are normal WebRTC/UI behavior and dropped
// silently by design). If the same IP crosses AUTO_BAN_VIOLATION_LIMIT
// violations within AUTO_BAN_VIOLATION_WINDOW_MS, it's auto-banned exactly
// like an admin ban (persisted, disconnects every socket from that IP
// immediately). Fire-and-forget on the ban itself since this runs on the hot
// message-handling path.
function recordRateLimitViolation(info: ClientInfo) {
  // Admin-facing kill switch (GET/PUT /admin/antispam) — off entirely means
  // not even counting, so re-enabling it later starts a fresh window instead
  // of immediately banning someone for violations that piled up while it
  // was off. Per-request limits from consumeRateLimit itself (the "hit
  // rejected" case, not this violation-tracking layer) still apply either
  // way — this only ever controls the auto-*ban*.
  if (!isAntiSpamEnabled()) return;
  if (!recordViolation(info.ip, AUTO_BAN_VIOLATION_LIMIT, AUTO_BAN_VIOLATION_WINDOW_MS)) return;
  autoBansTotal.inc();
  void banIp(
    info.ip,
    "Bloqueio automático: excesso de mensagens (possível bot de spam)",
    AUTO_BAN_DURATION_MINUTES
  )
    .then(() => disconnectClientsByIp(info.ip))
    .catch(() => {});
}

export async function registerSignalingRoutes(app: FastifyInstance, genId: () => string) {
  // Restores whatever topwarn was active before this process last
  // restarted (deploy, crash) — see announcementStore.ts. Awaited before any
  // route/the "/ws" handler below is registered so the very first request
  // this process serves already sees it, same as initModerationStore/
  // initAccountStore in index.ts.
  currentAnnouncement = await loadPersistedAnnouncement();
  if (currentAnnouncement) {
    announcementStats = { viewerIds: new Set(), buttonClicks: 0, xClicks: 0 };
  }
  // Restores the configured partner ads (and the empty-response percentage)
  // the same way — see partnerStore.ts.
  partnerConfig = await loadPersistedPartnerConfig();
  // ...along with each ad's accumulated views/clicks, so the admin panel
  // keeps showing an ongoing campaign's real totals instead of restarting
  // from zero on every deploy. Only ids that still exist in the config are
  // hydrated — anything else is a leftover with nowhere to be displayed.
  const persistedPartnerStats = await loadPersistedPartnerStats();
  for (const partner of partnerConfig.partners) {
    const persisted = persistedPartnerStats[partner.id];
    if (!persisted) continue;
    const entry = getPartnerStats(partner.id);
    entry.views = persisted.views;
    entry.sessionViews = persisted.sessionViews;
    entry.clicks = persisted.clicks;
    entry.clicksByVideo = persisted.clicksByVideo;
    entry.rewardVideoOpens = persisted.rewardVideoOpens;
    entry.rewardVideoCompletions = persisted.rewardVideoCompletions;
  }
  // Restores the configured supporters list the same way — see
  // supporterStore.ts.
  currentSupporters = sortSupporters(await loadPersistedSupporters());

  // Detects and reaps half-dead connections (network dropped without a clean
  // close, e.g. mobile network handoff, sleeping laptop, NAT/proxy silently
  // dropping an idle socket). Without this, a client can vanish for other
  // peers with no "peer-left" until the OS eventually notices the TCP
  // connection is gone, which can take minutes — the pings also generate
  // periodic traffic that keeps idle-timeout proxies from killing the
  // connection in the first place.
  const heartbeat = setInterval(() => {
    const now = Date.now();
    for (const [targetId, queue] of pendingSignals) {
      const fresh = queue.filter((item) => now - item.queuedAt <= PENDING_SIGNAL_TTL_MS);
      if (fresh.length === 0) pendingSignals.delete(targetId);
      else if (fresh.length !== queue.length) pendingSignals.set(targetId, fresh);
    }
    for (const info of clients.values()) {
      if (!info.isAlive) {
        heartbeatReapedTotal.inc();
        info.socket.terminate();
        continue;
      }
      info.isAlive = false;
      info.socket.ping();
    }
  }, HEARTBEAT_INTERVAL_MS);

  app.addHook("onClose", (_instance, done) => {
    clearInterval(heartbeat);
    done();
  });

  // Site-wide "people online" counter. Unlike /rooms this includes private
  // rooms — but only ever returns a single aggregate number, never handles
  // or peer detail, so it can't be used to discover a private room's
  // existence the way /admin/rooms can.
  //
  // Public and cheap, and realistically polled by every open tab's UI
  // (people-online widget) — generous limit, well above what one real
  // visitor's polling loop needs, tuned against a scripted hammering loop
  // instead.
  app.get("/stats", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    let peopleOnline = 0;
    for (const info of rooms.values()) peopleOnline += realPeopleCount(info);
    return { peopleOnline };
  });

  // Public room directory. Private rooms (handle starts with "priv-") are
  // filtered out here, server-side — the client never receives them, so
  // there's no separate access-control step to forget on the frontend.
  //
  // Same reasoning/limit as /stats: public, cheap, polled by the room
  // browser UI on a normal cadence.
  app.get("/rooms", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    const publicRooms = [...rooms.entries()]
      .filter(([handle]) => !isPrivateRoom(handle))
      .map(([handle, info]) => ({
        handle,
        peopleCount: realPeopleCount(info),
        createdAt: info.createdAt,
      }))
      .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
    return { rooms: publicRooms };
  });

  // Does this exact room exist? Two callers on the home page, wanting
  // opposite things from the same answer.
  //
  // The public room field asks as you type (debounced), purely so the
  // button can say "Criar sala" or "Entrar na sala" before it's pressed —
  // for a public room the two are the same click, and only the wording
  // tells you which one you're about to do.
  //
  // Private "Entrar em sala" asks on submit, where it's load-bearing:
  // joining a room that isn't there *creates* it, so without this a
  // mistyped digit silently opens a brand-new room and the person sits
  // alone in it wondering where everyone is.
  //
  // Answers for public and private rooms alike, but only ever about a
  // handle the caller already spelled out in full: for a private room that
  // means already knowing name *and* code, which is the same thing that
  // gets you in the door anyway (see roomCodeFromHandle) — so this hands
  // back nothing that joining wouldn't. The limit still matters, and is why
  // the typing-driven check is deliberately public-only on the client: it
  // keeps this from being a cheap way to sweep the code space for a name
  // someone has guessed.
  app.get<{ Params: { handle: string } }>(
    "/rooms/:handle/exists",
    { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const handle = request.params.handle;
      if (!HANDLE_RE.test(handle)) {
        return reply.code(400).send({ error: "Nome de sala inválido." });
      }
      // In memory means people are in it right now; a persisted record
      // means it existed and emptied out (the room is recreated with its
      // history intact on the next join — see the "join" handler), which
      // for someone holding the link is just as much "this room exists".
      if (rooms.has(handle)) return { exists: true };
      return { exists: (await loadRoomRecord(handle)) !== null };
    }
  );

  // Account system: create/login work for anyone, no auth required going
  // in. Admin is no longer a separate Basic-Auth credential (see the old
  // adminAuth.ts) — it's just an account whose flags include "ADMIN" (see
  // accountStore.ts's initAccountStore bootstrap), checked identically to
  // every other route below via requireAdmin.
  // Account creation — cheap to abuse into a spam/enumeration tool if left
  // uncapped (each attempt tries a password hash + a uniqueness check), and
  // nobody legitimately creates more than a couple of accounts per IP in a
  // sitting, so this stays tight.
  app.post(
    "/auth/register",
    { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } },
    async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = (typeof body.username === "string" ? body.username.trim() : "").toLowerCase();
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!USERNAME_RE.test(username)) {
      return reply.code(400).send({ error: "Usuário inválido — use 3 a 20 letras, números ou _." });
    }
    if (!isValidDisplayName(displayName)) {
      return reply.code(400).send({ error: "Nome de exibição inválido." });
    }
    if (password.length < 6 || password.length > 200) {
      return reply.code(400).send({ error: "Senha deve ter entre 6 e 200 caracteres." });
    }
    try {
      const account = await createAccount(username, displayName, password, request.ip);
      const token = signToken({ sub: account.id, username: account.username, flags: account.flags });
      return { token, account };
    } catch (err) {
      const message = err instanceof Error ? err.message : "Falha ao criar conta.";
      return reply.code(409).send({ error: message });
    }
  });

  // Login is the classic brute-force target — capped tighter than most
  // routes here, but loose enough that someone fat-fingering their own
  // password a few times in a row doesn't get locked out mid-attempt.
  app.post("/auth/login", { config: { rateLimit: { max: 10, timeWindow: "5 minutes" } } }, async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const account = await verifyAccountLogin(username, password, request.ip);
    if (!account) {
      return reply.code(401).send({ error: "Usuário ou senha inválidos." });
    }
    // A banned account is refused its token outright rather than being let
    // in to fail later at "register" — the credentials are right, so saying
    // "wrong password" would just be a lie, and handing out a token that
    // can't be used anywhere is worse than none.
    const ban = isBanned("account", account.id);
    if (ban) {
      return reply
        .code(403)
        .send({ error: ban.reason ? `Conta banida: ${ban.reason}` : "Conta banida." });
    }
    const token = signToken({ sub: account.id, username: account.username, flags: account.flags });
    return { token, account };
  });

  // Token verify + a fresh MongoDB read (not just the boot-time cache), so
  // a flag change made directly in the database shows up here without
  // needing a server restart. Realistically called on every page
  // load/focus to confirm the session — generous like /stats.
  app.get("/auth/me", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const payload = verifyToken(request.headers.authorization?.startsWith("Bearer ")
      ? request.headers.authorization.slice(7)
      : null);
    if (!payload) return reply.code(401).send({ error: "unauthorized" });
    const account = await refreshAccountFromMongo(payload.sub);
    if (!account) return reply.code(401).send({ error: "unauthorized" });
    // A banned account's session stops resolving here, which is what makes
    // the ban stick no matter where the token came from — /auth/login refuses
    // to issue one at all, but the OAuth callbacks (oauthRoutes.ts) hand one
    // out at four different points, and every client bootstraps its session
    // through this endpoint. Treated as an expired session rather than a
    // distinct status: the client drops the token and shows a logged-out
    // state, and the reason is delivered where it can actually be read (see
    // the "banned" message in the WS register handler).
    if (isBanned("account", account.id)) return reply.code(401).send({ error: "unauthorized" });
    // Which social providers this account can log in with, plus whether it
    // has a password at all — an account created through Discord/Google
    // doesn't (see accountStore.ts), and the client needs to know that to
    // show the right options instead of an empty password form.
    return { account, connections: getAccountConnections(account.id) };
  });

  // Public profile page (see app/user/[id]/page.tsx) — reachable by clicking
  // a name in the room header or the participant list, both of which now
  // send the account id as PeerInfo.userId (see peerSummary). Unauthenticated
  // on purpose, same as /partner and /rooms: nothing here is more sensitive
  // than what a room's own peer list already shows to everyone in it.
  app.get("/users/:id", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const account = await refreshAccountFromMongo(id);
    if (!account) return reply.code(404).send({ error: "Usuário não encontrado." });
    return { account, live: findLivePublicRoomForAccount(id) };
  });

  // Full room directory for moderators — unlike /rooms, this includes
  // private rooms and per-peer detail, since moderation is the one
  // legitimate reason to need that visibility.
  // Every /admin/* route below is already gated by requireAdmin, so its
  // realistic caller set is just the admin panel itself (a handful of
  // moderators at most) — limits here exist as a backstop against a buggy
  // polling loop or a leaked token, not against a wide pool of untrusted
  // callers, so GETs get a generous per-minute budget...
  app.get("/admin/rooms", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const allRooms = [...rooms.entries()]
      .map(([handle, info]) => ({
        handle,
        isPrivate: isPrivateRoom(handle),
        createdAt: info.createdAt,
        peopleCount: realPeopleCount(info),
        // Stable identity of whoever currently owns the room (see
        // stableUserId / leaveRoom's ownership handoff): an accountId for a
        // logged-in owner, a guest id otherwise. Sent so the admin panel can
        // both tag the owner in the peer list and find a room by its owner's
        // id even when that person isn't the one being searched by name.
        ownerId: info.ownerId ?? null,
        // 6-digit access code of a private room — nothing gates entry on it
        // yet (see roomStore.ts's RoomRecord.code), but a moderator looking
        // for "the private room someone gave me the code to" has no other
        // way to find it.
        code: info.code ?? null,
        // Room video sources (see RoomVideoSource) are attributed to whoever
        // added them, so the per-peer count below is what the admin panel
        // filters on — this total is just the room-level summary.
        videoSourceCount: info.videoSources.length,
        peers: [...info.sockets]
          .map((s) => clients.get(s))
          .filter((c): c is ClientInfo => c !== undefined && !c.isModerator)
          .map((c) => ({
            id: c.id,
            name: c.name,
            sharing: c.sharing,
            // Per-channel breakdown of `sharing` — see
            // ClientInfo.sharingScreen. null means an older client that
            // never told us which of the two it is.
            screen: c.sharingScreen ?? null,
            camera: c.sharingCamera ?? null,
            // How many of the room's video sources this person put there.
            // Keyed on stableUserId, the same identity RoomVideoSource
            // records in addedById — not the connection id, which changes
            // on every reconnect.
            videoSources: info.videoSources.filter((v) => v.addedById === stableUserId(c)).length,
            mic: c.mic,
            ip: c.ip,
            isGuest: !c.accountId,
            // Everything below exists purely so the admin panel's search can
            // find a room by *who's in it*. `name` alone isn't enough: an
            // account's display name can differ from its username, and a
            // guest's name is whatever they typed this session, so neither
            // is a reliable handle for "find this person's room".
            accountId: c.accountId ?? null,
            username: c.accountId ? getPublicAccountById(c.accountId)?.username ?? null : null,
            // Persists across a guest's reconnects (see the "register"
            // handler's guest token) — the closest thing to a stable id a
            // non-account visitor has.
            guestId: c.guestId ?? null,
            // See ClientInfo.fingerprint. null for a client that never sent
            // one (an outdated one, or one that strips it) — the panel just
            // doesn't offer the browser-ban button for those.
            fingerprint: c.fingerprint ?? null,
          })),
      }))
      .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
    return { rooms: allRooms };
  });

  // Site-wide banner shown to every connected socket (see broadcastToAll),
  // not scoped to a room. GET lets the admin panel show whether one's
  // already active on load (plus its live engagement stats); POST creates a
  // brand new one (fresh id + stats, see parseAnnouncementBody/genId below);
  // PUT edits the currently active one in place (same id, stats preserved,
  // version bumped — see the Announcement.version doc comment); DELETE ends
  // it for everyone currently connected.
  app.get(
    "/admin/announcement",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { announcement: currentAnnouncement, stats: announcementStatsSummary() };
    }
  );

  // ...while mutating admin actions (POST/PUT/DELETE) get a tighter one —
  // still far above what a human clicking a button ever needs, just enough
  // to blunt a runaway script.
  app.post("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const parsed = parseAnnouncementBody(body);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }
    const rawId = typeof body.id === "string" ? body.id.trim() : "";
    if (rawId && !ANNOUNCEMENT_ID_RE.test(rawId)) {
      return reply.code(400).send({ error: "ID inválido — use até 64 letras, números, _ ou -." });
    }

    currentAnnouncement = { id: rawId || genId(), version: 1, ...parsed };
    // A brand new announcement always starts its own fresh counters, even if
    // it reuses a previous id on purpose — see the AnnouncementStatsEntry
    // doc comment for why PUT (edit) instead preserves this bucket.
    announcementStats = { viewerIds: new Set(), buttonClicks: 0, xClicks: 0 };
    await savePersistedAnnouncement(currentAnnouncement);
    broadcastToAll({ type: "announcement", announcement: currentAnnouncement, live: true });
    return { announcement: currentAnnouncement, stats: announcementStatsSummary() };
  });

  app.put("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    if (!currentAnnouncement) {
      return reply.code(404).send({ error: "Nenhum aviso ativo para editar." });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    // Guards against two admin tabs editing stale state — a client that
    // fetched the active announcement before someone else replaced it (a
    // fresh POST, different id) gets told instead of silently overwriting
    // whatever's live now under a stranger's id.
    const bodyId = typeof body.id === "string" ? body.id : "";
    if (bodyId && bodyId !== currentAnnouncement.id) {
      return reply.code(409).send({ error: "O aviso ativo mudou em outra sessão — recarregue e tente de novo." });
    }
    const parsed = parseAnnouncementBody(body);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }

    currentAnnouncement = { ...currentAnnouncement, ...parsed, version: currentAnnouncement.version + 1 };
    await savePersistedAnnouncement(currentAnnouncement);
    broadcastToAll({ type: "announcement", announcement: currentAnnouncement, live: true });
    return { announcement: currentAnnouncement, stats: announcementStatsSummary() };
  });

  app.delete("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    currentAnnouncement = null;
    announcementStats = null;
    await deletePersistedAnnouncement();
    broadcastToAll({ type: "announcement", announcement: null, live: true });
    return reply.code(204).send();
  });

  // Supporters list shown on hover over "Apoiar projeto" (see
  // components/SupportersTooltip.tsx). Public and cheap — fetched once on
  // page load, same budget as /partner. Live edits reach an already-open
  // page via the "supporters" broadcast below instead, same as
  // announcement/partner.
  app.get("/supporters", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    return { supporters: currentSupporters };
  });

  app.get(
    "/admin/supporters",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { supporters: currentSupporters };
    }
  );

  // Replaces the whole list at once — same shape as PUT /admin/banned-words,
  // and for the same reason: simplest match for an admin textarea of one
  // supporter per line, and avoids the list drifting out of sync with what
  // the admin panel shows the way incremental add/remove endpoints could.
  app.put("/admin/supporters", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (!Array.isArray(body.supporters)) {
      return reply.code(400).send({ error: "Lista de apoiadores inválida." });
    }
    const parsed: Supporter[] = [];
    for (const entry of body.supporters) {
      if (!entry || typeof entry !== "object") {
        return reply.code(400).send({ error: "Lista de apoiadores inválida." });
      }
      const rawEntry = entry as Record<string, unknown>;
      const name =
        typeof rawEntry.name === "string" ? rawEntry.name.trim().slice(0, MAX_SUPPORTER_NAME_LEN) : "";
      const amount = Number(rawEntry.amount);
      if (!name || !Number.isFinite(amount) || amount < 0) {
        return reply.code(400).send({ error: "Cada apoiador precisa de nome e valor válidos." });
      }
      parsed.push({ name, amount });
    }
    currentSupporters = sortSupporters(parsed.slice(0, MAX_SUPPORTERS));
    await savePersistedSupporters(currentSupporters);
    broadcastToAll({ type: "supporters", supporters: currentSupporters });
    return { supporters: currentSupporters };
  });

  // Sidebar partner-ad slot (see components/PartnerCard.tsx). Public and
  // cheap — polled once per page load/reload, same budget as /stats/rooms.
  // `emptyPercent` (see partnerStore.ts) is rolled *here*, per request, so a
  // brand new or reloaded page sometimes gets nothing even with partners
  // active — the live socket push (see broadcastPartnerUpdate) deliberately
  // never rolls this, only this HTTP path does.
  app.get("/partner", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request) => {
    // "current" is the ad the caller is showing right now (see PartnerCard's
    // rotation), and it is excluded outright: when it is present this route
    // never answers with that same id, full stop.
    //
    // No fallback to the whole pool when the exclusion empties it. With a
    // single active ad that means a rotation answers empty, and the caller
    // shows the house ad instead — which is the right outcome, not a
    // degenerate one: the slot alternates between the advertiser and the
    // "anuncie aqui" pitch rather than "rotating" onto the same thing it was
    // already showing. The next rotation has no current to send (the slot is
    // empty), so the ad comes back.
    //
    // Safe to take from an unauthenticated caller: the worst an arbitrary id
    // can do is remove one ad from one request's roll.
    const currentId = typeof (request.query as { current?: unknown })?.current === "string"
      ? (request.query as { current: string }).current
      : null;
    const pool = currentId
      ? activePartners().filter((p) => p.id !== currentId)
      : activePartners();
    const showEmpty = partnerConfig.emptyPercent > 0 && Math.random() * 100 < partnerConfig.emptyPercent;
    const picked = showEmpty ? null : pickWeightedPartner(pool);
    return { partner: picked ? publicPartner(picked) : null };
  });

  // Pays out a partner ad's watch-to-earn reward (see PartnerRewardModal.tsx
  // — it only calls this once the video's `ended` event fires, having blocked
  // skipping ahead of it) — requires a real account (guests have nowhere to
  // hold points, see accountModels.ts), and pays out at most once per
  // account per ad, enforced server-side (claimPersistedPartnerReward) rather
  // than trusted from local storage, which is only ever a UI convenience.
  app.post(
    "/partner/:id/claim-reward",
    { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const payload = verifyToken(getBearerToken(request.headers.authorization));
      if (!payload || payload.guest) {
        return reply
          .code(401)
          .send({ error: "Crie uma conta ou entre em uma para receber pontos assistindo." });
      }
      const { id } = request.params as { id: string };
      const partner = partnerConfig.partners.find((p) => p.id === id);
      if (!partner || !partner.rewardVideoUrl || !partner.rewardPoints) {
        return reply.code(404).send({ error: "Esse anúncio não tem recompensa em vídeo." });
      }
      const claimed = await claimPersistedPartnerReward(id, payload.sub, "video");
      if (!claimed) {
        return reply.code(409).send({ error: "Você já resgatou essa recompensa." });
      }
      const points = await addAccountPoints(payload.sub, partner.rewardPoints);
      return { points };
    }
  );

  // The click-to-earn twin of the endpoint above: points for clicking the
  // ad's CTA. Same one-per-account-per-ad gate, from its own claim set — the
  // two rewards are independent, so collecting one must never consume the
  // other. Deliberately does not care *where* the click happened
  // (clickRewardPlacement is a UI decision about where the points are
  // offered, and the client is not a source of truth about which button it
  // rendered); what it enforces is that the ad has a click reward at all.
  app.post(
    "/partner/:id/claim-click-reward",
    { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const payload = verifyToken(getBearerToken(request.headers.authorization));
      if (!payload || payload.guest) {
        return reply
          .code(401)
          .send({ error: "Crie uma conta ou entre em uma para receber pontos clicando." });
      }
      const { id } = request.params as { id: string };
      const partner = partnerConfig.partners.find((p) => p.id === id);
      if (!partner || !partner.clickRewardPoints) {
        return reply.code(404).send({ error: "Esse anúncio não dá pontos por clique." });
      }
      const claimed = await claimPersistedPartnerReward(id, payload.sub, "click");
      if (!claimed) {
        return reply.code(409).send({ error: "Você já resgatou os pontos desse anúncio." });
      }
      const points = await addAccountPoints(payload.sub, partner.clickRewardPoints);
      return { points };
    }
  );

  // Full partner list + live stats for the admin panel — unlike GET
  // /partner, includes every partner (even expired/inactive ones — see
  // Partner.expiresAt's doc comment) and the admin-only weight/createdAt
  // fields, plus each one's engagement numbers.
  app.get("/admin/partners", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return {
      partners: partnerConfig.partners,
      emptyPercent: partnerConfig.emptyPercent,
      stats: await partnerStatsSummaries(partnerConfig.partners.map((p) => p.id)),
    };
  });

  app.post("/admin/partners", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const parsed = parsePartnerBody(body);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }
    const partner: Partner = { id: genId(), createdAt: Date.now(), ...parsed };
    partnerConfig = { ...partnerConfig, partners: [...partnerConfig.partners, partner] };
    await savePersistedPartnerConfig(partnerConfig);
    broadcastPartnerUpdate();
    return { partner, stats: (await partnerStatsSummaries([partner.id]))[partner.id] };
  });

  app.put("/admin/partners/:id", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const { id } = request.params as { id: string };
    const existing = partnerConfig.partners.find((p) => p.id === id);
    if (!existing) {
      return reply.code(404).send({ error: "Anúncio não encontrado." });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const parsed = parsePartnerBody(body);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }
    const updated: Partner = { ...existing, ...parsed };
    partnerConfig = {
      ...partnerConfig,
      partners: partnerConfig.partners.map((p) => (p.id === id ? updated : p)),
    };
    await savePersistedPartnerConfig(partnerConfig);
    broadcastPartnerUpdate();
    return { partner: updated, stats: (await partnerStatsSummaries([id]))[id] };
  });

  app.delete("/admin/partners/:id", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const { id } = request.params as { id: string };
    partnerConfig = { ...partnerConfig, partners: partnerConfig.partners.filter((p) => p.id !== id) };
    partnerStats.delete(id);
    await deletePersistedPartnerStats(id);
    await deletePersistedPartnerRewardClaims(id);
    await savePersistedPartnerConfig(partnerConfig);
    broadcastPartnerUpdate();
    return reply.code(204).send();
  });

  // The global "show nothing X% of the time" knob (see partnerStore.ts's
  // PartnerConfig.emptyPercent doc comment) — separate from the per-partner
  // CRUD above since it's not scoped to any one partner. No live broadcast
  // needed: it only ever affects the GET /partner roll for a future request,
  // never anyone already connected.
  app.put(
    "/admin/partner-settings",
    { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      const body = (request.body ?? {}) as Record<string, unknown>;
      const rawPercent = typeof body.emptyPercent === "number" ? body.emptyPercent : NaN;
      if (!Number.isFinite(rawPercent) || rawPercent < 0 || rawPercent > 100) {
        return reply.code(400).send({ error: "Porcentagem inválida — use um número entre 0 e 100." });
      }
      partnerConfig = { ...partnerConfig, emptyPercent: rawPercent };
      await savePersistedPartnerConfig(partnerConfig);
      return { emptyPercent: partnerConfig.emptyPercent };
    }
  );

  // Dashboard overview for the admin panel — aggregate numbers only (no
  // room/peer detail, see /admin/rooms for that), so it's cheap to poll.
  app.get("/admin/stats", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    let peopleOnline = 0;
    let sharingCount = 0;
    let publicRooms = 0;
    let privateRooms = 0;
    for (const [handle, info] of rooms) {
      peopleOnline += realPeopleCount(info);
      sharingCount += realSharingCount(info);
      if (isPrivateRoom(handle)) privateRooms += 1;
      else publicRooms += 1;
    }
    return {
      connectedSockets: clients.size,
      peopleOnline,
      sharingCount,
      publicRooms,
      privateRooms,
      bannedIps: countBans("ip"),
      bannedAccounts: countBans("account"),
      bannedFingerprints: countBans("fingerprint"),
      bannedWords: listBannedWords().length,
      mongo: { enabled: MONGO_ENABLED, connected: isMongoConnected() },
    };
  });

  // Ban list/management, for all three subjects (see moderationStore.ts's
  // BanSubject). Banning takes effect immediately: any socket currently
  // matching is disconnected right away (see disconnectBannedClients). An IP
  // ban is additionally enforced at the "/ws" upgrade itself, before the
  // connection is ever added to `clients`; the other two can't be — neither
  // the account nor the fingerprint is known until "register" — so those are
  // enforced there instead.
  app.get("/admin/bans", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    // `ip` is a legacy alias for `value`, kept so an admin panel left open
    // across the deploy that added subjects still renders its list instead
    // of a column of "undefined".
    return { bans: listBans().map((ban) => ({ ...ban, ip: ban.value })) };
  });

  app.post("/admin/bans", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const subject = parseBanSubject(body.subject);
    if (!subject) {
      return reply.code(400).send({ error: "Tipo de banimento inválido." });
    }
    // `ip` is still accepted as the value field for an IP ban — that's what
    // every caller sent before this endpoint knew about other subjects.
    const rawValue = typeof body.value === "string" ? body.value : typeof body.ip === "string" ? body.ip : "";
    const value = rawValue.trim();
    const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, BAN_REASON_MAX_LEN) : "";
    const durationMinutes =
      typeof body.durationMinutes === "number" && Number.isFinite(body.durationMinutes) && body.durationMinutes > 0
        ? body.durationMinutes
        : null;
    if (!isValidBanValue(subject, value)) {
      return reply.code(400).send({
        error:
          subject === "ip"
            ? "IP inválido."
            : subject === "account"
              ? "Id de conta inválido."
              : "Fingerprint inválido.",
      });
    }
    const ban = await addBan(subject, value, reason, durationMinutes);
    disconnectBannedClients(subject, value);
    return { ban: { ...ban, ip: ban.value } };
  });

  app.delete(
    "/admin/bans/:subject/:value",
    { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      const params = request.params as { subject: string; value: string };
      const subject = parseBanSubject(params.subject);
      if (!subject) {
        return reply.code(400).send({ error: "Tipo de banimento inválido." });
      }
      await removeBan(subject, params.value);
      return reply.code(204).send();
    }
  );

  // Legacy single-segment form, from before bans had subjects — always an
  // IP, since that's all this route could ever have been used for.
  app.delete("/admin/bans/:ip", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const { ip } = request.params as { ip: string };
    await unbanIp(ip);
    return reply.code(204).send();
  });

  // Chat content filter — one flat list of forbidden words/phrases, replaced
  // wholesale on every PUT (see setBannedWords) rather than incremental
  // add/remove endpoints, matching the shape of a single admin textarea.
  app.get(
    "/admin/banned-words",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { words: listBannedWords() };
    }
  );

  app.put("/admin/banned-words", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (!Array.isArray(body.words) || !body.words.every((w) => typeof w === "string")) {
      return reply.code(400).send({ error: "Lista de palavras inválida." });
    }
    const words = await setBannedWords(body.words as string[]);
    return { words };
  });

  // Kill switch for the auto-ban system (see recordRateLimitViolation) —
  // lets an admin turn it off at runtime, no redeploy, e.g. if it's
  // wrongly banning real users during an unrelated slowdown that makes
  // their retries look like spam.
  app.get(
    "/admin/antispam",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { enabled: isAntiSpamEnabled() };
    }
  );

  app.put("/admin/antispam", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (typeof body.enabled !== "boolean") {
      return reply.code(400).send({ error: "Campo 'enabled' inválido." });
    }
    const enabled = await setAntiSpamEnabled(body.enabled);
    return { enabled };
  });

  app.get(
    "/ws",
    {
      websocket: true,
      // Bounds *connection attempts* per IP, not concurrent connections or
      // anything that happens over an already-open socket (that's the
      // per-message limiters in rateLimiter.ts, applied inside the message
      // handler below). 30/min comfortably covers a real client's
      // reconnect/backoff behavior (network blips, sleep/wake, page
      // reloads) while still bounding a connection-flood attempt.
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    (socket: WebSocket, request: FastifyRequest) => {
    const ip = request.ip;
    if (isIpBanned(ip)) {
      bannedIpConnectionsRejectedTotal.inc();
      socket.close(BANNED_CLOSE_CODE, "ip-banned");
      return;
    }

    const info: ClientInfo = {
      id: genId(),
      name: null,
      room: null,
      sharing: false,
      mic: false,
      isAlive: true,
      socket,
      ip,
      geoLocation: lookupConnectionLocation(ip),
      rateLimitKey: genId(),
    };
    clients.set(socket, info);
    wsConnectionsTotal.inc();
    send(socket, { type: "welcome", id: info.id });
    // "online-only" is deliberately never handed to a connection that shows
    // up after it was sent — that's the entire distinction from "all" (see
    // AnnouncementVisibility above). `live: false` tells the client this is
    // a catch-up delivery, not a fresh one (see AnnouncementBanner.tsx's
    // sound handling).
    if (currentAnnouncement && currentAnnouncement.visibility === "all") {
      send(socket, { type: "announcement", announcement: currentAnnouncement, live: false });
    }

    socket.on("pong", () => {
      info.isAlive = true;
    });

    socket.on("message", async (raw: Buffer) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (!msg || typeof msg.type !== "string") return;

      // Backstop across every message type combined for this connection —
      // runs before the per-type limiters below so it also catches a flood
      // of a `type` no case here recognizes (which the `default: break`
      // would otherwise process at unlimited rate).
      if (!(await consumeRateLimit(wsGlobalLimiter, info.rateLimitKey, "global"))) return;

      switch (msg.type) {
        case "register": {
          // Covers both the initial registration and every later rename
          // (renaming doesn't re-enter via "join" — see below), so one
          // budget for both is enough to stop a rename-spam loop without
          // getting in the way of a real, occasional name change.
          if (!(await consumeRateLimit(wsRegisterLimiter, info.rateLimitKey, "register"))) {
            send(socket, { type: "register-error", message: "Muitas tentativas. Aguarde um instante." });
            recordRateLimitViolation(info);
            return;
          }
          // A logged-in client passes its account JWT here; a guest passes
          // whatever guest token a previous "registered" response handed it
          // (see below) — same `token` field either way, told apart by the
          // decoded payload's `guest` flag. Neither is required: an old
          // client that only ever knew about plain names/clientIds sends
          // nothing here and still works exactly as before.
          const rawToken = typeof msg.token === "string" ? msg.token : "";
          const authPayload = rawToken ? verifyToken(rawToken) : null;
          const isAccountToken = Boolean(authPayload && !authPayload.guest);

          // Browser fingerprint (see ClientInfo.fingerprint). Recorded on
          // every register — it's the same value each time for a given
          // browser, so re-sending it is how a connection that opened before
          // the client had computed it still ends up identified.
          const rawFingerprint = typeof msg.fingerprint === "string" ? msg.fingerprint : "";
          if (rawFingerprint && isValidBanValue("fingerprint", rawFingerprint)) {
            info.fingerprint = rawFingerprint;
          }
          // The two bans that can't be enforced at connection time the way an
          // IP ban is: neither the account nor the fingerprint is known until
          // this message arrives. Closing (rather than just refusing the
          // name) is what stops the client from retrying forever — the close
          // code puts it in the same "banned" state an IP ban does.
          const fingerprintBan = isBanned("fingerprint", info.fingerprint);
          const accountBan = isAccountToken ? isBanned("account", authPayload!.sub) : null;
          const identityBan = accountBan ?? fingerprintBan;
          if (identityBan) {
            registerErrorsTotal.inc();
            // A dedicated message rather than a "register-error": this isn't
            // something a different name would fix, and the close that
            // follows is what the client actually reacts to. Sending the
            // moderator's own reason lets it say *why* instead of falling
            // back to the generic auto-ban wording (an IP ban has no
            // equivalent — it's rejected at the "/ws" upgrade, before there's
            // a client to tell anything to).
            send(socket, {
              type: "banned",
              subject: identityBan.subject,
              reason: identityBan.reason || null,
            });
            socket.close(BANNED_CLOSE_CODE, `${identityBan.subject}-banned`);
            return;
          }

          // A logged-in account's display name always comes from its own
          // account record, never from whatever the client sends alongside
          // the token — otherwise `name` would be the one piece of identity
          // info an account holder could still freely spoof despite a valid
          // token, and it'd let the name drift from what the account
          // actually shows elsewhere (e.g. the admin panel, chat history
          // from other rooms). A guest has no such record, so its name
          // stays exactly what it always was: whatever it types.
          let rawName: string;
          // Re-fetched from Mongo (not the boot-time cache) and reused below
          // for info.flags — the JWT's own `flags` claim is a snapshot from
          // whenever this token was signed, so trusting it here would mean a
          // flag granted (or revoked) since then never takes effect until
          // the holder logs in again for a fresh token.
          let freshAccount: Awaited<ReturnType<typeof refreshAccountFromMongo>> = null;
          if (isAccountToken) {
            freshAccount = await refreshAccountFromMongo(authPayload!.sub);
            if (!freshAccount) {
              // The account behind this token doesn't exist anymore
              // (deleted after the token was issued) — treat it like any
              // other invalid token rather than trusting a name for an
              // account that's gone.
              registerErrorsTotal.inc();
              send(socket, { type: "register-error", message: "Conta não encontrada." });
              return;
            }
            rawName = freshAccount.displayName;
          } else {
            rawName = typeof msg.name === "string" ? msg.name.trim().slice(0, 24) : "";
          }
          if (!isValidDisplayName(rawName)) {
            registerErrorsTotal.inc();
            send(socket, { type: "register-error", message: "Nome inválido." });
            return;
          }

          let newGuestToken: string | null = null;
          if (isAccountToken) {
            info.accountId = authPayload!.sub;
            info.flags = freshAccount!.flags;
            info.guestId = undefined;
            info.guestVerified = false;
          } else {
            info.accountId = undefined;
            info.flags = undefined;
            if (authPayload && authPayload.guest) {
              info.guestId = authPayload.sub;
              info.guestVerified = true;
            } else if (!info.guestId) {
              // No usable token presented: mint a fresh, unverified guest
              // identity for this connection and hand back a token for it,
              // so the client can prove it's still the same guest next time
              // (see isSameOwner). Every connection that shows up without a
              // token gets its own distinct id here — that's what stops a
              // stranger from reusing this guest's publicly-visible name or
              // connection id to hijack the session below or in "join": they
              // can never produce a matching *verified* guestId.
              info.guestId = `guest:${genId()}`;
              info.guestVerified = false;
            }
            if (!info.guestVerified) {
              newGuestToken = signToken({ sub: info.guestId!, username: rawName, flags: [], guest: true });
            }
          }

          const key = rawName.toLowerCase();
          // A name tied to a registered account (its username or display
          // name) is reserved for that account's owner — anyone else, guest
          // or a different account, trying to register under it gets
          // rejected.
          const reservedOwnerId = isNameReserved(key);
          if (reservedOwnerId && reservedOwnerId !== info.accountId) {
            registerErrorsTotal.inc();
            send(socket, {
              type: "register-error",
              message: "Esse nome pertence a uma conta registrada.",
            });
            return;
          }

          // Renaming while already in a room doesn't go through "join"
          // again, so the room-scoped name collision "join" normally checks
          // (see below) has to be checked here instead — the same name
          // could already be held by someone else in *this* room.
          if (info.room) {
            const roomInfo = rooms.get(info.room);
            const holderSocket = roomInfo?.names.get(key);
            const holder = holderSocket && holderSocket !== socket ? clients.get(holderSocket) : undefined;
            if (holder && !isSameOwner(holder, info)) {
              registerErrorsTotal.inc();
              send(socket, { type: "register-error", message: "Esse nome já está em uso nesta sala." });
              return;
            }
          }

          const previousName = info.name;
          info.name = rawName;
          if (info.room) {
            const roomInfo = rooms.get(info.room);
            if (roomInfo) {
              if (previousName) roomInfo.names.delete(previousName.toLowerCase());
              roomInfo.names.set(key, socket);
            }
          }

          // A client-supplied id (persisted client-side across reloads) lets
          // a returning client reclaim its previous connection id instead of
          // showing up as a stranger to everyone else's still-open peer
          // connections. Only actually reclaimed if it's free, already ours,
          // or provably the same owner as whoever currently holds it —
          // otherwise someone merely guessing/observing another live
          // connection's id (it's visible to every peer in its room) could
          // hijack that session by presenting it back. A session that was
          // never given a chance to prove itself (no token ever verified for
          // it — the old, pre-token model) still trusts a bare id match by
          // default, to keep working exactly as it always has for clients
          // that don't know about tokens at all — see
          // ALLOW_OLD_CLIENTS_GUEST_SYSTEM.
          const requestedClientId = typeof msg.clientId === "string" ? msg.clientId : "";
          const clientId = CLIENT_ID_RE.test(requestedClientId) ? requestedClientId : null;
          if (clientId && clientId !== info.id) {
            const existingById = clientsById.get(clientId);
            if (!existingById) {
              if (clientsById.get(info.id) === info) clientsById.delete(info.id);
              info.id = clientId;
            } else if (existingById.socket !== socket) {
              const existingProtected =
                !ALLOW_OLD_CLIENTS_GUEST_SYSTEM || Boolean(existingById.accountId) || existingById.guestVerified;
              if (!existingProtected || isSameOwner(existingById, info)) {
                detachSession(existingById);
                if (clientsById.get(info.id) === info) clientsById.delete(info.id);
                info.id = clientId;
              }
              // else: someone else's protected session — ignore the
              // requested id and keep our own freshly generated one.
            }
          }
          clientsById.set(info.id, info);

          send(socket, {
            type: "registered",
            id: info.id,
            name: rawName,
            account: info.accountId ? { username: authPayload!.username, flags: info.flags ?? [] } : null,
            // Only sent when non-null — a guest whose existing token was
            // just verified above doesn't need a new one. A client that
            // doesn't understand this field simply ignores it, same as any
            // other unrecognized field.
            guestToken: newGuestToken,
          });

          // Renaming while already in a room doesn't go through "join"
          // again, so nothing else would tell the other participants —
          // without this their peer list would keep showing the old name.
          if (info.room && previousName && previousName !== rawName) {
            broadcastToRoom(info.room, { type: "peer-renamed", id: info.id, name: rawName }, socket);
          }
          break;
        }
        case "join": {
          // Shared with "admin-join" below — switching rooms is something a
          // real connection does rarely, never in a tight loop.
          if (!(await consumeRateLimit(wsJoinLimiter, info.rateLimitKey, "join"))) {
            send(socket, { type: "join-error", message: "Muitas tentativas. Aguarde um instante." });
            recordRateLimitViolation(info);
            return;
          }
          if (!info.name) {
            send(socket, { type: "error", message: "Registre um nome antes de entrar em uma sala." });
            return;
          }
          const room = typeof msg.room === "string" ? msg.room : "";
          if (!HANDLE_RE.test(room)) {
            send(socket, { type: "error", message: "Sala inválida." });
            return;
          }
          if (info.room === room) return;

          // Gates the join itself — this is also how a room gets *created*
          // in this codebase (the first join creates it), so this is the
          // one checkpoint that covers both "someone spun up a new room"
          // and "someone joined an existing one". Skipped if this connection
          // already passed it recently (info.turnstileVerifiedAt — see
          // ClientInfo and TURNSTILE_REVERIFY_INTERVAL_MS) so switching
          // rooms doesn't re-challenge someone freshly verified on this same
          // socket, while still forcing a re-check periodically rather than
          // trusting one solve for the connection's entire lifetime. Checked
          // before touching any room state; async (a real network call to
          // Cloudflare), so re-validate afterwards in case this socket moved
          // on (closed, or a second "join" already landed — see the
          // loadPersistedChat comment below for why that's possible).
          const turnstileStillFresh =
            info.turnstileVerifiedAt !== undefined &&
            Date.now() - info.turnstileVerifiedAt < TURNSTILE_REVERIFY_INTERVAL_MS;
          const turnstileToken = typeof msg.turnstileToken === "string" ? msg.turnstileToken : "";
          // While TURNSTILE_ENABLED is off, a token is never *required* — an
          // older client that's never heard of Turnstile sends nothing at
          // all and is let straight through, which is the whole point of
          // keeping it off until every client is known to send one. But an
          // already-updated client that does send a token still gets it
          // fully verified and enforced here regardless, rather than that
          // check being silently skipped — there's no backward-compat
          // reason to wave through a client that's actively claiming to have
          // passed the challenge.
          //
          // The post-restart grace window (TURNSTILE_STARTUP_GRACE_MS) is
          // the one exception to that last part: within it, verification is
          // skipped outright, token or no token. A restart's reconnect burst
          // hits Cloudflare's siteverify with everyone's token at once, and
          // a token that's genuinely valid can still come back *rejected*
          // under that load (network hiccup, Cloudflare briefly slow to
          // answer, VERIFY_TIMEOUT_MS in turnstile.ts tripping) —
          // from this server's side that's indistinguishable from an actual
          // failed challenge, so a client doing everything right would still
          // get turnstile-required and, after MAX_JOIN_RETRIES, a dead end.
          // Skipping the call entirely during the window sidesteps that
          // false-rejection risk rather than trying to tell it apart from a
          // real one.
          const withinStartupGrace = Date.now() - SERVER_START_TIME < TURNSTILE_STARTUP_GRACE_MS;
          const mustVerifyTurnstile =
            !turnstileStillFresh && !withinStartupGrace && (TURNSTILE_ENABLED || turnstileToken.length > 0);
          if (mustVerifyTurnstile) {
            const verified = await verifyTurnstileToken(turnstileToken, info.ip);
            turnstileVerificationsTotal.inc({ result: verified ? "success" : "failure" });
            if (!verified) {
              send(socket, {
                type: "turnstile-required",
                message: "Verificação de segurança necessária para entrar na sala.",
              });
              return;
            }
            info.turnstileVerifiedAt = Date.now();
            if (!clients.has(socket) || info.room === room) return;
          }

          // A name already held by someone else in *this* room is only ever
          // let through when it's provably the same guest/account already
          // there under another connection (a second tab, or a reload that
          // hasn't reclaimed its old connection id yet) — reclaiming just
          // takes over the slot instead of rejecting, same as a plain
          // clientId collision does in "register". Two different rooms
          // never collide this way (this check is scoped to `room` alone),
          // and a stranger presenting the same name they can see in the
          // room's peer list is turned away without touching the person
          // already there.
          const nameKey = info.name.toLowerCase();
          const existingRoomInfo = rooms.get(room);
          const holderSocket = existingRoomInfo?.names.get(nameKey);
          if (holderSocket && holderSocket !== socket) {
            const holder = clients.get(holderSocket);
            if (holder && isSameOwner(holder, info)) {
              detachSession(holder);
            } else {
              send(socket, { type: "join-error", message: "Esse nome já está em uso nesta sala." });
              return;
            }
          }

          if (info.room) leaveRoom(info);
          clearRoomDeletionTimer(room);
          info.room = room;
          info.sharing = false;
          info.sharingScreen = undefined;
          info.sharingCamera = undefined;
          info.mic = false;
          // Starts this connection's call-time segment (see
          // flushClientStats) — never for a moderator's admin-join ghost
          // connection, which never reaches this branch anyway.
          info.joinedAt = Date.now();
          let roomInfo = rooms.get(room);
          if (!roomInfo) {
            // Reloads any chat history and RoomRecord still persisted
            // (chatStore.ts/roomStore.ts) from before the room last emptied
            // out or the process last restarted — run together since both
            // are one round trip either way and this is the one point in
            // the whole "join" path that ever touches either store; every
            // later join into this same (now in-memory) room skips this
            // block entirely. Awaiting here means another client's "join"
            // for this same brand-new room could land while we wait —
            // re-check after, so we don't clobber a RoomInfo that landed
            // first.
            const [messages, existingRecord] = await Promise.all([
              loadPersistedChat(room),
              loadRoomRecord(room),
            ]);
            roomInfo = rooms.get(room);
            if (!roomInfo) {
              // No prior record means this join is the one creating the
              // room from scratch — this connection becomes its first
              // owner, and private/flags/code get real starting values
              // (see roomStore.ts's RoomRecord — none of it is enforced
              // anywhere yet, just persisted).
              const isPrivate = isPrivateRoom(room);
              const record: RoomRecord = existingRecord ?? {
                ownerId: stableUserId(info),
                private: isPrivate,
                flags: [],
                // From the handle itself when it carries one (see
                // roomCodeFromHandle) — the client generated it, and the
                // URL is what everyone shares.
                code: isPrivate ? roomCodeFromHandle(room) ?? generateRoomCode() : null,
              };
              roomInfo = {
                sockets: new Set(),
                createdAt: Date.now(),
                messages,
                names: new Map(),
                videoSources: [],
                ...record,
              };
              rooms.set(room, roomInfo);
              roomsCreatedTotal.inc({ visibility: isPrivateRoom(room) ? "private" : "public" });
              if (!existingRecord) void saveRoomRecord(room, record);
            }
          }
          // The await above gave this socket's own "leave"/another "join"
          // a chance to run first and move it elsewhere (or the socket
          // could've closed outright) — don't add it to a room it's no
          // longer trying to join.
          if (info.room !== room || !clients.has(socket)) return;
          roomInfo.sockets.add(socket);
          roomInfo.names.set(nameKey, socket);
          const peers = [...roomInfo.sockets]
            .filter((s) => s !== socket)
            .map((s) => clients.get(s))
            .filter((c): c is ClientInfo => c !== undefined)
            .map(peerSummary);
          send(socket, {
            type: "room-state",
            room,
            selfId: info.id,
            // The identity a video source is attributed to (see
            // RoomVideoSource.addedById and peerSummary's `userId`) — the
            // connection id above is per-socket and says nothing about who
            // this is across a reconnect.
            selfUserId: stableUserId(info),
            peers,
            messages: roomInfo.messages,
            videoSources: roomInfo.videoSources,
          });
          flushPendingSignals(info);
          broadcastToRoom(
            room,
            {
              type: "peer-joined",
              id: info.id,
              name: info.name,
              isGuest: !info.accountId,
              flags: info.flags ?? [],
              userId: stableUserId(info),
            },
            socket
          );
          break;
        }
        // A moderator entering a room to watch/listen for moderation.
        // Deliberately mirrors "join" (same room bookkeeping, same
        // room-state/peer-joined messages) so this socket rides the exact
        // same signal-relay and broadcaster-reactivity machinery a real
        // participant does — the only difference is the `role: "moderator"`
        // tag on its peer entry, which is what the client uses to keep it
        // out of the visible participant list/count. Leaving reuses the
        // plain "leave" message (and socket close already calls
        // leaveRoom() regardless), so no separate cleanup path is needed.
        case "admin-join": {
          if (!(await consumeRateLimit(wsJoinLimiter, info.rateLimitKey, "join"))) {
            send(socket, { type: "error", message: "Muitas tentativas. Aguarde um instante." });
            return;
          }
          const token = typeof msg.token === "string" ? msg.token : "";
          const adminPayload = verifyToken(token);
          if (!adminPayload || !adminPayload.flags.includes("ADMIN")) {
            send(socket, { type: "error", message: "Não autorizado." });
            socket.terminate();
            return;
          }
          const room = typeof msg.room === "string" ? msg.room : "";
          if (!HANDLE_RE.test(room)) {
            send(socket, { type: "error", message: "Sala inválida." });
            return;
          }
          const roomInfo = rooms.get(room);
          if (!roomInfo) {
            send(socket, { type: "error", message: "Sala não encontrada ou já encerrada." });
            return;
          }
          if (info.room === room) return;
          if (info.room) leaveRoom(info);
          info.isModerator = true;
          info.name = info.name ?? "Moderador";
          info.room = room;
          info.sharing = false;
          info.sharingScreen = undefined;
          info.sharingCamera = undefined;
          info.mic = false;
          roomInfo.sockets.add(socket);
          const adminPeers = [...roomInfo.sockets]
            .filter((s) => s !== socket)
            .map((s) => clients.get(s))
            .filter((c): c is ClientInfo => c !== undefined)
            .map(peerSummary);
          send(socket, {
            type: "room-state",
            room,
            selfId: info.id,
            peers: adminPeers,
            messages: roomInfo.messages,
            // Same list a regular participant gets on "join". A moderator
            // doesn't embed the videos, but it does need to know who put one
            // there — that's a third kind of "transmitting" the moderation
            // UI has to be able to tell apart from a screen or camera share.
            // The later video-source-added/removed broadcasts already reach
            // this socket like any other room member's.
            videoSources: roomInfo.videoSources,
          });
          flushPendingSignals(info);
          broadcastToRoom(
            room,
            {
              type: "peer-joined",
              id: info.id,
              name: info.name,
              isGuest: !info.accountId,
              flags: info.flags ?? [],
              role: "moderator",
            },
            socket
          );
          break;
        }
        case "leave": {
          if (info.room) leaveRoom(info);
          break;
        }
        case "sharing": {
          if (!info.room) return;
          // Dropped silently (no client feedback) when over budget: this is
          // transient toggle state, not a one-shot user action — the next
          // real toggle just propagates normally once the window resets.
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          // `screen`/`camera` are the per-channel breakdown (see
          // ClientInfo.sharingScreen); an older client sends neither and
          // only ever sets `sharing`. Either one being true also counts as
          // sharing on its own, so a client that ever stops sending the
          // rolled-up boolean still can't end up marked as not sharing.
          const nextSharing = Boolean(msg.sharing) || Boolean(msg.screen) || Boolean(msg.camera);
          // Opens/closes this connection's share-time segment (see
          // flushClientStats) — turning on starts the timer (only if it
          // wasn't already running, so a duplicate "sharing:true" is a
          // no-op); turning off closes it out and credits the account right
          // here, rather than waiting for the segment to close some other
          // way later.
          if (nextSharing) {
            if (info.sharingOnAt === undefined) info.sharingOnAt = Date.now();
          } else if (info.sharingOnAt !== undefined) {
            const shareSeconds = secondsSince(info.sharingOnAt, Date.now());
            info.sharingOnAt = undefined;
            if (info.accountId && shareSeconds > 0) {
              void addAccountCallStats(info.accountId, { shareSeconds });
            }
          }
          info.sharing = nextSharing;
          if (typeof msg.screen === "boolean" || typeof msg.camera === "boolean") {
            info.sharingScreen = Boolean(msg.screen);
            info.sharingCamera = Boolean(msg.camera);
          } else {
            // Nothing to go on — back to "unknown" rather than keeping a
            // breakdown this message never confirmed.
            info.sharingScreen = undefined;
            info.sharingCamera = undefined;
          }
          broadcastToRoom(info.room, {
            type: "peer-sharing",
            id: info.id,
            sharing: info.sharing,
            screen: info.sharingScreen ?? null,
            camera: info.sharingCamera ?? null,
          });
          break;
        }
        case "mic": {
          if (!info.room) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          const nextMic = Boolean(msg.mic);
          // Same open/close-a-segment reasoning as "sharing" above.
          if (nextMic) {
            if (info.micOnAt === undefined) info.micOnAt = Date.now();
          } else if (info.micOnAt !== undefined) {
            const micSeconds = secondsSince(info.micOnAt, Date.now());
            info.micOnAt = undefined;
            if (info.accountId && micSeconds > 0) {
              void addAccountCallStats(info.accountId, { micSeconds });
            }
          }
          info.mic = nextMic;
          broadcastToRoom(info.room, { type: "peer-mic", id: info.id, mic: info.mic });
          break;
        }
        // Adding, removing and steering a room video source (see
        // RoomVideoSource). All three are ordinary room broadcasts — the
        // server owns the record so that a latecomer's "room-state" already
        // describes what everyone else is watching, and so the playback
        // position everyone extrapolates from comes off one clock.
        case "video-source-add": {
          if (!info.room || !info.name) return;
          if (!(await consumeRateLimit(wsVideoSourceLimiter, info.rateLimitKey, "video-source"))) return;
          const roomInfo = rooms.get(info.room);
          if (!roomInfo) return;
          if (roomInfo.videoSources.length >= MAX_ROOM_VIDEO_SOURCES) {
            send(socket, {
              type: "error",
              message: `Máximo de ${MAX_ROOM_VIDEO_SOURCES} fontes de vídeo por sala.`,
            });
            return;
          }
          const kind = msg.kind === "twitch" ? "twitch" : "youtube";
          const rawUrl = typeof msg.url === "string" ? msg.url : "";
          const videoId = kind === "twitch" ? parseTwitchChannel(rawUrl) : parseYouTubeVideoId(rawUrl);
          if (!videoId) {
            send(socket, {
              type: "error",
              message: kind === "twitch" ? "Link da Twitch inválido." : "Link do YouTube inválido.",
            });
            return;
          }
          const source: RoomVideoSource = {
            id: genId(),
            kind,
            videoId,
            addedById: stableUserId(info),
            addedByName: info.name,
            controlMode: msg.controlMode === "anyone" ? "anyone" : "owner",
            // Starts playing: someone who just added a video meant to watch
            // it, and a source that arrives paused at 0 makes everyone wait
            // for whoever added it to press play again.
            playing: true,
            positionSeconds: 0,
            playbackRate: 1,
            updatedAt: Date.now(),
          };
          roomInfo.videoSources.push(source);
          broadcastToRoom(info.room, { type: "video-source-added", source });
          break;
        }
        // Only whoever added it may take it off everyone's screen, same as
        // only they may steer it. Everyone else can leave a video without
        // ending it for the room — that's a purely local thing the client
        // does on its own (see WatchRoom's hiddenVideoSourceIds), and never
        // reaches this server. A source outliving its adder is handled by
        // leaveRoom below, not by letting anyone remove anything.
        case "video-source-remove": {
          if (!info.room) return;
          if (!(await consumeRateLimit(wsVideoSourceLimiter, info.rateLimitKey, "video-source"))) return;
          const roomInfo = rooms.get(info.room);
          if (!roomInfo) return;
          const id = typeof msg.id === "string" ? msg.id : "";
          const target = roomInfo.videoSources.find((v) => v.id === id);
          if (!target || target.addedById !== stableUserId(info)) return;
          roomInfo.videoSources = roomInfo.videoSources.filter((v) => v.id !== id);
          broadcastToRoom(info.room, { type: "video-source-removed", id });
          break;
        }
        // Play/pause/seek, from whoever touched their player. Dropped
        // silently when over budget, same as the other transient toggles:
        // the next real state change re-syncs everyone anyway, and the
        // periodic drift correction on the client never sends anything.
        case "video-source-state": {
          if (!info.room) return;
          if (!(await consumeRateLimit(wsVideoSourceLimiter, info.rateLimitKey, "video-source"))) return;
          const roomInfo = rooms.get(info.room);
          if (!roomInfo) return;
          const id = typeof msg.id === "string" ? msg.id : "";
          const source = roomInfo.videoSources.find((v) => v.id === id);
          if (!source) return;
          // Whoever added it drives — or, if they set controlMode to
          // "anyone" when adding it, anyone in the room does. Enforced here
          // and not just in the UI: everyone else's player is following this
          // record, so a client that decided to send anyway would be
          // steering other people's screens. Silently ignored rather than
          // answered with an error — a client honoring canControl is already
          // blocked from reaching this, so anything arriving here that isn't
          // covered by controlMode is not an honest mistake.
          if (source.controlMode !== "anyone" && source.addedById !== stableUserId(info)) return;
          const rawPosition = typeof msg.positionSeconds === "number" ? msg.positionSeconds : NaN;
          source.positionSeconds =
            Number.isFinite(rawPosition) && rawPosition > 0 ? Math.min(rawPosition, 24 * 60 * 60) : 0;
          source.playing = Boolean(msg.playing);
          // Merged rather than overwritten: a client that doesn't know about
          // speed (an older tab still open through a deploy) sends none, and
          // its play/pause must not silently reset the room to 1x.
          if (hasOwn(msg, "playbackRate")) {
            source.playbackRate = normalizePlaybackRate(msg.playbackRate);
          }
          source.updatedAt = Date.now();
          broadcastToRoom(info.room, {
            type: "video-source-state",
            id: source.id,
            playing: source.playing,
            positionSeconds: source.positionSeconds,
            playbackRate: source.playbackRate,
            updatedAt: source.updatedAt,
          });
          break;
        }
        // Clock synchronization, for the shared video sources. Their
        // playback position is extrapolated from a server timestamp (see
        // RoomVideoSource.updatedAt), so a client whose clock is a few
        // seconds off watches a few seconds off — the one error the drift
        // correction can never fix, because every client is confidently
        // wrong by its own constant. This is the classic NTP exchange: the
        // client stamps t0, this stamps its own now, and the client works
        // out the offset from the round trip.
        case "time-sync": {
          send(socket, {
            type: "time-sync",
            t0: typeof msg.t0 === "number" ? msg.t0 : 0,
            serverTime: Date.now(),
          });
          break;
        }
        case "typing": {
          if (!info.room) return;
          // Purely relayed, no server-side state kept — the client is what
          // decides when to (re)send true/false (see signalingClient.ts's
          // setTyping); this only needs to forward it, and drops silently on
          // excess like the other transient toggles above rather than
          // surfacing an error for something this ephemeral.
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          broadcastToRoom(
            info.room,
            { type: "peer-typing", id: info.id, typing: Boolean(msg.typing) },
            socket
          );
          break;
        }
        case "chat": {
          if (!info.room) return;
          // Only rate-limited case besides "register"/"join" that gives the
          // client explicit feedback — chat is a deliberate, one-off user
          // action, so silently eating a message (like "signal" below does)
          // would look like a bug rather than a rate limit; reusing
          // "chat-blocked" means the frontend already has UI for this.
          if (!(await consumeRateLimit(wsChatLimiter, info.rateLimitKey, "chat"))) {
            send(socket, {
              type: "chat-blocked",
              message: "Você está enviando mensagens rápido demais. Aguarde um instante.",
            });
            recordRateLimitViolation(info);
            return;
          }
          const isGif = msg.kind === "gif";
          let chatMessage: ChatMessage;
          if (isGif) {
            const url = typeof msg.url === "string" ? msg.url.trim() : "";
            if (!isValidGifUrl(url)) return;
            chatMessage = {
              id: genId(),
              from: info.id,
              name: info.name as string,
              isGuest: !info.accountId,
              flags: info.flags ?? [],
              kind: "gif",
              text: "",
              url,
              ts: Date.now(),
            };
          } else {
            const text = typeof msg.text === "string" ? msg.text.trim().slice(0, CHAT_MAX_LEN) : "";
            if (!isValidChatText(text)) return;
            if (findBannedWord(text)) {
              chatMessagesBlockedTotal.inc();
              send(socket, {
                type: "chat-blocked",
                message: "Sua mensagem contém uma palavra não permitida.",
              });
              return;
            }
            chatMessage = {
              id: genId(),
              from: info.id,
              name: info.name as string,
              isGuest: !info.accountId,
              flags: info.flags ?? [],
              text,
              ts: Date.now(),
            };
          }
          const roomInfo = rooms.get(info.room);
          if (!roomInfo) return;
          roomInfo.messages.push(chatMessage);
          if (roomInfo.messages.length > ROOM_CHAT_HISTORY_LIMIT) {
            roomInfo.messages.splice(0, roomInfo.messages.length - ROOM_CHAT_HISTORY_LIMIT);
          }
          savePersistedChat(info.room, roomInfo.messages);
          broadcastToRoom(info.room, { type: "chat-message", ...chatMessage });
          break;
        }
        case "signal": {
          if (!info.room) return;
          // Dropped silently, not surfaced to the client: this limiter is
          // sized well above what a real mesh negotiation ever needs (see
          // wsSignalLimiter in rateLimiter.ts), so hitting it means
          // something is already wrong — no UI message would help, and
          // WebRTC's own negotiation/retry logic tolerates an occasional
          // missed signal better than a user-facing error would.
          if (!(await consumeRateLimit(wsSignalLimiter, info.rateLimitKey, "signal"))) return;
          const targetId = typeof msg.to === "string" ? msg.to : "";
          if (!targetId) return;
          const dataKind =
            msg.data && typeof msg.data === "object" && "kind" in msg.data
              ? String((msg.data as { kind: unknown }).kind)
              : "unknown";
          signalsRelayedTotal.inc({ kind: dataKind });
          deliverOrQueueSignal(info.room, targetId, info.id, msg.data);
          break;
        }
        // Real engagement signals for the admin panel's live announcement
        // stats (see announcementStats above) — sent by AnnouncementBanner.tsx
        // only for the announcement it's actually displaying, so a stale/
        // mismatched id here (an edit or a brand new announcement racing the
        // client's report) is simply ignored rather than corrupting the
        // current bucket.
        case "announcement-view": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!currentAnnouncement || !announcementStats || id !== currentAnnouncement.id) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "announcement-view"))) return;
          announcementStats.viewerIds.add(info.id);
          break;
        }
        case "announcement-button-click": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!currentAnnouncement || !announcementStats || id !== currentAnnouncement.id) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "announcement-click"))) return;
          announcementStats.buttonClicks += 1;
          break;
        }
        case "announcement-x-click": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!currentAnnouncement || !announcementStats || id !== currentAnnouncement.id) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "announcement-x-click"))) return;
          announcementStats.xClicks += 1;
          break;
        }
        // Same reasoning as the announcement-* cases above, for the sidebar
        // partner-ad slot (see components/PartnerCard.tsx) — only recorded
        // for an id that's still a real partner (expired ones stay in
        // partnerConfig.partners, see its doc comment, so this still counts
        // a view/click on one that expired moments ago while it was showing).
        // One impression, i.e. one serve. Deliberately *not* deduped by
        // connection: the slot refills every few minutes (see PartnerCard's
        // rotation), and each refill that lands on this ad is another time it
        // was actually put in front of someone. Deduping here is what the
        // "partner-session-view" case below is for, and folding the two
        // together is what made a single number have to mean both.
        case "partner-view": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!partnerConfig.partners.some((p) => p.id === id)) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "partner-view"))) return;
          getPartnerStats(id).views += 1;
          // Not awaited: it only writes through to Redis/disk (and logs its
          // own failures), and nothing in this handler's reply depends on
          // it — no reason to hold up the socket for the roundtrip.
          void incrementPersistedPartnerStats(id, { views: 1 });
          // Same, for the distinct-people set. Idempotent, so re-sending it
          // on every serve costs a set write and changes nothing.
          void recordPersistedPartnerViewer(id, partnerViewerKey(info));
          break;
        }
        // Reach: one per connection per ad, which is what "views" alone
        // counted before the slot rotated. The client sends this separately
        // from the impression above rather than as a flag on it, so neither
        // count has to be inferred from the other.
        case "partner-session-view": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!partnerConfig.partners.some((p) => p.id === id)) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "partner-session-view"))) {
            return;
          }
          const entry = getPartnerStats(id);
          // The dedupe happens before the counter moves, so a repeat from
          // the same connection never reaches the persisted total either —
          // see PartnerStatsEntry.
          if (entry.viewerIds.has(info.id)) break;
          entry.viewerIds.add(info.id);
          entry.sessionViews += 1;
          void incrementPersistedPartnerStats(id, { sessionViews: 1 });
          break;
        }
        // The same CTA exists in two places (the sidebar card and the
        // reward-video popup), and each keeps its own counter. `source` says
        // which — anything other than "video", including its absence from an
        // older client, counts as the card, which is where the button lived
        // before the popup had one.
        case "partner-click": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!partnerConfig.partners.some((p) => p.id === id)) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "partner-click"))) return;
          const fromVideo = msg.source === "video";
          if (fromVideo) {
            getPartnerStats(id).clicksByVideo += 1;
            void incrementPersistedPartnerStats(id, { clicksByVideo: 1 });
          } else {
            getPartnerStats(id).clicks += 1;
            void incrementPersistedPartnerStats(id, { clicks: 1 });
          }
          break;
        }
        // Watch-to-earn funnel (see PartnerRewardModal.tsx) — sent when the
        // "Ganhar X Pontos" popup opens. Gated on the ad actually having a
        // reward configured (not just existing), same reasoning as the
        // "-completed" case below: only real reward ads should ever move
        // these counters, so an id for an ad with no video can't inflate a
        // number the admin panel can't otherwise explain.
        case "partner-reward-video-open": {
          const id = typeof msg.id === "string" ? msg.id : "";
          const partner = partnerConfig.partners.find((p) => p.id === id);
          if (!partner || !partner.rewardVideoUrl || !partner.rewardPoints) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "partner-reward-video-open"))) {
            return;
          }
          getPartnerStats(id).rewardVideoOpens += 1;
          void incrementPersistedPartnerStats(id, { rewardVideoOpens: 1 });
          break;
        }
        // Sent when the video reaches `ended` with enough of it genuinely
        // watched to unlock "Receber Recompensa" (see the modal's own
        // REQUIRED_WATCH_FRACTION check) — *not* the same event as actually
        // claiming the reward. Someone can watch the whole thing and still
        // never click claim (or not have an account to claim with at all),
        // which is exactly the gap this number and rewardClaims together are
        // meant to show the admin panel.
        case "partner-reward-video-completed": {
          const id = typeof msg.id === "string" ? msg.id : "";
          const partner = partnerConfig.partners.find((p) => p.id === id);
          if (!partner || !partner.rewardVideoUrl || !partner.rewardPoints) return;
          if (
            !(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "partner-reward-video-completed"))
          ) {
            return;
          }
          getPartnerStats(id).rewardVideoCompletions += 1;
          void incrementPersistedPartnerStats(id, { rewardVideoCompletions: 1 });
          break;
        }
        default:
          break;
      }
    });

    socket.on("close", () => {
      wsDisconnectionsTotal.inc();
      // leaveRoom guards its own roomInfo.names cleanup against a
      // stale/superseded session's delayed close event wiping out a newer
      // reconnect that already took over this name/id (it only ever deletes
      // its *own* socket's reservation).
      if (info.room) leaveRoom(info);
      if (clientsById.get(info.id) === info) {
        clientsById.delete(info.id);
        pendingSignals.delete(info.id);
      }
      clients.delete(socket);
    });
  });
}
