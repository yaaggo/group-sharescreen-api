import { Schema, model } from "mongoose";

// What a ban is keyed on. "ip" is the original (and still the only one the
// auto-ban system issues); the other two exist because an IP is the weakest
// of the three to ban on — it's shared by everyone behind a CGNAT and
// changes on its own for anyone on mobile data.
export type BanSubject = "ip" | "account" | "fingerprint";

export interface BanDoc {
  // Absent on every document written before this field existed — all of
  // those are IP bans, which is why the default below is "ip" rather than
  // required.
  subject?: BanSubject;
  // The banned value itself: an IP, an account id, or a browser
  // fingerprint, depending on `subject`. The field is *named* `ip` purely
  // because that's what it was called when IPs were the only thing bannable
  // — renaming it would orphan every persisted ban, and the collection is
  // called ip_bans for the same reason.
  ip: string;
  reason: string;
  createdAt: number;
  // null means permanent — never auto-expires.
  expiresAt: number | null;
}

const banSchema = new Schema<BanDoc>(
  {
    subject: { type: String, default: "ip" },
    // No longer unique on its own: uniqueness is per (subject, value) now,
    // via the compound index below. A database created before this change
    // still carries the old single-field unique index, which is harmless —
    // the three subjects' value spaces don't overlap in practice (an IP is
    // never a UUID or a hex hash), so it can only ever reject a duplicate
    // that the compound index would reject too.
    ip: { type: String, required: true },
    reason: { type: String, required: true, default: "" },
    createdAt: { type: Number, required: true },
    expiresAt: { type: Number, default: null },
  },
  // No timestamps/versionKey — createdAt is our own app-level field (used
  // for sorting/display), not Mongoose's, and there's nothing here that
  // needs optimistic-concurrency version tracking.
  { versionKey: false }
);

banSchema.index({ subject: 1, ip: 1 }, { unique: true });

export const IpBanModel = model<BanDoc>("IpBan", banSchema, "ip_bans");

// A single document (fixed _id) holding the whole banned-words list, mirroring
// setBannedWords' "replace the whole list at once" shape in moderationStore.ts.
interface ModerationConfigDoc {
  _id: string;
  bannedWords: string[];
  // Master switch for the auto-ban system (see signaling.ts's
  // recordRateLimitViolation) — an admin-facing kill switch for when it's
  // doing more harm than good (e.g. banning real users during a slowdown
  // that makes them look like they're spamming retries), without needing a
  // redeploy to turn it back off.
  antiSpamEnabled: boolean;
}

const moderationConfigSchema = new Schema<ModerationConfigDoc>(
  {
    _id: { type: String },
    bannedWords: { type: [String], default: [] },
    antiSpamEnabled: { type: Boolean, default: true },
  },
  { versionKey: false }
);

export const ModerationConfigModel = model<ModerationConfigDoc>(
  "ModerationConfig",
  moderationConfigSchema,
  "moderation_config"
);
