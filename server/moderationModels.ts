import { Schema, model } from "mongoose";

export interface IpBan {
  ip: string;
  reason: string;
  createdAt: number;
  // null means permanent — never auto-expires.
  expiresAt: number | null;
}

const ipBanSchema = new Schema<IpBan>(
  {
    ip: { type: String, required: true, unique: true },
    reason: { type: String, required: true, default: "" },
    createdAt: { type: Number, required: true },
    expiresAt: { type: Number, default: null },
  },
  // No timestamps/versionKey — createdAt is our own app-level field (used
  // for sorting/display), not Mongoose's, and there's nothing here that
  // needs optimistic-concurrency version tracking.
  { versionKey: false }
);

export const IpBanModel = model<IpBan>("IpBan", ipBanSchema, "ip_bans");

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
