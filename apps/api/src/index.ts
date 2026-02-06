import { AppError } from "./errors";
import { BookingDurableObject } from "./booking-do";
import {
  isValidBookingRef,
  isValidTWId,
  normalizeBookingRef,
  normalizeTWId,
} from "./validators";

type Env = {
  DB: D1Database;
  BOOKING_DO: DurableObjectNamespace;
  APP_ENV?: string;
  PUBLIC_BASE_URL?: string;
  GOOGLE_CLIENT_ID?: string;
  APPLE_CLIENT_ID?: string;
  LINE_LOGIN_CHANNEL_ID?: string;
  EMAIL_PROVIDER?: string;
  RESEND_API_KEY?: string;
  RESEND_FROM?: string;
  SENDGRID_API_KEY?: string;
  SENDGRID_FROM?: string;
  POSTMARK_API_KEY?: string;
  POSTMARK_FROM?: string;
  LINE_CHANNEL_ACCESS_TOKEN?: string;
  TURNSTILE_SECRET?: string;
};

type BookingRpc = {
  createHold: (input: {
    slotId: string;
    patientProvisionalKey?: string;
    now?: number;
  }) => Promise<{ holdToken: string; expiresAt: number }>;
  confirmBooking: (input: {
    holdToken: string;
    nationalId: string;
    dob: string;
    displayName?: string;
    phone?: string;
    email?: string;
    source?: string;
    idempotencyKey?: string;
    now?: number;
  }) => Promise<{
    appointmentId: string;
    bookingRef: string;
    queueNo: number;
    status: string;
    serviceDateLocal: string;
  }>;
  cancelBooking: (input: { appointmentId: string; now?: number }) => Promise<{
    status: string;
    cancelledAt: number;
  }>;
  bookSlotForPatient: (input: {
    slotId: string;
    patientId: string;
    source?: string;
    now?: number;
  }) => Promise<{
    appointmentId: string;
    bookingRef: string;
    queueNo: number;
    status: string;
    serviceDateLocal: string;
  }>;
};

function jsonResponse(data: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,authorization,x-idempotency-key,x-device-id,x-staff-email",
      ...(init.headers ?? {}),
    },
    ...init,
  });
}

function csvResponse(data: string, filename: string) {
  return new Response(data, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="${filename}"`,
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,authorization,x-idempotency-key,x-device-id,x-staff-email",
    },
  });
}

function calendarResponse(data: string, filename: string) {
  return new Response(data, {
    headers: {
      "content-type": "text/calendar; charset=utf-8",
      "content-disposition": `attachment; filename="${filename}"`,
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,authorization,x-idempotency-key,x-device-id,x-staff-email",
    },
  });
}


function errorResponse(error: unknown, fallbackStatus = 500) {
  if (error instanceof AppError) {
    return jsonResponse(
      {
        error: {
          code: error.code,
          message: error.message,
          fields: error.details ?? undefined,
        },
      },
      { status: error.status }
    );
  }

  return jsonResponse(
    {
      error: {
        code: "internal_error",
        message: "Unexpected error",
      },
    },
    { status: fallbackStatus }
  );
}

async function parseJson<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    throw new AppError("validation_error", 400, { body: "invalid_json" });
  }
}

function getClientIp(request: Request): string | null {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() || null;
  }
  return request.headers.get("cf-connecting-ip") || null;
}

async function hashValue(value: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const JWKS_CACHE_MS = 60 * 60 * 1000;
const EMAIL_VERIFICATION_TTL_MS = 10 * 60 * 1000;
const EMAIL_VERIFICATION_COOLDOWN_MS = 60 * 1000;
const EMAIL_VERIFICATION_MAX_ATTEMPTS = 5;
const EMAIL_VERIFICATION_RATE_LIMIT = { limit: 5, windowMs: 60 * 60 * 1000 };

type AuthProvider = "google" | "apple" | "line";

type VerifiedProfile = {
  provider: AuthProvider;
  sub: string;
  email?: string;
  name?: string;
};

type JwksCacheEntry = {
  keys: JsonWebKey[];
  expiresAt: number;
};

const jwksCache = new Map<AuthProvider, JwksCacheEntry>();

function base64urlDecode(input: string): Uint8Array {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const base64 = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeJwtPart<T>(part: string): T {
  const bytes = base64urlDecode(part);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as T;
}

function getProviderConfig(provider: AuthProvider, env: Env) {
  switch (provider) {
    case "google":
      return {
        jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
        issuer: ["https://accounts.google.com", "accounts.google.com"],
        audience: env.GOOGLE_CLIENT_ID,
      };
    case "apple":
      return {
        jwksUrl: "https://appleid.apple.com/auth/keys",
        issuer: ["https://appleid.apple.com"],
        audience: env.APPLE_CLIENT_ID,
      };
    case "line":
      return {
        jwksUrl: "https://api.line.me/oauth2/v2.1/certs",
        issuer: ["https://access.line.me"],
        audience: env.LINE_LOGIN_CHANNEL_ID,
      };
    default:
      throw new AppError("validation_error", 400, { provider: "invalid" });
  }
}

async function getJwks(provider: AuthProvider, env: Env): Promise<JsonWebKey[]> {
  const cached = jwksCache.get(provider);
  const now = Date.now();
  if (cached && cached.expiresAt > now) {
    return cached.keys;
  }

  const { jwksUrl } = getProviderConfig(provider, env);
  const response = await fetch(jwksUrl);
  if (!response.ok) {
    throw new AppError("oauth_jwks_failed", 502);
  }
  const payload = (await response.json()) as { keys?: JsonWebKey[] };
  const keys = payload.keys ?? [];
  jwksCache.set(provider, { keys, expiresAt: now + JWKS_CACHE_MS });
  return keys;
}

async function verifyIdToken(provider: AuthProvider, idToken: string, env: Env): Promise<VerifiedProfile> {
  const [headerPart, payloadPart, signaturePart] = idToken.split(".");
  if (!headerPart || !payloadPart || !signaturePart) {
    throw new AppError("token_invalid", 401);
  }

  const header = decodeJwtPart<{ kid?: string; alg?: string }>(headerPart);
  const payload = decodeJwtPart<{
    sub?: string;
    email?: string;
    name?: string;
    aud?: string;
    iss?: string;
    exp?: number;
  }>(payloadPart);

  if (!header.kid || header.alg !== "RS256") {
    throw new AppError("token_invalid", 401, { header: "unsupported" });
  }
  if (!payload.sub) {
    throw new AppError("token_invalid", 401, { sub: "missing" });
  }
  if (payload.exp && payload.exp * 1000 < Date.now()) {
    throw new AppError("token_expired", 401);
  }

  const config = getProviderConfig(provider, env);
  if (config.audience) {
    const aud = payload.aud;
    const audMatches = Array.isArray(aud)
      ? aud.includes(config.audience)
      : aud === config.audience;
    if (!audMatches) {
      throw new AppError("token_invalid", 401, { aud: "mismatch" });
    }
  }
  if (payload.iss && !config.issuer.includes(payload.iss)) {
    throw new AppError("token_invalid", 401, { iss: "mismatch" });
  }

  const keys = await getJwks(provider, env);
  const jwk = keys.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new AppError("token_invalid", 401, { kid: "unknown" });
  }

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const data = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signature = base64urlDecode(signaturePart);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, data);
  if (!valid) {
    throw new AppError("token_invalid", 401);
  }

  return {
    provider,
    sub: payload.sub,
    email: payload.email,
    name: payload.name,
  };
}

async function checkRateLimit(env: Env, key: string, limit: number, windowMs: number) {
  if (env.APP_ENV === "dev" || env.APP_ENV === "test") return;
  const now = Date.now();
  await env.DB.exec("BEGIN");
  try {
    const row = await env.DB.prepare(
      `SELECT window_start, count FROM rate_limit WHERE key = ?`
    ).bind(key).first();

    if (!row || now - Number(row.window_start) >= windowMs) {
      await env.DB.prepare(
        `INSERT OR REPLACE INTO rate_limit (key, window_start, count)
         VALUES (?, ?, 1)`
      ).bind(key, now).run();
      await env.DB.exec("COMMIT");
      return;
    }

    const count = Number(row.count);
    if (count >= limit) {
      await env.DB.exec("ROLLBACK");
      throw new AppError("rate_limited", 429);
    }

    await env.DB.prepare(
      `UPDATE rate_limit SET count = count + 1 WHERE key = ?`
    ).bind(key).run();
    await env.DB.exec("COMMIT");
  } catch (error) {
    await env.DB.exec("ROLLBACK");
    throw error;
  }
}

async function verifyTurnstile(request: Request, env: Env, token?: string) {
  const secret = env.TURNSTILE_SECRET;
  if (!secret) return;
  if (!token) {
    throw new AppError("turnstile_required", 400, { turnstile_token: "required" });
  }

  const body = new URLSearchParams();
  body.set("secret", secret);
  body.set("response", token);
  const ip = getClientIp(request);
  if (ip) body.set("remoteip", ip);

  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
  });
  if (!response.ok) {
    throw new AppError("turnstile_failed", 502);
  }
  const result = (await response.json()) as { success?: boolean; "error-codes"?: string[] };
  if (!result.success) {
    throw new AppError("turnstile_failed", 403, { errors: result["error-codes"] ?? [] });
  }
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function isValidEmail(value: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

function maskNationalId(value?: string | null): string | null {
  if (!value) return null;
  const normalized = normalizeTWId(value);
  if (!normalized) return null;
  if (normalized.length <= 4) return normalized;
  const prefix = normalized.slice(0, 1);
  const suffix = normalized.slice(-4);
  return `${prefix}${"*".repeat(Math.max(normalized.length - 5, 0))}${suffix}`;
}

function generateVerificationCode(): string {
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return String(buffer[0] % 1000000).padStart(6, "0");
}

function resolveEmailVerificationPurpose(purpose?: string | null): string {
  const resolved = (purpose || "booking").trim();
  if (resolved !== "booking") {
    throw new AppError("validation_error", 400, { purpose: "invalid" });
  }
  return resolved;
}

type EmailVerificationInput = {
  id?: string | null;
  code?: string | null;
  email?: string | null;
  purpose: string;
  now: number;
  consume: boolean;
};

async function validateEmailVerification(env: Env, input: EmailVerificationInput) {
  const id = input.id?.trim() || "";
  const code = input.code?.trim() || "";
  const emailRaw = input.email?.trim() || "";
  const missing: Record<string, string> = {};
  if (!id) missing.email_verification_id = "required";
  if (!code) missing.email_verification_code = "required";
  if (!emailRaw) missing.email = "required";
  if (Object.keys(missing).length) {
    throw new AppError("email_verification_required", 400, missing);
  }

  const email = normalizeEmail(emailRaw);
  if (!isValidEmail(email)) {
    throw new AppError("validation_error", 400, { email: "invalid" });
  }

  const row = await env.DB.prepare(
    `SELECT id, email, code_hash, purpose, expires_at, used_at, attempt_count
     FROM email_verification WHERE id = ?`
  ).bind(id).first();
  if (!row) {
    throw new AppError("email_verification_invalid", 400, { email_verification_id: "not_found" });
  }

  const storedEmail = normalizeEmail(row.email as string);
  if (storedEmail !== email) {
    throw new AppError("email_verification_mismatch", 400);
  }

  if ((row.purpose as string) !== input.purpose) {
    throw new AppError("email_verification_invalid", 400, { purpose: "mismatch" });
  }

  const usedAt = row.used_at ? Number(row.used_at) : null;
  if (usedAt) {
    throw new AppError("email_verification_used", 400);
  }

  const expiresAt = Number(row.expires_at);
  if (expiresAt <= input.now) {
    throw new AppError("email_verification_expired", 400);
  }

  const attempts = Number(row.attempt_count ?? 0);
  if (attempts >= EMAIL_VERIFICATION_MAX_ATTEMPTS) {
    throw new AppError("email_verification_locked", 429);
  }

  const codeHash = await hashValue(code);
  if (codeHash !== (row.code_hash as string)) {
    await env.DB.prepare(
      `UPDATE email_verification SET attempt_count = attempt_count + 1 WHERE id = ?`
    ).bind(id).run();
    throw new AppError("email_verification_invalid", 400);
  }

  if (input.consume) {
    await env.DB.prepare(
      `UPDATE email_verification SET used_at = ? WHERE id = ?`
    ).bind(input.now, id).run();
  }
}

async function verifyTurnstileOrEmail(
  request: Request,
  env: Env,
  input: {
    turnstileToken?: string;
    email?: string;
    emailVerificationId?: string;
    emailVerificationCode?: string;
    purpose: string;
    now: number;
  }
) {
  const hasEmailVerification = Boolean(
    input.email && input.emailVerificationId && input.emailVerificationCode
  );
  if (hasEmailVerification) {
    await validateEmailVerification(env, {
      id: input.emailVerificationId,
      code: input.emailVerificationCode,
      email: input.email,
      purpose: input.purpose,
      now: input.now,
      consume: true,
    });
    return;
  }

  const secret = env.TURNSTILE_SECRET;
  if (!secret) return;
  await verifyTurnstile(request, env, input.turnstileToken);
}

async function requestEmailVerification(request: Request, env: Env) {
  const body = await parseJson<{ email?: string; purpose?: string }>(request);
  const emailRaw = body.email?.trim() || "";
  if (!emailRaw) {
    throw new AppError("validation_error", 400, { email: "required" });
  }
  const email = normalizeEmail(emailRaw);
  if (!isValidEmail(email)) {
    throw new AppError("validation_error", 400, { email: "invalid" });
  }
  const purpose = resolveEmailVerificationPurpose(body.purpose);
  const now = Date.now();
  const ip = getClientIp(request) ?? "unknown";
  const emailHash = await hashValue(email);
  await checkRateLimit(
    env,
    `rl:email_verification:${ip}:${emailHash}`,
    EMAIL_VERIFICATION_RATE_LIMIT.limit,
    EMAIL_VERIFICATION_RATE_LIMIT.windowMs
  );

  const recent = await env.DB.prepare(
    `SELECT created_at
     FROM email_verification
     WHERE email = ? AND purpose = ?
     ORDER BY created_at DESC
     LIMIT 1`
  ).bind(email, purpose).first();
  if (recent && now - Number(recent.created_at) < EMAIL_VERIFICATION_COOLDOWN_MS) {
    throw new AppError("email_verification_too_soon", 429);
  }

  await env.DB.prepare(
    `UPDATE email_verification
     SET used_at = ?
     WHERE email = ? AND purpose = ? AND used_at IS NULL`
  ).bind(now, email, purpose).run();

  const code = generateVerificationCode();
  const codeHash = await hashValue(code);
  const id = crypto.randomUUID();
  const expiresAt = now + EMAIL_VERIFICATION_TTL_MS;

  await env.DB.prepare(
    `INSERT INTO email_verification
      (id, email, code_hash, purpose, created_at, expires_at, used_at, attempt_count)
     VALUES (?, ?, ?, ?, ?, ?, NULL, 0)`
  ).bind(id, email, codeHash, purpose, now, expiresAt).run();

  const sendEnabled = env.APP_ENV !== "dev" && env.APP_ENV !== "test";
  if (sendEnabled) {
    await sendEmail(
      env,
      email,
      "\u9a57\u8b49\u78bc\u901a\u77e5",
      `\u60a8\u7684\u9a57\u8b49\u78bc\u662f ${code}\uff0c\u6709\u6548\u6642\u9593 10 \u5206\u9418\u3002`
    );
  }

  const data: Record<string, unknown> = { verification_id: id, expires_at: expiresAt };
  if (!sendEnabled) {
    data.debug_code = code;
  }
  return jsonResponse({ data });
}

async function verifyEmailVerification(request: Request, env: Env) {
  const body = await parseJson<{
    verification_id?: string;
    code?: string;
    email?: string;
    purpose?: string;
  }>(request);
  const purpose = resolveEmailVerificationPurpose(body.purpose);
  await validateEmailVerification(env, {
    id: body.verification_id,
    code: body.code,
    email: body.email,
    purpose,
    now: Date.now(),
    consume: false,
  });
  return jsonResponse({ data: { valid: true } });
}

type AuditInput = {
  orgId: string;
  clinicId?: string | null;
  actorType: "staff" | "patient" | "system";
  actorId?: string | null;
  action: string;
  entityTable: string;
  entityId: string;
  before?: unknown;
  after?: unknown;
  requestId?: string | null;
};

function getRequestId(request: Request): string | null {
  return (
    request.headers.get("x-request-id") ||
    request.headers.get("cf-ray") ||
    null
  );
}

function toJson(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return JSON.stringify(value);
}

async function writeAuditLog(env: Env, input: AuditInput) {
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO audit_log
      (id, org_id, clinic_id, actor_type, actor_id, action, entity_table, entity_id,
       before_json, after_json, request_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    crypto.randomUUID(),
    input.orgId,
    input.clinicId ?? null,
    input.actorType,
    input.actorId ?? null,
    input.action,
    input.entityTable,
    input.entityId,
    toJson(input.before),
    toJson(input.after),
    input.requestId ?? null,
    now
  ).run();
}

async function getProviderOrgClinic(env: Env, providerId: string) {
  const row = await env.DB.prepare(
    `SELECT org_id, clinic_id FROM provider WHERE id = ?`
  ).bind(providerId).first();
  if (!row) return null;
  return { orgId: row.org_id as string, clinicId: row.clinic_id as string };
}

async function getClinicOrg(env: Env, clinicId: string) {
  const row = await env.DB.prepare(
    `SELECT org_id FROM clinic WHERE id = ?`
  ).bind(clinicId).first();
  if (!row) return null;
  return { orgId: row.org_id as string, clinicId };
}

async function getAppointmentOrgClinic(env: Env, appointmentId: string) {
  const row = await env.DB.prepare(
    `SELECT org_id, clinic_id FROM appointment WHERE id = ?`
  ).bind(appointmentId).first();
  if (!row) return null;
  return { orgId: row.org_id as string, clinicId: row.clinic_id as string };
}

async function getPatientOrg(env: Env, patientId: string) {
  const row = await env.DB.prepare(
    `SELECT org_id FROM patient WHERE id = ?`
  ).bind(patientId).first();
  if (!row) return null;
  return { orgId: row.org_id as string };
}

async function ensureRole(env: Env, roleName: string, scope = "org"): Promise<string> {
  const existing = await env.DB.prepare(
    `SELECT id FROM role WHERE name = ?`
  ).bind(roleName).first();
  if (existing) {
    return existing.id as string;
  }
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO role (id, scope, name)
     VALUES (?, ?, ?)`
  ).bind(id, scope, roleName).run();
  return id;
}

async function setStaffRoles(env: Env, staffId: string, roleNames: string[]) {
  await env.DB.prepare(
    `DELETE FROM staff_user_role WHERE staff_user_id = ?`
  ).bind(staffId).run();

  for (const roleName of roleNames) {
    const roleId = await ensureRole(env, roleName.trim());
    await env.DB.prepare(
      `INSERT OR IGNORE INTO staff_user_role (staff_user_id, role_id)
       VALUES (?, ?)`
    ).bind(staffId, roleId).run();
  }
}

const ADMIN_ROLE_NAMES = new Set(["system_admin", "group_admin", "clinic_admin"]);

type StaffContext = {
  staffId: string | null;
  orgId?: string | null;
  clinicId?: string | null;
  roles: string[];
};

async function getStaffContext(request: Request, env: Env): Promise<StaffContext> {
  if (env.APP_ENV === "dev" || env.APP_ENV === "test") {
    return { staffId: null, roles: ["dev_admin"] };
  }

  const email =
    request.headers.get("cf-access-authenticated-user-email") ||
    request.headers.get("x-staff-email");

  if (!email) {
    throw new AppError("unauthorized", 401, { access: "missing_email" });
  }

  const staff = await env.DB.prepare(
    `SELECT id, org_id, clinic_id, is_active FROM staff_user WHERE email = ?`
  ).bind(email).first();

  if (!staff || Number(staff.is_active) !== 1) {
    throw new AppError("forbidden", 403, { staff: "inactive_or_missing" });
  }

  const rolesResult = await env.DB.prepare(
    `SELECT role.name
     FROM staff_user_role
     JOIN role ON role.id = staff_user_role.role_id
     WHERE staff_user_role.staff_user_id = ?`
  ).bind(staff.id).all();

  const roles = (rolesResult.results ?? []).map((row) => row.name as string);

  return {
    staffId: staff.id as string,
    orgId: staff.org_id as string,
    clinicId: staff.clinic_id as string | null,
    roles,
  };
}

function getPatientToken(request: Request): string | null {
  const authHeader = request.headers.get("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  return request.headers.get("x-patient-session");
}

async function createPatientSession(env: Env, input: {
  patientId: string;
  provider: AuthProvider;
  providerSub: string;
  boundStatus: string;
}): Promise<string> {
  const token = crypto.randomUUID();
  const tokenHash = await hashValue(token);
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  await env.DB.prepare(
    `INSERT INTO patient_session
      (id, token_hash, patient_id, provider, provider_sub, bound_status, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    crypto.randomUUID(),
    tokenHash,
    input.patientId,
    input.provider,
    input.providerSub,
    input.boundStatus,
    now,
    expiresAt
  ).run();
  return token;
}

async function getPatientSession(env: Env, request: Request) {
  const token = getPatientToken(request);
  if (!token) return null;
  const tokenHash = await hashValue(token);
  const now = Date.now();
  const row = await env.DB.prepare(
    `SELECT patient_id, provider, provider_sub, bound_status, expires_at
     FROM patient_session
     WHERE token_hash = ? AND expires_at > ?`
  ).bind(tokenHash, now).first();
  if (!row) return null;
  return {
    patientId: row.patient_id as string,
    provider: row.provider as string,
    providerSub: row.provider_sub as string,
    boundStatus: row.bound_status as string,
  };
}

function isPrivilegedAdminWrite(path: string, method: string): boolean {
  if (path.startsWith("/api/v1/admin/clinics")) return true;
  if (path.startsWith("/api/v1/admin/providers")) return true;
  if (path.startsWith("/api/v1/admin/schedule-rules")) return true;
  if (path.startsWith("/api/v1/admin/schedule-exceptions")) return true;
  if (path.startsWith("/api/v1/admin/slots/")) return true;
  if (path.startsWith("/api/v1/admin/queue/reserved")) return true;
  if (path.startsWith("/api/v1/admin/message-templates")) return true;
  if (path.startsWith("/api/v1/admin/staff-users")) return true;
  if (path.startsWith("/api/v1/admin/roles")) return true;
  if (path.startsWith("/api/v1/admin/patient-auth")) return true;
  if (path.startsWith("/api/v1/admin/clinic-notice")) return true;
  if (path.startsWith("/api/v1/admin/forms")) return true;
  if (path.startsWith("/api/v1/admin/patients/")) {
    if (path.endsWith("/lookup")) return false;
    if (path.endsWith("/quick-create")) return false;
    if (path.endsWith("/unlock")) return true;
    if (method === "DELETE") return true;
    return false;
  }
  return false;
}

async function enforceAdminAccess(request: Request, env: Env) {
  if (!request.url.includes("/api/v1/admin")) return;
  const method = request.method.toUpperCase();
  const staff = await getStaffContext(request, env);
  if (env.APP_ENV === "dev" || env.APP_ENV === "test") return;

  if (method === "GET") return;
  if (!isPrivilegedAdminWrite(new URL(request.url).pathname, method)) return;

  const hasAdminRole = staff.roles.some((role) => ADMIN_ROLE_NAMES.has(role));
  if (!hasAdminRole) {
    throw new AppError("forbidden", 403, { role: "insufficient" });
  }
}

async function getAdminProfile(request: Request, env: Env) {
  const staff = await getStaffContext(request, env);
  let profile: { email: string | null; name: string | null } | null = null;
  if (staff.staffId) {
    const row = await env.DB.prepare(
      `SELECT email, name FROM staff_user WHERE id = ?`
    ).bind(staff.staffId).first();
    profile = row
      ? { email: (row.email as string) ?? null, name: (row.name as string) ?? null }
      : null;
  }

  return jsonResponse({
    data: {
      staff_id: staff.staffId,
      org_id: staff.orgId ?? null,
      clinic_id: staff.clinicId ?? null,
      roles: staff.roles ?? [],
      email: profile?.email ?? null,
      name: profile?.name ?? null,
    },
  });
}

function getTaipeiDateString(date = new Date()): string {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Taipei",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });
  return formatter.format(date);
}

function toUtcEpochMs(serviceDateLocal: string, timeLocal: string): number {
  const [year, month, day] = serviceDateLocal.split("-").map((value) => Number(value));
  const [hours, minutes] = timeLocal.split(":").map((value) => Number(value));
  return Date.UTC(year, month - 1, day, hours - 8, minutes, 0);
}

function isValidDateString(value: string): boolean {
  return /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value);
}

function isValidTimeString(value: string): boolean {
  return /^[0-9]{2}:[0-9]{2}$/.test(value);
}

function getWeekday(value: string): number {
  const [year, month, day] = value.split("-").map((item) => Number(item));
  const utcDate = new Date(Date.UTC(year, month - 1, day));
  return utcDate.getUTCDay();
}

function enumerateDates(fromDate: string, toDate: string): string[] {
  const [fromYear, fromMonth, fromDay] = fromDate.split("-").map((item) => Number(item));
  const [toYear, toMonth, toDay] = toDate.split("-").map((item) => Number(item));
  const start = Date.UTC(fromYear, fromMonth - 1, fromDay);
  const end = Date.UTC(toYear, toMonth - 1, toDay);
  if (Number.isNaN(start) || Number.isNaN(end) || start > end) {
    throw new AppError("validation_error", 400, { date_range: "invalid" });
  }
  const dates: string[] = [];
  for (let cursor = start; cursor <= end; cursor += 24 * 60 * 60 * 1000) {
    const date = new Date(cursor).toISOString().slice(0, 10);
    dates.push(date);
  }
  return dates;
}


function getBookingStubByKey(env: Env, key: string): BookingRpc {
  const namespace = env.BOOKING_DO as unknown as {
    getByName?: (name: string) => unknown;
    idFromName: (name: string) => unknown;
    get: (id: unknown) => unknown;
  };
  if (typeof namespace.getByName === "function") {
    return namespace.getByName(key) as BookingRpc;
  }
  return namespace.get(namespace.idFromName(key)) as BookingRpc;
}

async function getBookingStubBySlot(env: Env, slotId: string): Promise<BookingRpc> {
  const slotRow = await env.DB.prepare(
    `SELECT provider_id, service_date_local
     FROM slot
     WHERE id = ?`
  ).bind(slotId).first();

  if (!slotRow) {
    throw new AppError("not_found", 404, { slot_id: "not_found" });
  }

  const key = `${slotRow.provider_id}:${slotRow.service_date_local}`;
  return getBookingStubByKey(env, key);
}

async function getBookingStubByHold(env: Env, holdToken: string): Promise<BookingRpc> {
  const holdRow = await env.DB.prepare(
    `SELECT provider_id, slot_id
     FROM appointment_hold
     WHERE id = ?`
  ).bind(holdToken).first();

  if (!holdRow) {
    throw new AppError("hold_expired", 410);
  }

  const slotRow = await env.DB.prepare(
    `SELECT service_date_local
     FROM slot
     WHERE id = ?`
  ).bind(holdRow.slot_id).first();

  if (!slotRow) {
    throw new AppError("not_found", 404, { slot_id: "not_found" });
  }

  const key = `${holdRow.provider_id}:${slotRow.service_date_local}`;
  return getBookingStubByKey(env, key);
}

async function getBookingStubByAppointment(env: Env, appointmentId: string): Promise<BookingRpc> {
  const row = await env.DB.prepare(
    `SELECT provider_id, service_date_local
     FROM appointment
     WHERE id = ?`
  ).bind(appointmentId).first();

  if (!row) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }

  const key = `${row.provider_id}:${row.service_date_local}`;
  return getBookingStubByKey(env, key);
}

async function listClinics(env: Env) {
  const result = await env.DB.prepare(
    `SELECT id, name, timezone FROM clinic ORDER BY name`
  ).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function listClinicsAdmin(request: Request, env: Env) {
  const staff = await getStaffContext(request, env);
  const where: string[] = [];
  const params: unknown[] = [];
  if (staff.orgId) {
    where.push("org_id = ?");
    params.push(staff.orgId);
  }

  const sql = `SELECT id, org_id, name, timezone, phone, address, created_at
               FROM clinic
               ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
               ORDER BY name`;
  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function resolveStaffOrgId(request: Request, env: Env): Promise<string> {
  const staff = await getStaffContext(request, env);
  if (staff.orgId) return staff.orgId;
  const orgRow = await env.DB.prepare(
    `SELECT id FROM org ORDER BY created_at LIMIT 1`
  ).first();
  if (!orgRow) {
    throw new AppError("validation_error", 400, { org_id: "missing" });
  }
  return orgRow.id as string;
}

async function createClinic(request: Request, env: Env) {
  const body = await parseJson<{
    name: string;
    timezone?: string;
    phone?: string;
    address?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.name) {
    throw new AppError("validation_error", 400, { name: "required" });
  }

  const orgId = await resolveStaffOrgId(request, env);
  const now = Date.now();
  const id = crypto.randomUUID();
  const timezone = body.timezone || "Asia/Taipei";

  await env.DB.prepare(
    `INSERT INTO clinic (id, org_id, name, timezone, phone, address, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id,
    orgId,
    body.name,
    timezone,
    body.phone ?? null,
    body.address ?? null,
    now
  ).run();

  await writeAuditLog(env, {
    orgId,
    clinicId: id,
    actorType: "staff",
    action: "create",
    entityTable: "clinic",
    entityId: id,
    after: {
      id,
      name: body.name,
      timezone,
      phone: body.phone ?? null,
      address: body.address ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function updateClinic(request: Request, env: Env, clinicId: string) {
  const body = await parseJson<{
    name?: string;
    timezone?: string;
    phone?: string;
    address?: string;
  }>(request);
  const requestId = getRequestId(request);

  const existing = await env.DB.prepare(
    `SELECT id, org_id, name, timezone, phone, address FROM clinic WHERE id = ?`
  ).bind(clinicId).first();

  if (!existing) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const next = {
    name: body.name ?? (existing.name as string),
    timezone: body.timezone ?? (existing.timezone as string),
    phone: body.phone ?? (existing.phone as string | null),
    address: body.address ?? (existing.address as string | null),
  };

  await env.DB.prepare(
    `UPDATE clinic
     SET name = ?, timezone = ?, phone = ?, address = ?
     WHERE id = ?`
  ).bind(
    next.name,
    next.timezone,
    next.phone ?? null,
    next.address ?? null,
    clinicId
  ).run();

  await writeAuditLog(env, {
    orgId: existing.org_id as string,
    clinicId,
    actorType: "staff",
    action: "update",
    entityTable: "clinic",
    entityId: clinicId,
    before: {
      name: existing.name,
      timezone: existing.timezone,
      phone: existing.phone,
      address: existing.address,
    },
    after: next,
    requestId,
  });

  return jsonResponse({ data: { id: clinicId } });
}

async function seedDevData(env: Env, request: Request) {
  if (env.APP_ENV !== "dev") {
    throw new AppError("not_found", 404);
  }

  const body = await parseJson<{ service_date_local?: string; days?: number }>(request);
  const serviceDate = body.service_date_local || getTaipeiDateString();
  const addDays = (value: string, offset: number) => {
    const [year, month, day] = value.split("-").map((item) => Number(item));
    const base = Date.UTC(year, month - 1, day);
    return new Date(base + offset * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  };
  const days = Math.min(Math.max(Number(body.days ?? 3), 1), 14);
  const lastDate = addDays(serviceDate, days - 1);
  const serviceDates = enumerateDates(serviceDate, lastDate);
  const now = Date.now();

  const orgId = "org_demo";
  const clinics = [
    { id: "cln_tp_main", name: "Taipei Main Clinic" },
    { id: "cln_tp_station", name: "Taipei Station Clinic" },
  ];
  const providers = [
    {
      id: "prv_retina",
      clinic_id: "cln_tp_main",
      name: "Dr. Wang",
      title: "Retina Clinic",
      specialty: "Retina",
      bio: "Retina specialist with 20+ years of clinical experience.",
      photo_url:
        "https://lh3.googleusercontent.com/aida-public/AB6AXuB8seP-4B0_0ico_5tpy7rDR4dHBFitxyQ9cwIKUzT3CRPEoWGWbzbu78I9SpoR6JrFCXXYBvO64hpZr_boO5oyyA6dzBbA1p3ZXV39Brso1kC90Ph1-kaa86j1gGoDNSldEXaadSoM1FuzovX4bjzpyKEvfcAiqBOR-XR8m82J_bvNKyfxQ0w0hExUrN3924yoSshHF_bflDCZcJZwWwlqXOX4OrhRg79AlmL04IPbDdKdFzwMQc7it2l_irH3ME8ozXZzv8q2qKzo",
    },
    {
      id: "prv_glaucoma",
      clinic_id: "cln_tp_main",
      name: "Dr. Lin",
      title: "Glaucoma Clinic",
      specialty: "Glaucoma",
      bio: "Glaucoma specialist focusing on optic nerve health.",
      photo_url:
        "https://images.unsplash.com/photo-1576091160550-2173dba999ef?auto=format&fit=crop&w=500&q=80",
    },
  ];

  await env.DB.prepare(
    `INSERT OR IGNORE INTO org (id, name, created_at)
     VALUES (?, ?, ?)`
  ).bind(orgId, "示範診所", now).run();

  for (const clinic of clinics) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO clinic (id, org_id, name, timezone, created_at)
       VALUES (?, ?, ?, 'Asia/Taipei', ?)`
    ).bind(clinic.id, orgId, clinic.name, now).run();
  }

  for (const provider of providers) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO provider
        (id, org_id, clinic_id, name, title, specialty, bio, photo_url, is_active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).bind(
      provider.id,
      orgId,
      provider.clinic_id,
      provider.name,
      provider.title,
      provider.specialty,
      provider.bio,
      provider.photo_url,
      now
    ).run();
  }
  const roleNames = ["system_admin", "group_admin", "clinic_admin", "staff"];
  for (const roleName of roleNames) {
    await ensureRole(env, roleName, "org");
  }

  const adminStaffId = "staff_admin";
  await env.DB.prepare(
    `INSERT OR IGNORE INTO staff_user
      (id, org_id, clinic_id, cf_subject, email, name, is_active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
  ).bind(
    adminStaffId,
    orgId,
    clinics[0].id,
    "admin@example.com",
    "admin@example.com",
    "System Admin",
    now
  ).run();

  const adminRoleId = await ensureRole(env, "system_admin", "org");
  await env.DB.prepare(
    `INSERT OR IGNORE INTO staff_user_role (staff_user_id, role_id)
     VALUES (?, ?)`
  ).bind(adminStaffId, adminRoleId).run();

  const slotTimes = [
    "09:00",
    "09:15",
    "09:30",
    "09:45",
    "10:00",
    "10:15",
    "10:30",
    "10:45",
    "11:00",
    "11:15",
    "11:30",
    "11:45",
  ];

  for (const serviceDate of serviceDates) {
    for (const provider of providers) {
      for (const time of slotTimes) {
        const slotId = `${provider.id}-${serviceDate}-${time.replace(":", "")}`;
        const startAtUtc = toUtcEpochMs(serviceDate, time);
        const endAtUtc = startAtUtc + 15 * 60 * 1000;

        await env.DB.prepare(
          `INSERT OR IGNORE INTO slot
            (id, provider_id, clinic_id, service_date_local, start_at_utc, end_at_utc, capacity, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 4, 'open', ?)`
        ).bind(
          slotId,
          provider.id,
          provider.clinic_id,
          serviceDate,
          startAtUtc,
          endAtUtc,
          now
        ).run();

        await env.DB.prepare(
          `INSERT OR IGNORE INTO slot_inventory (slot_id, capacity, booked_count, version)
           VALUES (?, 4, 0, 0)`
        ).bind(slotId).run();
      }
    }
  }
  const formDefinitions = [
    {
      type: "initial",
      schema: {
        title: "Initial Visit Form",
        fields: [
          { key: "symptom", label: "Chief complaint", type: "text" },
          { key: "allergy", label: "Allergies", type: "text" },
          { key: "medication", label: "Current medications", type: "text" },
        ],
      },
    },
    {
      type: "followup",
      schema: {
        title: "Follow-up Form",
        fields: [
          { key: "status", label: "Status update", type: "text" },
          { key: "pain_scale", label: "Pain scale (1-10)", type: "number" },
          { key: "note", label: "Additional notes", type: "text" },
        ],
      },
    },
  ];

  for (const formDef of formDefinitions) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO form_definition
        (id, type, version, schema_json, is_active, created_at)
       VALUES (?, ?, 1, ?, 1, ?)`
    ).bind(crypto.randomUUID(), formDef.type, JSON.stringify(formDef.schema), now).run();
  }

  return jsonResponse({ data: { ok: true, service_date_local: serviceDate, service_dates: serviceDates } });
}

async function listProviders(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const specialty = url.searchParams.get("specialty");
  const query = url.searchParams.get("q");

  const where: string[] = ["is_active = 1"];
  const params: unknown[] = [];

  if (clinicId) {
    where.push("clinic_id = ?");
    params.push(clinicId);
  }

  if (specialty && specialty !== "all") {
    where.push("specialty = ?");
    params.push(specialty);
  }

  if (query) {
    where.push("name LIKE ?");
    params.push(`%${query}%`);
  }

  const sql = `SELECT id, clinic_id, name, title, specialty, photo_url
               FROM provider
               WHERE ${where.join(" AND ")}
               ORDER BY name`;

  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function listSlots(request: Request, env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const providerId = url.searchParams.get("provider_id");
  const serviceDate = url.searchParams.get("service_date_local");

  if (!clinicId || !providerId || !serviceDate) {
    throw new AppError("validation_error", 400, {
      clinic_id: clinicId ? undefined : "required",
      provider_id: providerId ? undefined : "required",
      service_date_local: serviceDate ? undefined : "required",
    });
  }

  const ip = getClientIp(request) ?? "unknown";
  const deviceId = request.headers.get("x-device-id") || "na";
  const rateKey = `rl:slots:${ip}:${deviceId}`;
  await checkRateLimit(env, rateKey, 60, 60 * 1000);

  const result = await env.DB.prepare(
    `SELECT slot.id as slot_id,
            slot.start_at_utc,
            slot.end_at_utc,
            slot.capacity,
            slot.status,
            slot_inventory.booked_count
     FROM slot
     JOIN slot_inventory ON slot_inventory.slot_id = slot.id
     WHERE slot.clinic_id = ?
       AND slot.provider_id = ?
       AND slot.service_date_local = ?
     ORDER BY slot.start_at_utc`
  ).bind(clinicId, providerId, serviceDate).all();

  return jsonResponse({ data: result.results ?? [] });
}

async function listProvidersAdmin(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const where: string[] = [];
  const params: unknown[] = [];

  if (clinicId) {
    where.push("clinic_id = ?");
    params.push(clinicId);
  }

  const sql = `SELECT id, clinic_id, name, title, specialty, bio, photo_url, is_active
               FROM provider
               ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
               ORDER BY name`;

  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function createProvider(request: Request, env: Env) {
  const body = await parseJson<{
    clinic_id: string;
    name: string;
    title?: string;
    specialty?: string;
    bio?: string;
    photo_url?: string;
    is_active?: boolean;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.clinic_id) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!body.name) {
    throw new AppError("validation_error", 400, { name: "required" });
  }

  const clinicInfo = await getClinicOrg(env, body.clinic_id);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const id = crypto.randomUUID();
  const now = Date.now();
  const isActive = body.is_active === false ? 0 : 1;

  await env.DB.prepare(
    `INSERT INTO provider
      (id, org_id, clinic_id, name, title, specialty, bio, photo_url, is_active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id,
    clinicInfo.orgId,
    body.clinic_id,
    body.name,
    body.title ?? null,
    body.specialty ?? null,
    body.bio ?? null,
    body.photo_url ?? null,
    isActive,
    now
  ).run();

  await writeAuditLog(env, {
    orgId: clinicInfo.orgId,
    clinicId: body.clinic_id,
    actorType: "staff",
    action: "create",
    entityTable: "provider",
    entityId: id,
    after: {
      id,
      clinic_id: body.clinic_id,
      name: body.name,
      title: body.title ?? null,
      specialty: body.specialty ?? null,
      bio: body.bio ?? null,
      photo_url: body.photo_url ?? null,
      is_active: isActive,
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function updateProvider(request: Request, env: Env, providerId: string) {
  const body = await parseJson<{
    clinic_id?: string;
    name?: string;
    title?: string;
    specialty?: string;
    bio?: string;
    photo_url?: string;
    is_active?: boolean;
  }>(request);
  const requestId = getRequestId(request);

  const existing = await env.DB.prepare(
    `SELECT id, org_id, clinic_id, name, title, specialty, bio, photo_url, is_active
     FROM provider
     WHERE id = ?`
  ).bind(providerId).first();

  if (!existing) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  let clinicId = body.clinic_id ?? (existing.clinic_id as string);
  let orgId = existing.org_id as string;
  if (body.clinic_id) {
    const clinicInfo = await getClinicOrg(env, body.clinic_id);
    if (!clinicInfo) {
      throw new AppError("not_found", 404, { clinic_id: "not_found" });
    }
    clinicId = clinicInfo.clinicId;
    orgId = clinicInfo.orgId;
  }

  const next = {
    clinic_id: clinicId,
    name: body.name ?? (existing.name as string),
    title: body.title ?? (existing.title as string | null),
    specialty: body.specialty ?? (existing.specialty as string | null),
    bio: body.bio ?? (existing.bio as string | null),
    photo_url: body.photo_url ?? (existing.photo_url as string | null),
    is_active: body.is_active === undefined ? Number(existing.is_active) : body.is_active ? 1 : 0,
  };

  await env.DB.prepare(
    `UPDATE provider
     SET org_id = ?, clinic_id = ?, name = ?, title = ?, specialty = ?, bio = ?, photo_url = ?, is_active = ?
     WHERE id = ?`
  ).bind(
    orgId,
    next.clinic_id,
    next.name,
    next.title ?? null,
    next.specialty ?? null,
    next.bio ?? null,
    next.photo_url ?? null,
    next.is_active,
    providerId
  ).run();

  await writeAuditLog(env, {
    orgId,
    clinicId: next.clinic_id,
    actorType: "staff",
    action: "update",
    entityTable: "provider",
    entityId: providerId,
    before: {
      clinic_id: existing.clinic_id,
      name: existing.name,
      title: existing.title,
      specialty: existing.specialty,
      bio: existing.bio,
      photo_url: existing.photo_url,
      is_active: existing.is_active,
    },
    after: next,
    requestId,
  });

  return jsonResponse({ data: { id: providerId } });
}

async function listScheduleRules(env: Env, url: URL) {
  const providerId = url.searchParams.get("provider_id");
  if (!providerId) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }

  const result = await env.DB.prepare(
    `SELECT id, provider_id, weekday, start_time_local, end_time_local,
            slot_minutes, capacity_per_slot, effective_from, effective_to, created_at
     FROM schedule_rule
     WHERE provider_id = ?
     ORDER BY weekday, start_time_local`
  ).bind(providerId).all();

  return jsonResponse({ data: result.results ?? [] });
}

async function createScheduleRule(request: Request, env: Env) {
  const body = await parseJson<{
    provider_id: string;
    weekday: number;
    start_time_local: string;
    end_time_local: string;
    slot_minutes: number;
    capacity_per_slot: number;
    effective_from?: string;
    effective_to?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider_id) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (body.weekday === undefined || body.weekday < 0 || body.weekday > 6) {
    throw new AppError("validation_error", 400, { weekday: "invalid" });
  }
  if (!isValidTimeString(body.start_time_local) || !isValidTimeString(body.end_time_local)) {
    throw new AppError("validation_error", 400, { time: "invalid" });
  }
  if (!body.slot_minutes || body.slot_minutes <= 0) {
    throw new AppError("validation_error", 400, { slot_minutes: "invalid" });
  }
  if (!body.capacity_per_slot || body.capacity_per_slot <= 0) {
    throw new AppError("validation_error", 400, { capacity_per_slot: "invalid" });
  }
  if (body.effective_from && !isValidDateString(body.effective_from)) {
    throw new AppError("validation_error", 400, { effective_from: "invalid" });
  }
  if (body.effective_to && !isValidDateString(body.effective_to)) {
    throw new AppError("validation_error", 400, { effective_to: "invalid" });
  }

  const providerInfo = await getProviderOrgClinic(env, body.provider_id);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO schedule_rule
      (id, provider_id, weekday, start_time_local, end_time_local, slot_minutes,
       capacity_per_slot, effective_from, effective_to, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id,
    body.provider_id,
    body.weekday,
    body.start_time_local,
    body.end_time_local,
    body.slot_minutes,
    body.capacity_per_slot,
    body.effective_from ?? null,
    body.effective_to ?? null,
    now
  ).run();

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "create",
    entityTable: "schedule_rule",
    entityId: id,
    after: {
      id,
      provider_id: body.provider_id,
      weekday: body.weekday,
      start_time_local: body.start_time_local,
      end_time_local: body.end_time_local,
      slot_minutes: body.slot_minutes,
      capacity_per_slot: body.capacity_per_slot,
      effective_from: body.effective_from ?? null,
      effective_to: body.effective_to ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function updateScheduleRule(request: Request, env: Env, id: string) {
  const body = await parseJson<{
    provider_id: string;
    weekday: number;
    start_time_local: string;
    end_time_local: string;
    slot_minutes: number;
    capacity_per_slot: number;
    effective_from?: string;
    effective_to?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider_id) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (body.weekday === undefined || body.weekday < 0 || body.weekday > 6) {
    throw new AppError("validation_error", 400, { weekday: "invalid" });
  }
  if (!isValidTimeString(body.start_time_local) || !isValidTimeString(body.end_time_local)) {
    throw new AppError("validation_error", 400, { time: "invalid" });
  }
  if (!body.slot_minutes || body.slot_minutes <= 0) {
    throw new AppError("validation_error", 400, { slot_minutes: "invalid" });
  }
  if (!body.capacity_per_slot || body.capacity_per_slot <= 0) {
    throw new AppError("validation_error", 400, { capacity_per_slot: "invalid" });
  }
  if (body.effective_from && !isValidDateString(body.effective_from)) {
    throw new AppError("validation_error", 400, { effective_from: "invalid" });
  }
  if (body.effective_to && !isValidDateString(body.effective_to)) {
    throw new AppError("validation_error", 400, { effective_to: "invalid" });
  }

  const existing = await env.DB.prepare(
    `SELECT id, provider_id, weekday, start_time_local, end_time_local, slot_minutes,
            capacity_per_slot, effective_from, effective_to
     FROM schedule_rule WHERE id = ?`
  ).bind(id).first();
  if (!existing) {
    throw new AppError("not_found", 404, { schedule_rule: "not_found" });
  }

  const providerInfo = await getProviderOrgClinic(env, body.provider_id);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const result = await env.DB.prepare(
    `UPDATE schedule_rule
     SET provider_id = ?, weekday = ?, start_time_local = ?, end_time_local = ?,
         slot_minutes = ?, capacity_per_slot = ?, effective_from = ?, effective_to = ?
     WHERE id = ?`
  ).bind(
    body.provider_id,
    body.weekday,
    body.start_time_local,
    body.end_time_local,
    body.slot_minutes,
    body.capacity_per_slot,
    body.effective_from ?? null,
    body.effective_to ?? null,
    id
  ).run();

  if (result.meta.changes !== 1) {
    throw new AppError("not_found", 404, { schedule_rule: "not_found" });
  }

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "update",
    entityTable: "schedule_rule",
    entityId: id,
    before: existing,
    after: {
      id,
      provider_id: body.provider_id,
      weekday: body.weekday,
      start_time_local: body.start_time_local,
      end_time_local: body.end_time_local,
      slot_minutes: body.slot_minutes,
      capacity_per_slot: body.capacity_per_slot,
      effective_from: body.effective_from ?? null,
      effective_to: body.effective_to ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { id } });
}

async function deleteScheduleRule(request: Request, env: Env, id: string) {
  const requestId = getRequestId(request);
  const existing = await env.DB.prepare(
    `SELECT id, provider_id, weekday, start_time_local, end_time_local, slot_minutes,
            capacity_per_slot, effective_from, effective_to
     FROM schedule_rule WHERE id = ?`
  ).bind(id).first();
  if (!existing) {
    throw new AppError("not_found", 404, { schedule_rule: "not_found" });
  }

  const providerInfo = await getProviderOrgClinic(env, existing.provider_id as string);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const result = await env.DB.prepare(`DELETE FROM schedule_rule WHERE id = ?`).bind(id).run();
  if (result.meta.changes !== 1) {
    throw new AppError("not_found", 404, { schedule_rule: "not_found" });
  }

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "delete",
    entityTable: "schedule_rule",
    entityId: id,
    before: existing,
    requestId,
  });

  return jsonResponse({ data: { id } });
}

async function listScheduleExceptions(env: Env, url: URL) {
  const providerId = url.searchParams.get("provider_id");
  if (!providerId) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }

  const result = await env.DB.prepare(
    `SELECT id, provider_id, service_date_local, type,
            override_start_time_local, override_end_time_local,
            override_slot_minutes, override_capacity_per_slot, note, created_at
     FROM schedule_exception
     WHERE provider_id = ?
     ORDER BY service_date_local DESC`
  ).bind(providerId).all();

  return jsonResponse({ data: result.results ?? [] });
}

async function createScheduleException(request: Request, env: Env) {
  const body = await parseJson<{
    provider_id: string;
    service_date_local: string;
    type: "closed" | "override";
    override_start_time_local?: string;
    override_end_time_local?: string;
    override_slot_minutes?: number;
    override_capacity_per_slot?: number;
    note?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider_id) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (!body.service_date_local || !isValidDateString(body.service_date_local)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }
  if (!body.type || !["closed", "override"].includes(body.type)) {
    throw new AppError("validation_error", 400, { type: "invalid" });
  }

  if (body.type === "override") {
    if (!isValidTimeString(body.override_start_time_local ?? "")) {
      throw new AppError("validation_error", 400, { override_start_time_local: "invalid" });
    }
    if (!isValidTimeString(body.override_end_time_local ?? "")) {
      throw new AppError("validation_error", 400, { override_end_time_local: "invalid" });
    }
    if (!body.override_slot_minutes || body.override_slot_minutes <= 0) {
      throw new AppError("validation_error", 400, { override_slot_minutes: "invalid" });
    }
    if (!body.override_capacity_per_slot || body.override_capacity_per_slot <= 0) {
      throw new AppError("validation_error", 400, { override_capacity_per_slot: "invalid" });
    }
  }

  const providerInfo = await getProviderOrgClinic(env, body.provider_id);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO schedule_exception
      (id, provider_id, service_date_local, type,
       override_start_time_local, override_end_time_local,
       override_slot_minutes, override_capacity_per_slot, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id,
    body.provider_id,
    body.service_date_local,
    body.type,
    body.override_start_time_local ?? null,
    body.override_end_time_local ?? null,
    body.override_slot_minutes ?? null,
    body.override_capacity_per_slot ?? null,
    body.note ?? null,
    now
  ).run();

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "create",
    entityTable: "schedule_exception",
    entityId: id,
    after: {
      id,
      provider_id: body.provider_id,
      service_date_local: body.service_date_local,
      type: body.type,
      override_start_time_local: body.override_start_time_local ?? null,
      override_end_time_local: body.override_end_time_local ?? null,
      override_slot_minutes: body.override_slot_minutes ?? null,
      override_capacity_per_slot: body.override_capacity_per_slot ?? null,
      note: body.note ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function updateScheduleException(request: Request, env: Env, id: string) {
  const body = await parseJson<{
    provider_id: string;
    service_date_local: string;
    type: "closed" | "override";
    override_start_time_local?: string;
    override_end_time_local?: string;
    override_slot_minutes?: number;
    override_capacity_per_slot?: number;
    note?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider_id) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (!body.service_date_local || !isValidDateString(body.service_date_local)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }
  if (!body.type || !["closed", "override"].includes(body.type)) {
    throw new AppError("validation_error", 400, { type: "invalid" });
  }

  if (body.type === "override") {
    if (!isValidTimeString(body.override_start_time_local ?? "")) {
      throw new AppError("validation_error", 400, { override_start_time_local: "invalid" });
    }
    if (!isValidTimeString(body.override_end_time_local ?? "")) {
      throw new AppError("validation_error", 400, { override_end_time_local: "invalid" });
    }
    if (!body.override_slot_minutes || body.override_slot_minutes <= 0) {
      throw new AppError("validation_error", 400, { override_slot_minutes: "invalid" });
    }
    if (!body.override_capacity_per_slot || body.override_capacity_per_slot <= 0) {
      throw new AppError("validation_error", 400, { override_capacity_per_slot: "invalid" });
    }
  }

  const existing = await env.DB.prepare(
    `SELECT id, provider_id, service_date_local, type,
            override_start_time_local, override_end_time_local,
            override_slot_minutes, override_capacity_per_slot, note
     FROM schedule_exception WHERE id = ?`
  ).bind(id).first();
  if (!existing) {
    throw new AppError("not_found", 404, { schedule_exception: "not_found" });
  }

  const providerInfo = await getProviderOrgClinic(env, body.provider_id);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const result = await env.DB.prepare(
    `UPDATE schedule_exception
     SET provider_id = ?, service_date_local = ?, type = ?,
         override_start_time_local = ?, override_end_time_local = ?,
         override_slot_minutes = ?, override_capacity_per_slot = ?, note = ?
     WHERE id = ?`
  ).bind(
    body.provider_id,
    body.service_date_local,
    body.type,
    body.override_start_time_local ?? null,
    body.override_end_time_local ?? null,
    body.override_slot_minutes ?? null,
    body.override_capacity_per_slot ?? null,
    body.note ?? null,
    id
  ).run();

  if (result.meta.changes !== 1) {
    throw new AppError("not_found", 404, { schedule_exception: "not_found" });
  }

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "update",
    entityTable: "schedule_exception",
    entityId: id,
    before: existing,
    after: {
      id,
      provider_id: body.provider_id,
      service_date_local: body.service_date_local,
      type: body.type,
      override_start_time_local: body.override_start_time_local ?? null,
      override_end_time_local: body.override_end_time_local ?? null,
      override_slot_minutes: body.override_slot_minutes ?? null,
      override_capacity_per_slot: body.override_capacity_per_slot ?? null,
      note: body.note ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { id } });
}

async function deleteScheduleException(request: Request, env: Env, id: string) {
  const requestId = getRequestId(request);
  const existing = await env.DB.prepare(
    `SELECT id, provider_id, service_date_local, type,
            override_start_time_local, override_end_time_local,
            override_slot_minutes, override_capacity_per_slot, note
     FROM schedule_exception WHERE id = ?`
  ).bind(id).first();
  if (!existing) {
    throw new AppError("not_found", 404, { schedule_exception: "not_found" });
  }

  const providerInfo = await getProviderOrgClinic(env, existing.provider_id as string);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const result = await env.DB.prepare(`DELETE FROM schedule_exception WHERE id = ?`).bind(id).run();
  if (result.meta.changes !== 1) {
    throw new AppError("not_found", 404, { schedule_exception: "not_found" });
  }

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "delete",
    entityTable: "schedule_exception",
    entityId: id,
    before: existing,
    requestId,
  });

  return jsonResponse({ data: { id } });
}

async function generateSlots(request: Request, env: Env) {
  const body = await parseJson<{
    provider_id: string;
    from_date: string;
    to_date?: string;
    reset_existing?: boolean;
    overwrite_empty?: boolean;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider_id) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (!body.from_date || !isValidDateString(body.from_date)) {
    throw new AppError("validation_error", 400, { from_date: "invalid" });
  }
  const toDate = body.to_date && isValidDateString(body.to_date) ? body.to_date : body.from_date;

  const providerInfo = await getProviderOrgClinic(env, body.provider_id);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const dates = enumerateDates(body.from_date, toDate);
  const now = Date.now();
  let inserted = 0;

  for (const serviceDate of dates) {
    if (body.reset_existing) {
      await env.DB.prepare(
        `DELETE FROM slot_inventory
         WHERE slot_id IN (
           SELECT slot.id
           FROM slot
           JOIN slot_inventory ON slot_inventory.slot_id = slot.id
           WHERE slot.provider_id = ? AND slot.service_date_local = ? AND slot_inventory.booked_count = 0
         )`
      ).bind(body.provider_id, serviceDate).run();

      await env.DB.prepare(
        `DELETE FROM slot
         WHERE provider_id = ? AND service_date_local = ?
           AND id NOT IN (SELECT slot_id FROM slot_inventory)`
      ).bind(body.provider_id, serviceDate).run();

      await env.DB.prepare(
        `DELETE FROM appointment_hold
         WHERE slot_id IN (
           SELECT id FROM slot WHERE provider_id = ? AND service_date_local = ?
         )`
      ).bind(body.provider_id, serviceDate).run();
    }

    const exceptionResult = await env.DB.prepare(
      `SELECT type, override_start_time_local, override_end_time_local,
              override_slot_minutes, override_capacity_per_slot
       FROM schedule_exception
       WHERE provider_id = ? AND service_date_local = ?
       ORDER BY created_at DESC`
    ).bind(body.provider_id, serviceDate).all();

    let schedules: Array<{
      start: string;
      end: string;
      minutes: number;
      capacity: number;
    }> = [];

    const exceptionRowsList = (exceptionResult.results ?? []) as Array<{
      type: string;
      override_start_time_local?: string;
      override_end_time_local?: string;
      override_slot_minutes?: number;
      override_capacity_per_slot?: number;
    }>;

    const hasClosed = exceptionRowsList.some((row) => row.type === "closed");
    const overrideRows = exceptionRowsList.filter((row) => row.type === "override");

    if (hasClosed) {
      continue;
    }

    if (overrideRows.length > 0) {
      schedules = overrideRows.map((row) => ({
        start: row.override_start_time_local as string,
        end: row.override_end_time_local as string,
        minutes: Number(row.override_slot_minutes),
        capacity: Number(row.override_capacity_per_slot),
      }));
    } else {
      const weekday = getWeekday(serviceDate);
      const ruleRows = await env.DB.prepare(
        `SELECT start_time_local, end_time_local, slot_minutes, capacity_per_slot
         FROM schedule_rule
         WHERE provider_id = ?
           AND weekday = ?
           AND (effective_from IS NULL OR effective_from <= ?)
           AND (effective_to IS NULL OR effective_to >= ?)
         ORDER BY start_time_local`
      ).bind(body.provider_id, weekday, serviceDate, serviceDate).all();

      schedules = (ruleRows.results ?? []).map((row) => ({
        start: row.start_time_local as string,
        end: row.end_time_local as string,
        minutes: Number(row.slot_minutes),
        capacity: Number(row.capacity_per_slot),
      }));
    }

    for (const schedule of schedules) {
      if (!isValidTimeString(schedule.start) || !isValidTimeString(schedule.end)) {
        continue;
      }
      const [startHour, startMin] = schedule.start.split(":").map(Number);
      const [endHour, endMin] = schedule.end.split(":").map(Number);
      const startTotal = startHour * 60 + startMin;
      const endTotal = endHour * 60 + endMin;
      if (startTotal >= endTotal) continue;

      for (let minutes = startTotal; minutes < endTotal; minutes += schedule.minutes) {
        const hh = String(Math.floor(minutes / 60)).padStart(2, "0");
        const mm = String(minutes % 60).padStart(2, "0");
        const timeLocal = `${hh}:${mm}`;
        const slotId = `${body.provider_id}-${serviceDate}-${hh}${mm}`;
        const startAtUtc = toUtcEpochMs(serviceDate, timeLocal);
        const endAtUtc = startAtUtc + schedule.minutes * 60 * 1000;

        const slotResult = await env.DB.prepare(
          `INSERT OR IGNORE INTO slot
            (id, provider_id, clinic_id, service_date_local, start_at_utc, end_at_utc, capacity, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)`
        ).bind(
          slotId,
          body.provider_id,
          providerInfo.clinicId,
          serviceDate,
          startAtUtc,
          endAtUtc,
          schedule.capacity,
          now
        ).run();

        await env.DB.prepare(
          `INSERT OR IGNORE INTO slot_inventory (slot_id, capacity, booked_count, version)
           VALUES (?, ?, 0, 0)`
        ).bind(slotId, schedule.capacity).run();

        if (slotResult.meta.changes === 1) {
          inserted += 1;
        } else if (body.overwrite_empty) {
          await env.DB.prepare(
            `UPDATE slot
             SET end_at_utc = ?, capacity = ?
             WHERE id = ?`
          ).bind(endAtUtc, schedule.capacity, slotId).run();

          await env.DB.prepare(
            `UPDATE slot_inventory
             SET capacity = ?
             WHERE slot_id = ? AND booked_count = 0`
          ).bind(schedule.capacity, slotId).run();
        }
      }
    }
  }

  await writeAuditLog(env, {
    orgId: providerInfo.orgId,
    clinicId: providerInfo.clinicId,
    actorType: "staff",
    action: "generate_slots",
    entityTable: "slot",
    entityId: `${body.provider_id}:${body.from_date}:${toDate}`,
    after: {
      provider_id: body.provider_id,
      from_date: body.from_date,
      to_date: toDate,
      inserted,
      reset_existing: Boolean(body.reset_existing),
      overwrite_empty: Boolean(body.overwrite_empty),
    },
    requestId,
  });

  return jsonResponse({ data: { inserted } });
}

async function closeSlots(request: Request, env: Env) {
  const body = await parseJson<{
    provider_id: string;
    service_date_local: string;
    mode: "stop_new" | "cancel_all";
    notify?: boolean;
    reason?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider_id) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (!body.service_date_local || !isValidDateString(body.service_date_local)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }
  if (!body.mode || !["stop_new", "cancel_all"].includes(body.mode)) {
    throw new AppError("validation_error", 400, { mode: "invalid" });
  }

  const providerInfo = await getProviderOrgClinic(env, body.provider_id);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const now = Date.now();
  const slots = await env.DB.prepare(
    `SELECT id FROM slot WHERE provider_id = ? AND service_date_local = ?`
  ).bind(body.provider_id, body.service_date_local).all();

  await env.DB.exec("BEGIN");
  try {
    await env.DB.prepare(
      `UPDATE slot
       SET status = 'closed'
       WHERE provider_id = ? AND service_date_local = ?`
    ).bind(body.provider_id, body.service_date_local).run();

    await env.DB.prepare(
      `DELETE FROM appointment_hold
       WHERE slot_id IN (
         SELECT id FROM slot WHERE provider_id = ? AND service_date_local = ?
       )`
    ).bind(body.provider_id, body.service_date_local).run();

    let cancelledCount = 0;
    if (body.mode === "cancel_all") {
      const appointments = await env.DB.prepare(
        `SELECT id, patient_id
         FROM appointment
         WHERE provider_id = ?
           AND service_date_local = ?
           AND status NOT IN ('cancelled', 'done', 'no_show')`
      ).bind(body.provider_id, body.service_date_local).all();

      if (appointments.results?.length) {
        const appointmentIds = appointments.results.map((row) => row.id as string);
        const placeholders = appointmentIds.map(() => "?").join(",");

        const updateResult = await env.DB.prepare(
          `UPDATE appointment
           SET status = 'cancelled', cancelled_at = ?, updated_at = ?
           WHERE id IN (${placeholders})`
        ).bind(now, now, ...appointmentIds).run();

        cancelledCount = updateResult.meta.changes ?? 0;

        await env.DB.prepare(
          `UPDATE slot_inventory
           SET booked_count = 0, version = version + 1
           WHERE slot_id IN (
             SELECT id FROM slot WHERE provider_id = ? AND service_date_local = ?
           )`
        ).bind(body.provider_id, body.service_date_local).run();

        if (body.notify) {
          for (const appointment of appointments.results) {
            let contacts = await env.DB.prepare(
              `SELECT type, value
               FROM patient_contact
               WHERE patient_id = ? AND is_primary = 1`
            ).bind(appointment.patient_id).all();

            if (!contacts.results?.length) {
              contacts = await env.DB.prepare(
                `SELECT type, value
                 FROM patient_contact
                 WHERE patient_id = ?`
              ).bind(appointment.patient_id).all();
            }

            const contactRows = filterNotificationContacts(contacts.results ?? []);
            for (const contact of contactRows) {

              await env.DB.prepare(
                `INSERT INTO notification_job
                  (id, event_type, channel, patient_id, appointment_id, payload_json, scheduled_at, status, created_at)
                 VALUES (?, 'manual', ?, ?, ?, ?, ?, 'queued', ?)`
              ).bind(
                crypto.randomUUID(),
                contact.type,
                appointment.patient_id,
                appointment.id,
                JSON.stringify({
                  reason: body.reason ?? "臨時停診",
                  service_date_local: body.service_date_local,
                  contact: contact.value,
                }),
                now,
                now
              ).run();
            }
          }
        }
      }
    }

    await env.DB.exec("COMMIT");

    await writeAuditLog(env, {
      orgId: providerInfo.orgId,
      clinicId: providerInfo.clinicId,
      actorType: "staff",
      action: "close_slots",
      entityTable: "slot",
      entityId: `${body.provider_id}:${body.service_date_local}`,
      after: {
        provider_id: body.provider_id,
        service_date_local: body.service_date_local,
        mode: body.mode,
        notify: Boolean(body.notify),
        reason: body.reason ?? null,
        closed_slots: slots.results?.length ?? 0,
        cancelled_appointments: cancelledCount,
      },
      requestId,
    });

    return jsonResponse({
      data: {
        closed_slots: slots.results?.length ?? 0,
        cancelled_appointments: cancelledCount,
      },
    });
  } catch (error) {
    await env.DB.exec("ROLLBACK");
    throw error;
  }
}

async function listNotificationJobs(env: Env, url: URL) {
  const status = url.searchParams.get("status");
  const where = status ? "WHERE status = ?" : "";
  const params = status ? [status] : [];
  const result = await env.DB.prepare(
    `SELECT id, event_type, channel, patient_id, appointment_id, scheduled_at, status, created_at
     FROM notification_job
     ${where}
     ORDER BY created_at DESC
     LIMIT 50`
  ).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function retryNotificationJob(request: Request, env: Env, jobId: string) {
  const requestId = getRequestId(request);
  const job = await env.DB.prepare(
    `SELECT id, status, patient_id
     FROM notification_job
     WHERE id = ?`
  ).bind(jobId).first();

  if (!job) {
    throw new AppError("not_found", 404, { notification_job: "not_found" });
  }

  if ((job.status as string) !== "failed") {
    throw new AppError("conflict", 409, { status: "not_failed" });
  }

  const now = Date.now();
  await env.DB.prepare(
    `UPDATE notification_job
     SET status = "queued", scheduled_at = ?
     WHERE id = ?`
  ).bind(now, jobId).run();

  const patientOrg = await getPatientOrg(env, job.patient_id as string);
  if (patientOrg) {
    await writeAuditLog(env, {
      orgId: patientOrg.orgId,
      clinicId: null,
      actorType: "staff",
      action: "retry",
      entityTable: "notification_job",
      entityId: jobId,
      before: { status: "failed" },
      after: { status: "queued", scheduled_at: now },
      requestId,
    });
  }

  return jsonResponse({ data: { id: jobId, status: "queued", scheduled_at: now } });
}

async function sendManualNotification(request: Request, env: Env) {
  const body = await parseJson<{
    channel: "email" | "line";
    patient_id: string;
    appointment_id?: string;
    payload?: Record<string, unknown>;
    template_id?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.channel) {
    throw new AppError("validation_error", 400, { channel: "required" });
  }
  if (!body.patient_id) {
    throw new AppError("validation_error", 400, { patient_id: "required" });
  }

  const patientOrg = await getPatientOrg(env, body.patient_id);
  if (!patientOrg) {
    throw new AppError("not_found", 404, { patient_id: "not_found" });
  }
  let clinicId: string | null = null;
  if (body.appointment_id) {
    const apptInfo = await getAppointmentOrgClinic(env, body.appointment_id);
    clinicId = apptInfo?.clinicId ?? null;
  }

  const now = Date.now();
  const id = crypto.randomUUID();
  let payload: Record<string, unknown> = body.payload ?? {};

  if (body.template_id) {
    const template = await env.DB.prepare(
      `SELECT subject, body FROM message_template WHERE id = ?`
    ).bind(body.template_id).first();
    if (!template) {
      throw new AppError("not_found", 404, { template_id: "not_found" });
    }
    const subject = template.subject ? renderTemplate(template.subject as string, payload) : null;
    const message = renderTemplate(template.body as string, payload);
    payload = { ...payload, subject, message, template_id: body.template_id };
  }

  await env.DB.prepare(
    `INSERT INTO notification_job
      (id, event_type, channel, patient_id, appointment_id, template_id, payload_json, scheduled_at, status, created_at)
     VALUES (?, 'manual', ?, ?, ?, ?, ?, ?, 'queued', ?)`
  ).bind(
    id,
    body.channel,
    body.patient_id,
    body.appointment_id ?? null,
    body.template_id ?? null,
    JSON.stringify(payload),
    now,
    now
  ).run();

  await writeAuditLog(env, {
    orgId: patientOrg.orgId,
    clinicId,
    actorType: "staff",
    action: "create",
    entityTable: "notification_job",
    entityId: id,
    after: {
      id,
      channel: body.channel,
      patient_id: body.patient_id,
      appointment_id: body.appointment_id ?? null,
      payload,
      status: "queued",
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function getContactValue(env: Env, patientId: string, channel: string): Promise<string | null> {
  let row = await env.DB.prepare(
    `SELECT value
     FROM patient_contact
     WHERE patient_id = ? AND type = ?
     ORDER BY is_primary DESC, created_at ASC
     LIMIT 1`
  ).bind(patientId, channel).first();

  if (!row) {
    row = await env.DB.prepare(
      `SELECT value
       FROM patient_contact
       WHERE patient_id = ? AND type = ?
       ORDER BY created_at ASC
       LIMIT 1`
    ).bind(patientId, channel).first();
  }

  return row?.value ?? null;
}

function buildDefaultMessage(payload: Record<string, unknown>): string {
  const clinic = payload.clinic_name ? `\u8a3a\u6240:${payload.clinic_name}` : "";
  const provider = payload.provider_name ? `\u91ab\u5e2b:${payload.provider_name}` : "";
  const patient = payload.patient_name ? `\u59d3\u540d:${payload.patient_name}` : "";
  const queue = payload.queue_no ? `\u865f\u78bc:${payload.queue_no}` : "";
  const date = payload.service_date_local ? `\u65e5\u671f:${payload.service_date_local}` : "";
  const reason = payload.reason ? `\u539f\u56e0:${payload.reason}` : "";
  return ["\u9580\u8a3a\u901a\u77e5", clinic, provider, patient, queue, date, reason].filter(Boolean).join(" / ");
}

function renderTemplate(text: string, variables: Record<string, unknown>): string {
  return text.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    const value = variables[key];
    return value === undefined || value === null ? "" : String(value);
  });
}

function escapeIcsText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "")
    .replace(/,/g, "\\,")
    .replace(/;/g, "\\;");
}

function formatIcsDateTime(ms: number): string {
  const date = new Date(ms);
  const pad = (value: number) => String(value).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
  );
}

function buildIcsCalendar(input: {
  uid: string;
  summary: string;
  description?: string | null;
  location?: string | null;
  startAtUtc: number;
  endAtUtc: number;
}): string {
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//clinic-booking//EN",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "BEGIN:VEVENT",
    `UID:${escapeIcsText(input.uid)}`,
    `DTSTAMP:${formatIcsDateTime(Date.now())}`,
    `DTSTART:${formatIcsDateTime(input.startAtUtc)}`,
    `DTEND:${formatIcsDateTime(input.endAtUtc)}`,
    `SUMMARY:${escapeIcsText(input.summary)}`,
  ];
  if (input.description) {
    lines.push(`DESCRIPTION:${escapeIcsText(input.description)}`);
  }
  if (input.location) {
    lines.push(`LOCATION:${escapeIcsText(input.location)}`);
  }
  lines.push("END:VEVENT", "END:VCALENDAR");
  return lines.join("\r\n");
}

function formatTaipeiTime(ms: number): string {
  return new Date(ms).toLocaleTimeString("en-GB", {
    timeZone: "Asia/Taipei",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function getServiceDateEndUtc(serviceDateLocal: string): number {
  const [year, month, day] = serviceDateLocal.split("-").map((value) => Number(value));
  return Date.UTC(year, month - 1, day, 23 - 8, 59, 59);
}

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === '"') {
      const nextChar = line[i + 1];
      if (inQuotes && nextChar === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (char === "," && !inQuotes) {
      values.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  values.push(current.trim());
  return values;
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  for (const line of lines) {
    rows.push(parseCsvLine(line));
  }
  return rows;
}

async function getActiveFormDefinition(env: Env, formType: string) {
  const row = await env.DB.prepare(
    `SELECT id, type, version, schema_json
     FROM form_definition
     WHERE type = ? AND is_active = 1
     ORDER BY version DESC
     LIMIT 1`
  ).bind(formType).first();
  return row;
}

async function verifyAuthPayload(request: Request, env: Env) {
  const body = await parseJson<{ provider: AuthProvider; id_token: string }>(request);
  const provider = body.provider;
  if (!provider || !body.id_token) {
    throw new AppError("validation_error", 400, { provider: "required", id_token: "required" });
  }
  if (!["google", "apple", "line"].includes(provider)) {
    throw new AppError("validation_error", 400, { provider: "invalid" });
  }
  const profile = await verifyIdToken(provider, body.id_token, env);
  return { provider, profile };
}

async function verifyAuth(request: Request, env: Env) {
  const { provider, profile } = await verifyAuthPayload(request, env);
  return jsonResponse({
    data: {
      provider,
      provider_sub: profile.sub,
      email: profile.email,
      name: profile.name,
    },
  });
}

async function loginAuth(request: Request, env: Env) {
  const { provider, profile } = await verifyAuthPayload(request, env);
  const authRow = await env.DB.prepare(
    `SELECT id, patient_id, bound_status
     FROM patient_auth
     WHERE provider = ? AND provider_sub = ?`
  ).bind(provider, profile.sub).first();

  if (!authRow) {
    return jsonResponse({
      data: {
        status: "unbound",
        provider,
        provider_sub: profile.sub,
        email: profile.email,
        name: profile.name,
      },
    });
  }

  const sessionToken = await createPatientSession(env, {
    patientId: authRow.patient_id as string,
    provider,
    providerSub: profile.sub,
    boundStatus: authRow.bound_status as string,
  });

  return jsonResponse({
    data: {
      status: authRow.bound_status,
      provider,
      provider_sub: profile.sub,
      patient_id: authRow.patient_id,
      session_token: sessionToken,
    },
  });
}

async function bindAuth(request: Request, env: Env) {
  const body = await parseJson<{
    provider: AuthProvider;
    provider_sub: string;
    national_id: string;
    dob: string;
    display_name?: string;
    phone?: string;
    email?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.provider || !body.provider_sub) {
    throw new AppError("validation_error", 400, { provider: "required", provider_sub: "required" });
  }
  if (!["google", "apple", "line"].includes(body.provider)) {
    throw new AppError("validation_error", 400, { provider: "invalid" });
  }
  const normalizedId = normalizeTWId(body.national_id ?? "");
  if (!isValidTWId(normalizedId, true)) {
    throw new AppError("validation_error", 400, { national_id: "invalid" });
  }
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(body.dob || "")) {
    throw new AppError("validation_error", 400, { dob: "invalid" });
  }
  if (!body.phone && !body.email) {
    throw new AppError("validation_error", 400, { contact: "required" });
  }

  const identityRow = await env.DB.prepare(
    `SELECT patient_id, dob FROM patient_identity WHERE national_id = ?`
  ).bind(normalizedId).first();

  let patientId = identityRow?.patient_id as string | null;
  if (identityRow && identityRow.dob !== body.dob) {
    throw new AppError("validation_error", 400, { dob: "mismatch" });
  }

  const now = Date.now();
  if (!patientId) {
    const orgRow = await env.DB.prepare(`SELECT id FROM org ORDER BY created_at LIMIT 1`).first();
    if (!orgRow) {
      throw new AppError("validation_error", 400, { org_id: "missing" });
    }
    patientId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO patient (id, org_id, display_name, gender, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      patientId,
      orgRow.id,
      body.display_name ?? null,
      null,
      now,
      now
    ).run();

    await env.DB.prepare(
      `INSERT INTO patient_identity (patient_id, national_id, dob, verified_level, created_at, updated_at)
       VALUES (?, ?, ?, 0, ?, ?)`
    ).bind(patientId, normalizedId, body.dob, now, now).run();
  }

  if (body.phone) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO patient_contact
         (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
       VALUES (?, (SELECT org_id FROM patient WHERE id = ?), ?, 'phone', ?, 1, 0, ?)`
    ).bind(crypto.randomUUID(), patientId, patientId, body.phone, now).run();
  }

  if (body.email) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO patient_contact
         (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
       VALUES (?, (SELECT org_id FROM patient WHERE id = ?), ?, 'email', ?, ?, 0, ?)`
    ).bind(
      crypto.randomUUID(),
      patientId,
      patientId,
      body.email,
      body.phone ? 0 : 1,
      now
    ).run();
  }

  const existingAuth = await env.DB.prepare(
    `SELECT id, patient_id, bound_status
     FROM patient_auth
     WHERE provider = ? AND provider_sub = ?`
  ).bind(body.provider, body.provider_sub).first();

  let boundStatus = "pending_review";
  let authId = existingAuth?.id as string | null;
  if (existingAuth) {
    if (existingAuth.patient_id !== patientId) {
      throw new AppError("conflict", 409, { provider_sub: "bound_to_other" });
    }
    boundStatus = existingAuth.bound_status as string;
  } else {
    authId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO patient_auth (id, patient_id, provider, provider_sub, bound_status, created_at)
       VALUES (?, ?, ?, ?, 'pending_review', ?)`
    ).bind(authId, patientId, body.provider, body.provider_sub, now).run();
  }

  const sessionToken = await createPatientSession(env, {
    patientId,
    provider: body.provider,
    providerSub: body.provider_sub,
    boundStatus,
  });

  const patientOrg = await getPatientOrg(env, patientId);
  if (patientOrg) {
    await writeAuditLog(env, {
      orgId: patientOrg.orgId,
      clinicId: null,
      actorType: "patient",
      action: "create",
      entityTable: "patient_auth",
      entityId: authId ?? "",
      after: {
        provider: body.provider,
        provider_sub: body.provider_sub,
        status: boundStatus,
      },
      requestId,
    });
  }

  return jsonResponse({
    data: {
      status: boundStatus,
      patient_id: patientId,
      session_token: sessionToken,
    },
  });
}

async function getPatientProfile(request: Request, env: Env) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }

  const authRow = await env.DB.prepare(
    `SELECT bound_status
     FROM patient_auth
     WHERE patient_id = ? AND provider = ? AND provider_sub = ?`
  ).bind(session.patientId, session.provider, session.providerSub).first();

  let boundStatus = session.boundStatus;
  if (authRow?.bound_status && authRow.bound_status !== boundStatus) {
    boundStatus = authRow.bound_status as string;
    const token = getPatientToken(request);
    if (token) {
      const tokenHash = await hashValue(token);
      await env.DB.prepare(
        `UPDATE patient_session
         SET bound_status = ?
         WHERE token_hash = ?`
      ).bind(boundStatus, tokenHash).run();
    }
  }

  const patient = await env.DB.prepare(
    `SELECT id, display_name, created_at
     FROM patient
     WHERE id = ?`
  ).bind(session.patientId).first();

  if (!patient) {
    throw new AppError("not_found", 404, { patient_id: "not_found" });
  }

  const identity = await env.DB.prepare(
    `SELECT national_id, dob
     FROM patient_identity
     WHERE patient_id = ?`
  ).bind(session.patientId).first();

  const contacts = await env.DB.prepare(
    `SELECT type, value, is_primary
     FROM patient_contact
     WHERE patient_id = ?
     ORDER BY is_primary DESC, created_at ASC`
  ).bind(session.patientId).all();

  const restriction = await env.DB.prepare(
    `SELECT no_show_count_recent, locked_until, lock_reason
     FROM patient_restriction
     WHERE patient_id = ?`
  ).bind(session.patientId).first();

  return jsonResponse({
    data: {
      patient_id: patient.id,
      display_name: patient.display_name,
      national_id: identity?.national_id ?? null,
      dob: identity?.dob ?? null,
      contacts: contacts.results ?? [],
      bound_status: boundStatus,
      restriction: restriction ?? null,
    },
  });
}

async function listPatientAppointments(request: Request, env: Env, url: URL) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }
  if (session.boundStatus !== "approved") {
    throw new AppError("forbidden", 403, { bound_status: session.boundStatus });
  }

  const limit = Math.min(Number(url.searchParams.get("limit") ?? 20), 50);
  const result = await env.DB.prepare(
    `SELECT appointment.id, appointment.status, appointment.queue_no, appointment.service_date_local,
            appointment.booking_ref, slot.start_at_utc, provider.name AS provider_name,
            provider.title AS provider_title, clinic.name AS clinic_name, clinic.id AS clinic_id,
            clinic_notice.content AS clinic_notice
     FROM appointment
     JOIN slot ON slot.id = appointment.slot_id
     JOIN provider ON provider.id = appointment.provider_id
     JOIN clinic ON clinic.id = appointment.clinic_id
     LEFT JOIN clinic_notice ON clinic_notice.clinic_id = clinic.id
     WHERE appointment.patient_id = ?
     ORDER BY appointment.service_date_local DESC, slot.start_at_utc DESC
     LIMIT ?`
  ).bind(session.patientId, limit).all();

  return jsonResponse({ data: result.results ?? [] });
}

async function cancelAppointmentByPatient(request: Request, env: Env, appointmentId: string) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }
  if (session.boundStatus !== "approved") {
    throw new AppError("forbidden", 403, { bound_status: session.boundStatus });
  }

  const appointment = await env.DB.prepare(
    `SELECT id, patient_id, status, org_id, clinic_id
     FROM appointment
     WHERE id = ?`
  ).bind(appointmentId).first();

  if (!appointment) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }

  if (appointment.patient_id !== session.patientId) {
    throw new AppError("forbidden", 403);
  }

  const stub = await getBookingStubByAppointment(env, appointmentId);
  const result = await stub.cancelBooking({ appointmentId, now: Date.now() });

  await writeAuditLog(env, {
    orgId: appointment.org_id as string,
    clinicId: (appointment.clinic_id as string) ?? null,
    actorType: "patient",
    action: "cancel",
    entityTable: "appointment",
    entityId: appointmentId,
    before: { status: appointment.status },
    after: { status: result.status, cancelled_at: result.cancelledAt },
    requestId: getRequestId(request),
  });

  return jsonResponse({ data: { status: result.status, cancelled_at: result.cancelledAt } });
}

async function getClinicNotice(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  if (!clinicId) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  const row = await env.DB.prepare(
    `SELECT clinic_id, content, updated_at
     FROM clinic_notice
     WHERE clinic_id = ?`
  ).bind(clinicId).first();

  if (!row) {
    return jsonResponse({
      data: {
        clinic_id: clinicId,
        content: "Please bring your health card and arrive 10 minutes early.",
      },
    });
  }
  return jsonResponse({ data: row });
}

async function upsertClinicNotice(request: Request, env: Env) {
  const body = await parseJson<{ clinic_id: string; content: string }>(request);
  const requestId = getRequestId(request);
  if (!body.clinic_id || !body.content) {
    throw new AppError("validation_error", 400, { clinic_id: "required", content: "required" });
  }

  const clinicInfo = await getClinicOrg(env, body.clinic_id);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO clinic_notice (clinic_id, content, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(clinic_id)
     DO UPDATE SET content = ?, updated_at = ?`
  ).bind(body.clinic_id, body.content, now, body.content, now).run();

  await writeAuditLog(env, {
    orgId: clinicInfo.orgId,
    clinicId: body.clinic_id,
    actorType: "staff",
    action: "update",
    entityTable: "clinic_notice",
    entityId: body.clinic_id,
    after: { content: body.content },
    requestId,
  });

  return jsonResponse({ data: { clinic_id: body.clinic_id } });
}

async function getPublicFormDefinition(env: Env, url: URL) {
  const formType = url.searchParams.get("type");
  if (!formType) {
    throw new AppError("validation_error", 400, { type: "required" });
  }
  const form = await getActiveFormDefinition(env, formType);
  if (!form) {
    throw new AppError("not_found", 404, { form: "not_found" });
  }
  return jsonResponse({ data: form });
}

async function getPatientFormSubmission(request: Request, env: Env, url: URL) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }
  if (session.boundStatus !== "approved") {
    throw new AppError("forbidden", 403, { bound_status: session.boundStatus });
  }
  const formType = url.searchParams.get("type");
  if (!formType) {
    throw new AppError("validation_error", 400, { type: "required" });
  }

  const row = await env.DB.prepare(
    `SELECT form_submission.id, form_submission.data_json, form_submission.updated_at, form_definition.type, form_definition.version AS form_version
     FROM form_submission
     JOIN form_definition ON form_definition.id = form_submission.form_definition_id
     WHERE form_submission.patient_id = ? AND form_definition.type = ?
     ORDER BY form_submission.updated_at DESC
     LIMIT 1`
  ).bind(session.patientId, formType).first();

  return jsonResponse({ data: row ?? null });
}

async function submitPatientForm(request: Request, env: Env) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }
  if (session.boundStatus !== "approved") {
    throw new AppError("forbidden", 403, { bound_status: session.boundStatus });
  }
  const body = await parseJson<{
    type: string;
    data: Record<string, unknown>;
    appointment_id?: string;
    submission_id?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.type || !body.data) {
    throw new AppError("validation_error", 400, { type: "required", data: "required" });
  }

  const form = await getActiveFormDefinition(env, body.type);
  if (!form) {
    throw new AppError("not_found", 404, { form: "not_found" });
  }

  const now = Date.now();
  if (body.submission_id) {
    const existing = await env.DB.prepare(
      `SELECT id, patient_id FROM form_submission WHERE id = ?`
    ).bind(body.submission_id).first();
    if (!existing) {
      throw new AppError("not_found", 404, { submission_id: "not_found" });
    }
    if (existing.patient_id !== session.patientId) {
      throw new AppError("forbidden", 403);
    }
    await env.DB.prepare(
      `UPDATE form_submission
       SET data_json = ?, updated_at = ?
       WHERE id = ?`
    ).bind(JSON.stringify(body.data), now, body.submission_id).run();

    const patientOrg = await getPatientOrg(env, session.patientId);
    if (patientOrg) {
      await writeAuditLog(env, {
        orgId: patientOrg.orgId,
        clinicId: null,
        actorType: "patient",
        action: "update",
        entityTable: "form_submission",
        entityId: body.submission_id,
        requestId,
      });
    }

    return jsonResponse({ data: { id: body.submission_id } });
  }

  const submissionId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO form_submission
      (id, patient_id, appointment_id, form_definition_id, data_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    submissionId,
    session.patientId,
    body.appointment_id ?? null,
    form.id,
    JSON.stringify(body.data),
    now,
    now
  ).run();

  const patientOrg = await getPatientOrg(env, session.patientId);
  if (patientOrg) {
    await writeAuditLog(env, {
      orgId: patientOrg.orgId,
      clinicId: null,
      actorType: "patient",
      action: "create",
      entityTable: "form_submission",
      entityId: submissionId,
      requestId,
    });
  }

  return jsonResponse({ data: { id: submissionId } }, { status: 201 });
}

async function listFormDefinitionsAdmin(request: Request, env: Env, url: URL) {
  const staff = await getStaffContext(request, env);
  const formType = url.searchParams.get("type");
  const where: string[] = [];
  const params: unknown[] = [];
  if (formType) {
    where.push("type = ?");
    params.push(formType);
  }
  const sql = `SELECT id, type, version, schema_json, is_active, created_at
               FROM form_definition
               ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
               ORDER BY type, version DESC`;
  const result = await env.DB.prepare(sql).bind(...params).all();
  void staff;
  return jsonResponse({ data: result.results ?? [] });
}

async function createFormDefinition(request: Request, env: Env) {
  const body = await parseJson<{ type: string; schema_json: string; is_active?: boolean }>(request);
  const requestId = getRequestId(request);
  const staff = await getStaffContext(request, env);
  if (!body.type || !body.schema_json) {
    throw new AppError("validation_error", 400, { type: "required", schema_json: "required" });
  }

  let schemaJson: string;
  try {
    schemaJson = JSON.stringify(JSON.parse(body.schema_json));
  } catch {
    throw new AppError("validation_error", 400, { schema_json: "invalid_json" });
  }

  const row = await env.DB.prepare(
    `SELECT MAX(version) as max_version FROM form_definition WHERE type = ?`
  ).bind(body.type).first();
  const nextVersion = Number(row?.max_version ?? 0) + 1;
  const id = crypto.randomUUID();
  const now = Date.now();
  const isActive = body.is_active ?? true;

  if (isActive) {
    await env.DB.prepare(
      `UPDATE form_definition SET is_active = 0 WHERE type = ?`
    ).bind(body.type).run();
  }

  await env.DB.prepare(
    `INSERT INTO form_definition (id, type, version, schema_json, is_active, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, body.type, nextVersion, schemaJson, isActive ? 1 : 0, now).run();

  await writeAuditLog(env, {
    orgId: staff.orgId ?? "system",
    clinicId: null,
    actorType: "staff",
    action: "create",
    entityTable: "form_definition",
    entityId: id,
    after: { type: body.type, version: nextVersion, is_active: isActive },
    requestId,
  });

  return jsonResponse({ data: { id, version: nextVersion } }, { status: 201 });
}

async function updateFormDefinition(request: Request, env: Env, id: string) {
  const body = await parseJson<{ is_active?: boolean }>(request);
  const requestId = getRequestId(request);
  const staff = await getStaffContext(request, env);
  if (typeof body.is_active !== "boolean") {
    throw new AppError("validation_error", 400, { is_active: "required" });
  }

  const existing = await env.DB.prepare(
    `SELECT id, type, is_active FROM form_definition WHERE id = ?`
  ).bind(id).first();
  if (!existing) {
    throw new AppError("not_found", 404, { form_definition: "not_found" });
  }

  if (!body.is_active) {
    const otherActive = await env.DB.prepare(
      `SELECT COUNT(*) as count
       FROM form_definition
       WHERE type = ? AND is_active = 1 AND id != ?`
    ).bind(existing.type, id).first();
    if (!Number(otherActive?.count)) {
      throw new AppError("conflict", 409, { is_active: "last_active" });
    }
  }

  if (body.is_active) {
    await env.DB.prepare(
      `UPDATE form_definition SET is_active = 0 WHERE type = ? AND id != ?`
    ).bind(existing.type, id).run();
  }

  await env.DB.prepare(
    `UPDATE form_definition SET is_active = ? WHERE id = ?`
  ).bind(body.is_active ? 1 : 0, id).run();

  await writeAuditLog(env, {
    orgId: staff.orgId ?? "system",
    clinicId: null,
    actorType: "staff",
    action: "update",
    entityTable: "form_definition",
    entityId: id,
    after: { is_active: body.is_active },
    requestId,
  });

  return jsonResponse({ data: { id, is_active: body.is_active } });
}

async function listFormSubmissionsAdmin(request: Request, env: Env, url: URL) {
  const patientId = url.searchParams.get("patient_id");
  const appointmentId = url.searchParams.get("appointment_id");
  if (!patientId && !appointmentId) {
    throw new AppError("validation_error", 400, { patient_id: "required_or_appointment_id" });
  }
  const where: string[] = [];
  const params: unknown[] = [];
  if (patientId) {
    where.push("form_submission.patient_id = ?");
    params.push(patientId);
  }
  if (appointmentId) {
    where.push("form_submission.appointment_id = ?");
    params.push(appointmentId);
  }

  const sql = `SELECT form_submission.id, form_submission.patient_id, form_submission.appointment_id,
                     form_submission.data_json, form_submission.updated_at, form_definition.type, form_definition.version AS form_version
               FROM form_submission
               JOIN form_definition ON form_definition.id = form_submission.form_definition_id
               ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
               ORDER BY form_submission.updated_at DESC
               LIMIT 100`;
  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function listPatientAuth(request: Request, env: Env, url: URL) {
  const staff = await getStaffContext(request, env);
  const status = url.searchParams.get("status");
  const where: string[] = [];
  const params: unknown[] = [];
  if (staff.orgId) {
    where.push("patient.org_id = ?");
    params.push(staff.orgId);
  }
  if (status) {
    where.push("patient_auth.bound_status = ?");
    params.push(status);
  }

  const sql = `SELECT patient_auth.id, patient_auth.provider, patient_auth.provider_sub, patient_auth.bound_status,
                     patient.id AS patient_id, patient.display_name, identity.national_id, identity.dob
              FROM patient_auth
              JOIN patient ON patient.id = patient_auth.patient_id
              LEFT JOIN patient_identity AS identity ON identity.patient_id = patient.id
              ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
              ORDER BY patient_auth.created_at DESC
              LIMIT 100`;

  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function updatePatientAuth(request: Request, env: Env, authId: string) {
  const body = await parseJson<{ bound_status: "approved" | "rejected" }>(request);
  const requestId = getRequestId(request);

  if (!body.bound_status || !["approved", "rejected"].includes(body.bound_status)) {
    throw new AppError("validation_error", 400, { bound_status: "invalid" });
  }

  const existing = await env.DB.prepare(
    `SELECT patient_auth.id, patient_auth.bound_status, patient_auth.patient_id, patient.org_id
     FROM patient_auth
     JOIN patient ON patient.id = patient_auth.patient_id
     WHERE patient_auth.id = ?`
  ).bind(authId).first();

  if (!existing) {
    throw new AppError("not_found", 404, { patient_auth: "not_found" });
  }

  await env.DB.prepare(
    `UPDATE patient_auth
     SET bound_status = ?
     WHERE id = ?`
  ).bind(body.bound_status, authId).run();

  await writeAuditLog(env, {
    orgId: existing.org_id as string,
    clinicId: null,
    actorType: "staff",
    action: "update",
    entityTable: "patient_auth",
    entityId: authId,
    before: { bound_status: existing.bound_status },
    after: { bound_status: body.bound_status },
    requestId,
  });

  return jsonResponse({ data: { id: authId, bound_status: body.bound_status } });
}

async function listMessageTemplates(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const channel = url.searchParams.get("channel");
  const locale = url.searchParams.get("locale");
  const includeVersions = url.searchParams.get("include_versions") === "1";
  if (!clinicId) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }

  const clinicInfo = await getClinicOrg(env, clinicId);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const where: string[] = ["org_id = ?"];
  const params: unknown[] = [clinicInfo.orgId];
  if (channel) {
    where.push("channel = ?");
    params.push(channel);
  }
  if (locale) {
    where.push("locale = ?");
    params.push(locale);
  }
  if (!includeVersions) {
    where.push("is_active = 1");
  }
  where.push("(clinic_id IS NULL OR clinic_id = ?)");
  params.push(clinicId);

  const result = await env.DB.prepare(
    `SELECT id, org_id, clinic_id, channel, name, subject, body, locale, version, is_active, created_at, updated_at
     FROM message_template
     WHERE ${where.join(" AND ")}
     ORDER BY name ASC, version DESC, created_at DESC`
  ).bind(...params).all();

  return jsonResponse({ data: result.results ?? [] });
}

async function createMessageTemplate(request: Request, env: Env) {
  const body = await parseJson<{
    clinic_id: string;
    channel: "email" | "line";
    name: string;
    subject?: string;
    body: string;
    locale?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.clinic_id) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!body.channel || !["email", "line"].includes(body.channel)) {
    throw new AppError("validation_error", 400, { channel: "invalid" });
  }
  if (!body.name) {
    throw new AppError("validation_error", 400, { name: "required" });
  }
  if (!body.body) {
    throw new AppError("validation_error", 400, { body: "required" });
  }

  const clinicInfo = await getClinicOrg(env, body.clinic_id);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const locale = body.locale?.trim() || "zh-TW";
  const versionRow = await env.DB.prepare(
    `SELECT MAX(version) AS max_version
     FROM message_template
     WHERE org_id = ? AND name = ? AND channel = ? AND locale = ?`
  ).bind(clinicInfo.orgId, body.name, body.channel, locale).first();
  const nextVersion = Number(versionRow?.max_version ?? 0) + 1;

  await env.DB.prepare(
    `UPDATE message_template
     SET is_active = 0
     WHERE org_id = ? AND name = ? AND channel = ? AND locale = ?`
  ).bind(clinicInfo.orgId, body.name, body.channel, locale).run();

  const now = Date.now();
  const id = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO message_template
      (id, org_id, clinic_id, channel, name, subject, body, locale, version, is_active, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
  ).bind(
    id,
    clinicInfo.orgId,
    body.clinic_id,
    body.channel,
    body.name,
    body.subject ?? null,
    body.body,
    locale,
    nextVersion,
    now,
    now
  ).run();

  await writeAuditLog(env, {
    orgId: clinicInfo.orgId,
    clinicId: body.clinic_id,
    actorType: "staff",
    action: "create",
    entityTable: "message_template",
    entityId: id,
    after: {
      id,
      channel: body.channel,
      name: body.name,
      subject: body.subject ?? null,
      body: body.body,
      locale,
      version: nextVersion,
    },
    requestId,
  });

  return jsonResponse({ data: { id, version: nextVersion } }, { status: 201 });
}

async function previewMessageTemplate(request: Request, env: Env) {
  const body = await parseJson<{
    template_id?: string;
    subject?: string;
    body?: string;
    payload?: Record<string, unknown>;
  }>(request);

  const payload = body.payload ?? {};
  let subject = body.subject ?? null;
  let content = body.body ?? null;

  if (body.template_id) {
    const template = await env.DB.prepare(
      `SELECT subject, body FROM message_template WHERE id = ?`
    ).bind(body.template_id).first();
    if (!template) {
      throw new AppError("not_found", 404, { template_id: "not_found" });
    }
    subject = template.subject as string | null;
    content = template.body as string | null;
  }

  if (!content) {
    throw new AppError("validation_error", 400, { body: "required" });
  }

  const renderedBody = renderTemplate(content, payload);
  const renderedSubject = subject ? renderTemplate(subject, payload) : null;

  return jsonResponse({
    data: {
      subject: renderedSubject,
      body: renderedBody,
    },
  });
}

async function sendEmail(env: Env, to: string, subject: string, message: string) {
  const provider = (env as Env & { EMAIL_PROVIDER?: string }).EMAIL_PROVIDER || "";
  if (provider === "resend") {
    const apiKey = (env as Env & { RESEND_API_KEY?: string }).RESEND_API_KEY;
    const from = (env as Env & { RESEND_FROM?: string }).RESEND_FROM;
    if (!apiKey || !from) throw new AppError("email_config_missing", 500);
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from,
        to,
        subject,
        text: message,
      }),
    });
    if (!response.ok) {
      throw new AppError("email_send_failed", 502);
    }
    return;
  }

  if (provider === "sendgrid") {
    const apiKey = (env as Env & { SENDGRID_API_KEY?: string }).SENDGRID_API_KEY;
    const from = (env as Env & { SENDGRID_FROM?: string }).SENDGRID_FROM;
    if (!apiKey || !from) throw new AppError("email_config_missing", 500);
    const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: from },
        subject,
        content: [{ type: "text/plain", value: message }],
      }),
    });
    if (!response.ok) {
      throw new AppError("email_send_failed", 502);
    }
    return;
  }

  if (provider === "postmark") {
    const apiKey = (env as Env & { POSTMARK_API_KEY?: string }).POSTMARK_API_KEY;
    const from = (env as Env & { POSTMARK_FROM?: string }).POSTMARK_FROM;
    if (!apiKey || !from) throw new AppError("email_config_missing", 500);
    const response = await fetch("https://api.postmarkapp.com/email", {
      method: "POST",
      headers: {
        "X-Postmark-Server-Token": apiKey,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        From: from,
        To: to,
        Subject: subject,
        TextBody: message,
      }),
    });
    if (!response.ok) {
      throw new AppError("email_send_failed", 502);
    }
    return;
  }

  throw new AppError("email_provider_missing", 500);
}

async function sendLine(env: Env, to: string, message: string) {
  const token = (env as Env & { LINE_CHANNEL_ACCESS_TOKEN?: string }).LINE_CHANNEL_ACCESS_TOKEN;
  if (!token) throw new AppError("line_config_missing", 500);
  const response = await fetch("https://api.line.me/v2/bot/message/push", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      to,
      messages: [{ type: "text", text: message }],
    }),
  });
  if (!response.ok) {
    throw new AppError("line_send_failed", 502);
  }
}
async function processNotificationJobsInternal(env: Env, limit: number, requestId: string) {
  const now = Date.now();
  const maxAttempts = 3;

  const jobs = await env.DB.prepare(
    `SELECT id, channel, patient_id, appointment_id, payload_json
     FROM notification_job
     WHERE status = 'queued' AND scheduled_at <= ?
     ORDER BY scheduled_at ASC
     LIMIT ?`
  ).bind(now, limit).all();

  let processed = 0;
  for (const job of jobs.results ?? []) {
    const attemptRow = await env.DB.prepare(
      `SELECT COUNT(1) AS attempts FROM notification_delivery WHERE job_id = ?`
    ).bind(job.id).first();
    const attempt = Number(attemptRow?.attempts ?? 0) + 1;
    const patientOrg = await getPatientOrg(env, job.patient_id);
    try {
      const payload = job.payload_json ? JSON.parse(job.payload_json) : {};
      const contact = payload.contact || await getContactValue(env, job.patient_id, job.channel);

      if (!contact) {
        throw new AppError("contact_missing", 400);
      }

      const message = payload.message || buildDefaultMessage(payload);
      const subject = payload.subject || "Appointment confirmed";

      if (job.channel === "email") {
        await sendEmail(env, contact, subject, message);
      } else if (job.channel === "line") {
        await sendLine(env, contact, message);
      } else {
        throw new AppError("channel_invalid", 400);
      }

      await env.DB.prepare(
        `UPDATE notification_job
         SET status = 'sent'
         WHERE id = ?`
      ).bind(job.id).run();

      await env.DB.prepare(
        `INSERT INTO notification_delivery
          (id, job_id, attempt, sent_at, status)
         VALUES (?, ?, ?, ?, 'success')`
      ).bind(crypto.randomUUID(), job.id, attempt, now).run();

      if (patientOrg) {
        await writeAuditLog(env, {
          orgId: patientOrg.orgId,
          clinicId: null,
          actorType: "system",
          action: "update",
          entityTable: "notification_job",
          entityId: job.id as string,
          before: { status: "queued" },
          after: { status: "sent" },
          requestId,
        });
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "send_failed";
      if (attempt < maxAttempts) {
        const backoffMs = Math.min(15 * 60 * 1000, Math.pow(2, attempt - 1) * 60 * 1000);
        await env.DB.prepare(
          `UPDATE notification_job
           SET status = 'queued', scheduled_at = ?
           WHERE id = ?`
        ).bind(now + backoffMs, job.id).run();

        await env.DB.prepare(
          `INSERT INTO notification_delivery
            (id, job_id, attempt, sent_at, status, error)
           VALUES (?, ?, ?, ?, 'temp_fail', ?)`
        ).bind(crypto.randomUUID(), job.id, attempt, now, errorMessage).run();

        if (patientOrg) {
          await writeAuditLog(env, {
            orgId: patientOrg.orgId,
            clinicId: null,
            actorType: "system",
            action: "retry",
            entityTable: "notification_job",
            entityId: job.id as string,
            before: { status: "queued" },
            after: { status: "queued", attempt, error: errorMessage },
            requestId,
          });
        }
      } else {
        await env.DB.prepare(
          `UPDATE notification_job
           SET status = 'failed'
           WHERE id = ?`
        ).bind(job.id).run();

        await env.DB.prepare(
          `INSERT INTO notification_delivery
            (id, job_id, attempt, sent_at, status, error)
           VALUES (?, ?, ?, ?, 'perm_fail', ?)`
        ).bind(crypto.randomUUID(), job.id, attempt, now, errorMessage).run();

        if (patientOrg) {
          await writeAuditLog(env, {
            orgId: patientOrg.orgId,
            clinicId: null,
            actorType: "system",
            action: "update",
            entityTable: "notification_job",
            entityId: job.id as string,
            before: { status: "queued" },
            after: { status: "failed", error: errorMessage },
            requestId,
          });
        }
      }
    }

    processed += 1;
  }

  return processed;
}

async function purgeOldRecords(env: Env, now: number) {
  const cutoff = now - 30 * 24 * 60 * 60 * 1000;
  await env.DB.prepare(`DELETE FROM audit_log WHERE created_at < ?`).bind(cutoff).run();
  await env.DB.prepare(`DELETE FROM notification_delivery WHERE sent_at IS NOT NULL AND sent_at < ?`).bind(cutoff).run();
}

async function processNotificationJobs(request: Request, env: Env) {
  const body = await parseJson<{ limit?: number }>(request);
  const requestId = getRequestId(request);
  const limit = Math.min(Math.max(body.limit ?? 10, 1), 50);
  const processed = await processNotificationJobsInternal(env, limit, requestId);
  return jsonResponse({ data: { processed } });
}

async function scheduleAppointmentReminders(env: Env, now: number, requestId: string) {
  const targetDate = getTaipeiDateString(new Date(now + 24 * 60 * 60 * 1000));
  const appointments = await env.DB.prepare(
    `SELECT appointment.id, appointment.patient_id, patient.display_name AS patient_name
     FROM appointment
     JOIN patient ON patient.id = appointment.patient_id
     WHERE appointment.service_date_local = ?
       AND appointment.status IN ('booked', 'checked_in')`
  ).bind(targetDate).all();

  for (const appointment of appointments.results ?? []) {
    let contacts = await env.DB.prepare(
      `SELECT type, value
       FROM patient_contact
       WHERE patient_id = ? AND is_primary = 1`
    ).bind(appointment.patient_id).all();

    if (!contacts.results?.length) {
      contacts = await env.DB.prepare(
        `SELECT type, value
         FROM patient_contact
         WHERE patient_id = ?`
      ).bind(appointment.patient_id).all();
    }

    const contactRows = filterNotificationContacts(contacts.results ?? []);

    for (const contact of contactRows) {

      const exists = await env.DB.prepare(
        `SELECT id FROM notification_job
         WHERE event_type = 'appointment_reminder'
           AND appointment_id = ?
           AND channel = ?`
      ).bind(appointment.id, contact.type).first();
      if (exists) continue;

      await env.DB.prepare(
        `INSERT INTO notification_job
          (id, event_type, channel, patient_id, appointment_id, payload_json, scheduled_at, status, created_at)
         VALUES (?, 'appointment_reminder', ?, ?, ?, ?, ?, 'queued', ?)`
      ).bind(
        crypto.randomUUID(),
        contact.type,
        appointment.patient_id,
        appointment.id,
        JSON.stringify({
          message: (() => {
            const name = (appointment as { patient_name?: string | null }).patient_name;
            const greeting = name ? `\u60a8\u597d ${name}` : `\u60a8\u597d`;
            return `${greeting}\uff0c\u63d0\u9192\u60a8 ${targetDate} \u6709\u9580\u8a3a\u9810\u7d04\uff0c\u8acb\u63d0\u524d\u5831\u5230\u3002`;
          })(),
          subject: "\u9580\u8a3a\u63d0\u9192",
          service_date_local: targetDate,
          patient_name: (appointment as { patient_name?: string | null }).patient_name ?? null,
          contact: contact.value,
        }),
        now,
        now
      ).run();
    }
  }

  if (appointments.results?.length) {
    const sample = appointments.results[0] as { patient_id: string };
    const patientOrg = await getPatientOrg(env, sample.patient_id);
    if (patientOrg) {
      await writeAuditLog(env, {
        orgId: patientOrg.orgId,
        clinicId: null,
        actorType: "system",
        action: "create",
        entityTable: "notification_job",
        entityId: `appointment_reminder:${targetDate}`,
        after: {
          service_date_local: targetDate,
          appointments: appointments.results?.length ?? 0,
        },
        requestId,
      });
    }
  }
}

async function createHold(request: Request, env: Env) {
  const body = await parseJson<{ slot_id: string; patient_provisional_key?: string }>(request);
  const slotId = body.slot_id;

  const stub = await getBookingStubBySlot(env, slotId);
  const result = await stub.createHold({
    slotId,
    patientProvisionalKey: body.patient_provisional_key,
    now: Date.now(),
  });

  return jsonResponse({
    data: {
      hold_token: result.holdToken,
      expires_at: result.expiresAt,
    },
  });
}

async function confirmBooking(request: Request, env: Env) {
  const body = await parseJson<{
    hold_token: string;
    national_id: string;
    dob: string;
    display_name?: string;
    phone?: string;
    email?: string;
    source?: string;
    turnstile_token?: string;
    email_verification_id?: string;
    email_verification_code?: string;
  }>(request);
  const requestId = getRequestId(request);
  const idempotencyKey = request.headers.get("x-idempotency-key") || undefined;
  const now = Date.now();

  const normalizedId = normalizeTWId(body.national_id ?? "");
  if (!isValidTWId(normalizedId, true)) {
    throw new AppError("validation_error", 400, { national_id: "invalid" });
  }
  const displayName = body.display_name?.trim() || "";
  if (!displayName) {
    throw new AppError("validation_error", 400, { display_name: "required" });
  }

  await verifyTurnstileOrEmail(request, env, {
    turnstileToken: body.turnstile_token,
    email: body.email,
    emailVerificationId: body.email_verification_id,
    emailVerificationCode: body.email_verification_code,
    purpose: "booking",
    now,
  });

  const ip = getClientIp(request) ?? "unknown";
  const deviceId = request.headers.get("x-device-id") || "na";
  const contactValue = body.phone || body.email || "";
  const contactHash = contactValue ? await hashValue(contactValue) : "none";
  await checkRateLimit(env, `rl:booking:${ip}:${deviceId}:${contactHash}`, 10, 15 * 60 * 1000);

  const existingIdentity = await env.DB.prepare(
    `SELECT patient_id
     FROM patient_identity
     WHERE national_id = ? AND dob = ?`
  ).bind(normalizedId, body.dob).first();
  if (existingIdentity?.patient_id) {
    const restriction = await env.DB.prepare(
      `SELECT no_show_count_recent, locked_until
       FROM patient_restriction
       WHERE patient_id = ?`
    ).bind(existingIdentity.patient_id).first();

    const lockedUntil = restriction?.locked_until ? Number(restriction.locked_until) : null;
    if (lockedUntil) {
      throw new AppError("patient_locked", 403, { locked_until: lockedUntil });
    }
  }

  const stub = await getBookingStubByHold(env, body.hold_token);
  const result = await stub.confirmBooking({
    holdToken: body.hold_token,
    nationalId: normalizedId,
    dob: body.dob,
    displayName,
    phone: body.phone,
    email: body.email,
    source: body.source,
    idempotencyKey: idempotencyKey || undefined,
    now,
  });

  const apptInfo = await getAppointmentOrgClinic(env, result.appointmentId);
  if (apptInfo) {
    await writeAuditLog(env, {
      orgId: apptInfo.orgId,
      clinicId: apptInfo.clinicId,
      actorType: "patient",
      action: "create",
      entityTable: "appointment",
      entityId: result.appointmentId,
      after: {
        booking_ref: result.bookingRef,
        queue_no: result.queueNo,
        status: result.status,
        service_date_local: result.serviceDateLocal,
      },
      requestId,
    });
  }

  const appointmentRow = await env.DB.prepare(
    `SELECT appointment.patient_id, patient.display_name
     FROM appointment
     JOIN patient ON patient.id = appointment.patient_id
     WHERE appointment.id = ?`
  ).bind(result.appointmentId).first();

  const patientId = appointmentRow?.patient_id as string | undefined;
  if (patientId) {
    let contacts = await env.DB.prepare(
      `SELECT type, value
       FROM patient_contact
       WHERE patient_id = ? AND is_primary = 1`
    ).bind(patientId).all();
    if (!contacts.results?.length) {
      contacts = await env.DB.prepare(
        `SELECT type, value
         FROM patient_contact
         WHERE patient_id = ?`
      ).bind(patientId).all();
    }

    const fallbackContacts = [];
    if (body.email) fallbackContacts.push({ type: "email", value: body.email });
    const contactRows = filterNotificationContacts((contacts.results?.length ? contacts.results : fallbackContacts) as Array<{ type: string; value: string }>);

    const patientName = (appointmentRow?.display_name as string | null) || displayName || null;
    const maskedId = maskNationalId(normalizedId);
    const greeting = patientName ? `\u60a8\u597d ${patientName}` : `\u60a8\u597d`;
    const idText = maskedId ? `\u8eab\u5206\u8b49\uff1a${maskedId}` : "";
    const message = `${greeting}\uff0c\u9580\u8a3a\u9810\u7d04\u5df2\u5b8c\u6210\u3002\u65e5\u671f\uff1a${result.serviceDateLocal}\uff0c\u67e5\u8a62\u78bc\uff1a${result.bookingRef}\u3002${idText ? ` ${idText}` : ""}`;
    const subject = "\u9580\u8a3a\u9810\u7d04\u78ba\u8a8d";
    const baseUrl = env.PUBLIC_BASE_URL || "";
    const contactParam = body.email
      ? `email=${encodeURIComponent(body.email)}`
      : body.phone
        ? `phone=${encodeURIComponent(body.phone)}`
        : "";
    const calendarUrl = baseUrl && contactParam
      ? `${baseUrl}/api/v1/public/appointments/${result.bookingRef}/calendar?dob=${encodeURIComponent(body.dob)}&${contactParam}`
      : null;
    for (const contact of contactRows) {

      await env.DB.prepare(
        `INSERT INTO notification_job
          (id, event_type, channel, patient_id, appointment_id, payload_json, scheduled_at, status, created_at)
         VALUES (?, 'booking_confirm', ?, ?, ?, ?, ?, 'queued', ?)`
      ).bind(
        crypto.randomUUID(),
        contact.type,
        patientId,
        result.appointmentId,
        JSON.stringify({
          message,
          subject,
          service_date_local: result.serviceDateLocal,
          booking_ref: result.bookingRef,
          patient_name: patientName,
          national_id_masked: maskedId,
          calendar_url: calendarUrl,
          contact: contact.value,
        }),
        now,
        now
      ).run();
    }
  }

  return jsonResponse({
    data: {
      appointment_id: result.appointmentId,
      booking_ref: result.bookingRef,
      queue_no: result.queueNo,
      status: result.status,
      service_date_local: result.serviceDateLocal,
    },
  });
}

async function lookupAppointment(env: Env, url: URL, bookingRef: string) {
  const dob = url.searchParams.get("dob");
  const phone = url.searchParams.get("phone");
  const email = url.searchParams.get("email");

  if (!dob) {
    throw new AppError("validation_error", 400, { dob: "required" });
  }
  if (!phone && !email) {
    throw new AppError("validation_error", 400, { contact: "required" });
  }

  const normalizedRef = normalizeBookingRef(bookingRef);
  if (!isValidBookingRef(normalizedRef)) {
    throw new AppError("validation_error", 400, { booking_ref: "invalid" });
  }

  const contactConditions: string[] = [];
  const params: unknown[] = [normalizedRef, dob];

  if (phone) {
    contactConditions.push("pc_phone.value = ?");
    params.push(phone);
  }
  if (email) {
    contactConditions.push("pc_email.value = ?");
    params.push(email);
  }

  const sql = `SELECT appointment.id, appointment.status, appointment.queue_no,
                     appointment.service_date_local, appointment.provider_id, appointment.clinic_id
              FROM appointment
              JOIN patient_identity ON appointment.patient_id = patient_identity.patient_id
              LEFT JOIN patient_contact pc_phone
                ON appointment.patient_id = pc_phone.patient_id AND pc_phone.type = 'phone'
              LEFT JOIN patient_contact pc_email
                ON appointment.patient_id = pc_email.patient_id AND pc_email.type = 'email'
              WHERE appointment.booking_ref = ?
                AND patient_identity.dob = ?
                AND (${contactConditions.join(" OR ")})
              LIMIT 1`;

  const row = await env.DB.prepare(sql).bind(...params).first();
  if (!row) {
    throw new AppError("not_found", 404, { booking_ref: "not_found" });
  }

  return jsonResponse({ data: row });
}

async function cancelAppointment(request: Request, env: Env, bookingRef: string) {
  const body = await parseJson<{ dob: string; phone?: string; email?: string }>(request);
  const requestId = getRequestId(request);
  const dob = body.dob;
  const phone = body.phone;
  const email = body.email;

  if (!dob) {
    throw new AppError("validation_error", 400, { dob: "required" });
  }
  if (!phone && !email) {
    throw new AppError("validation_error", 400, { contact: "required" });
  }

  const normalizedRef = normalizeBookingRef(bookingRef);
  if (!isValidBookingRef(normalizedRef)) {
    throw new AppError("validation_error", 400, { booking_ref: "invalid" });
  }

  const contactConditions: string[] = [];
  const params: unknown[] = [normalizedRef, dob];

  if (phone) {
    contactConditions.push("pc_phone.value = ?");
    params.push(phone);
  }
  if (email) {
    contactConditions.push("pc_email.value = ?");
    params.push(email);
  }

  const sql = `SELECT appointment.id
              FROM appointment
              JOIN patient_identity ON appointment.patient_id = patient_identity.patient_id
              LEFT JOIN patient_contact pc_phone
                ON appointment.patient_id = pc_phone.patient_id AND pc_phone.type = 'phone'
              LEFT JOIN patient_contact pc_email
                ON appointment.patient_id = pc_email.patient_id AND pc_email.type = 'email'
              WHERE appointment.booking_ref = ?
                AND patient_identity.dob = ?
                AND (${contactConditions.join(" OR ")})
              LIMIT 1`;

  const row = await env.DB.prepare(sql).bind(...params).first();
  if (!row) {
    throw new AppError("not_found", 404, { booking_ref: "not_found" });
  }

  const before = await env.DB.prepare(
    `SELECT status, org_id, clinic_id FROM appointment WHERE id = ?`
  ).bind(row.id as string).first();

  const stub = await getBookingStubByAppointment(env, row.id as string);
  const result = await stub.cancelBooking({ appointmentId: row.id as string, now: Date.now() });

  if (before?.org_id) {
    await writeAuditLog(env, {
      orgId: before.org_id as string,
      clinicId: (before.clinic_id as string) ?? null,
      actorType: "patient",
      action: "cancel",
      entityTable: "appointment",
      entityId: row.id as string,
      before: { status: before.status },
      after: { status: result.status, cancelled_at: result.cancelledAt },
      requestId,
    });
  }

  return jsonResponse({ data: result });
}

async function getPublicAppointmentDetails(
  env: Env,
  bookingRef: string,
  dob: string,
  phone?: string,
  email?: string
) {
  if (!dob) {
    throw new AppError("validation_error", 400, { dob: "required" });
  }
  if (!phone && !email) {
    throw new AppError("validation_error", 400, { contact: "required" });
  }

  const normalizedRef = normalizeBookingRef(bookingRef);
  if (!isValidBookingRef(normalizedRef)) {
    throw new AppError("validation_error", 400, { booking_ref: "invalid" });
  }

  const contactConditions: string[] = [];
  const params: unknown[] = [normalizedRef, dob];

  if (phone) {
    contactConditions.push("pc_phone.value = ?");
    params.push(phone);
  }
  if (email) {
    contactConditions.push("pc_email.value = ?");
    params.push(email);
  }

  const sql = `SELECT appointment.id, appointment.booking_ref, appointment.status,
                     appointment.service_date_local, appointment.queue_no, appointment.patient_id,
                     appointment.provider_id, appointment.clinic_id,
                     slot.start_at_utc, slot.end_at_utc,
                     clinic.name AS clinic_name, clinic.address AS clinic_address,
                     provider.name AS provider_name, provider.title AS provider_title
              FROM appointment
              JOIN patient_identity ON appointment.patient_id = patient_identity.patient_id
              LEFT JOIN patient_contact pc_phone
                ON appointment.patient_id = pc_phone.patient_id AND pc_phone.type = 'phone'
              LEFT JOIN patient_contact pc_email
                ON appointment.patient_id = pc_email.patient_id AND pc_email.type = 'email'
              JOIN slot ON slot.id = appointment.slot_id
              JOIN clinic ON clinic.id = appointment.clinic_id
              JOIN provider ON provider.id = appointment.provider_id
              WHERE appointment.booking_ref = ?
                AND patient_identity.dob = ?
                AND (${contactConditions.join(" OR ")})
              LIMIT 1`;

  const row = await env.DB.prepare(sql).bind(...params).first();
  if (!row) {
    throw new AppError("not_found", 404, { booking_ref: "not_found" });
  }

  return row;
}

async function getAppointmentCalendar(env: Env, url: URL, bookingRef: string) {
  const dob = url.searchParams.get("dob") || "";
  const phone = url.searchParams.get("phone") || undefined;
  const email = url.searchParams.get("email") || undefined;

  const row = await getPublicAppointmentDetails(env, bookingRef, dob, phone, email);
  const summary = `${row.clinic_name || "Clinic"} ${row.provider_name || ""}`.trim();
  const description = `Booking ref: ${row.booking_ref}`;
  const ics = buildIcsCalendar({
    uid: `${row.booking_ref}@clinic-booking`,
    summary,
    description,
    location: row.clinic_address ?? null,
    startAtUtc: Number(row.start_at_utc),
    endAtUtc: Number(row.end_at_utc),
  });

  return calendarResponse(ics, `appointment-${row.booking_ref}.ics`);
}

async function getMemberAppointmentCalendar(request: Request, env: Env, appointmentId: string) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }
  if (session.boundStatus !== "approved") {
    throw new AppError("forbidden", 403, { bound_status: session.boundStatus });
  }

  const row = await env.DB.prepare(
    `SELECT appointment.id, appointment.booking_ref, appointment.status,
            appointment.service_date_local, appointment.queue_no,
            slot.start_at_utc, slot.end_at_utc,
            clinic.name AS clinic_name, clinic.address AS clinic_address,
            provider.name AS provider_name, provider.title AS provider_title
     FROM appointment
     JOIN slot ON slot.id = appointment.slot_id
     JOIN clinic ON clinic.id = appointment.clinic_id
     JOIN provider ON provider.id = appointment.provider_id
     WHERE appointment.id = ? AND appointment.patient_id = ?`
  ).bind(appointmentId, session.patientId).first();

  if (!row) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }

  const summary = `${row.clinic_name || "Clinic"} ${row.provider_name || ""}`.trim();
  const description = `Booking ref: ${row.booking_ref}`;
  const ics = buildIcsCalendar({
    uid: `${row.booking_ref}@clinic-booking`,
    summary,
    description,
    location: row.clinic_address ?? null,
    startAtUtc: Number(row.start_at_utc),
    endAtUtc: Number(row.end_at_utc),
  });

  return calendarResponse(ics, `appointment-${row.booking_ref}.ics`);
}

async function issueCheckinToken(env: Env, appointmentId: string, serviceDateLocal: string) {
  const now = Date.now();
  const endOfDay = getServiceDateEndUtc(serviceDateLocal);
  const expiresAt = Math.max(now + 60 * 60 * 1000, endOfDay);
  const rawToken = `${crypto.randomUUID().replace(/-/g, "")}${crypto.randomUUID().slice(0, 6)}`;
  const tokenHash = await hashValue(rawToken);

  await env.DB.prepare(
    `INSERT INTO appointment_checkin_token
      (id, appointment_id, token_hash, expires_at, created_at, used_at)
     VALUES (?, ?, ?, ?, ?, NULL)`
  ).bind(
    crypto.randomUUID(),
    appointmentId,
    tokenHash,
    expiresAt,
    now
  ).run();

  return { token: rawToken, expiresAt };
}

async function createCheckinTokenByBookingRef(request: Request, env: Env, bookingRef: string) {
  const body = await parseJson<{ dob: string; phone?: string; email?: string }>(request);
  const row = await getPublicAppointmentDetails(env, bookingRef, body.dob, body.phone, body.email);

  if (["cancelled", "done", "no_show"].includes(row.status as string)) {
    throw new AppError("conflict", 409, { status: "not_checkin" });
  }

  const { token, expiresAt } = await issueCheckinToken(env, row.id as string, row.service_date_local as string);
  return jsonResponse({ data: { checkin_token: token, expires_at: expiresAt } });
}

async function createCheckinTokenForMember(request: Request, env: Env, appointmentId: string) {
  const session = await getPatientSession(env, request);
  if (!session) {
    throw new AppError("unauthorized", 401);
  }
  if (session.boundStatus !== "approved") {
    throw new AppError("forbidden", 403, { bound_status: session.boundStatus });
  }

  const row = await env.DB.prepare(
    `SELECT id, status, service_date_local
     FROM appointment
     WHERE id = ? AND patient_id = ?`
  ).bind(appointmentId, session.patientId).first();

  if (!row) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }
  if (["cancelled", "done", "no_show"].includes(row.status as string)) {
    throw new AppError("conflict", 409, { status: "not_checkin" });
  }

  const { token, expiresAt } = await issueCheckinToken(env, row.id as string, row.service_date_local as string);
  return jsonResponse({ data: { checkin_token: token, expires_at: expiresAt } });
}

async function checkinAppointmentByToken(request: Request, env: Env) {
  const body = await parseJson<{ token: string }>(request);
  if (!body.token) {
    throw new AppError("validation_error", 400, { token: "required" });
  }

  const now = Date.now();
  const tokenHash = await hashValue(body.token);
  const tokenRow = await env.DB.prepare(
    `SELECT id, appointment_id, used_at
     FROM appointment_checkin_token
     WHERE token_hash = ? AND expires_at > ?
     ORDER BY created_at DESC
     LIMIT 1`
  ).bind(tokenHash, now).first();

  if (!tokenRow) {
    throw new AppError("not_found", 404, { token: "not_found" });
  }

  const appointment = await env.DB.prepare(
    `SELECT id, status, patient_id, org_id, clinic_id
     FROM appointment
     WHERE id = ?`
  ).bind(tokenRow.appointment_id as string).first();

  if (!appointment) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }

  const currentStatus = appointment.status as string;
  if (["cancelled", "done", "no_show"].includes(currentStatus)) {
    throw new AppError("conflict", 409, { status: "not_checkin" });
  }

  let nextStatus = currentStatus;
  if (currentStatus === "booked") {
    nextStatus = "checked_in";
    await env.DB.prepare(
      `UPDATE appointment
       SET status = ?, updated_at = ?
       WHERE id = ?`
    ).bind(nextStatus, now, appointment.id).run();

    await env.DB.prepare(
      `INSERT INTO appointment_status_history
        (id, appointment_id, from_status, to_status, changed_by_type, changed_by_id, changed_at, meta)
       VALUES (?, ?, ?, ?, 'patient', ?, ?, NULL)`
    ).bind(
      crypto.randomUUID(),
      appointment.id,
      currentStatus,
      nextStatus,
      appointment.patient_id,
      now
    ).run();

    if (appointment.org_id) {
      await writeAuditLog(env, {
        orgId: appointment.org_id as string,
        clinicId: (appointment.clinic_id as string) ?? null,
        actorType: "patient",
        actorId: appointment.patient_id as string,
        action: "update",
        entityTable: "appointment",
        entityId: appointment.id as string,
        before: { status: currentStatus },
        after: { status: nextStatus },
      });
    }
  }

  if (!tokenRow.used_at) {
    await env.DB.prepare(
      `UPDATE appointment_checkin_token
       SET used_at = ?
       WHERE id = ?`
    ).bind(now, tokenRow.id as string).run();
  }

  return jsonResponse({ data: { appointment_id: appointment.id, status: nextStatus } });
}

async function listAppointments(env: Env, url: URL) {
  const bookingRef = url.searchParams.get("booking_ref");
  const clinicId = url.searchParams.get("clinic_id");
  const providerId = url.searchParams.get("provider_id");
  const serviceDate = url.searchParams.get("service_date_local");
  const status = url.searchParams.get("status");

  const where: string[] = [];
  const params: unknown[] = [];

  if (bookingRef) {
    where.push("appointment.booking_ref = ?");
    params.push(bookingRef);
  }
  if (clinicId) {
    where.push("appointment.clinic_id = ?");
    params.push(clinicId);
  }
  if (providerId) {
    where.push("appointment.provider_id = ?");
    params.push(providerId);
  }
  if (serviceDate) {
    where.push("appointment.service_date_local = ?");
    params.push(serviceDate);
  }
  if (status) {
    where.push("appointment.status = ?");
    params.push(status);
  }

  const orderBy = serviceDate ? "appointment.queue_no ASC" : "appointment.created_at DESC";
  const sql = `SELECT appointment.id, appointment.patient_id, appointment.provider_id, appointment.clinic_id,
                     appointment.service_date_local, appointment.queue_no, appointment.status, appointment.booking_ref,
                     patient.display_name AS patient_name
              FROM appointment
              JOIN patient ON appointment.patient_id = patient.id
              ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
              ORDER BY ${orderBy}
              LIMIT 50`;

  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

function escapeCsvValue(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, "\"\"")}"`;
  }
  return text;
}

async function exportAppointmentsCsv(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const providerId = url.searchParams.get("provider_id");
  const serviceDate = url.searchParams.get("service_date_local");

  if (!clinicId) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!serviceDate) {
    throw new AppError("validation_error", 400, { service_date_local: "required" });
  }

  const clinicInfo = await getClinicOrg(env, clinicId);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const where: string[] = ["appointment.clinic_id = ?", "appointment.service_date_local = ?"];
  const params: unknown[] = [clinicId, serviceDate];
  if (providerId) {
    where.push("appointment.provider_id = ?");
    params.push(providerId);
  }

  const sql = `SELECT appointment.service_date_local,
                     clinic.name AS clinic_name,
                     provider.name AS provider_name,
                     appointment.queue_no,
                     appointment.status,
                     appointment.booking_ref,
                     patient.display_name AS patient_name,
                     patient_identity.national_id,
                     patient_identity.dob,
                     (SELECT value
                        FROM patient_contact
                       WHERE patient_contact.patient_id = patient.id
                         AND patient_contact.type = 'phone'
                       ORDER BY is_primary DESC, created_at ASC
                       LIMIT 1) AS phone,
                     (SELECT value
                        FROM patient_contact
                       WHERE patient_contact.patient_id = patient.id
                         AND patient_contact.type = 'email'
                       ORDER BY is_primary DESC, created_at ASC
                       LIMIT 1) AS email
              FROM appointment
              JOIN patient ON patient.id = appointment.patient_id
              JOIN patient_identity ON patient_identity.patient_id = patient.id
              JOIN provider ON provider.id = appointment.provider_id
              JOIN clinic ON clinic.id = appointment.clinic_id
              WHERE ${where.join(" AND ")}
              ORDER BY appointment.queue_no ASC`;

  const result = await env.DB.prepare(sql).bind(...params).all();
  const rows = result.results ?? [];
  const headers = [
    "service_date_local",
    "clinic_name",
    "provider_name",
    "queue_no",
    "patient_name",
    "national_id",
    "dob",
    "phone",
    "email",
    "status",
    "booking_ref",
  ];

  const lines = [
    headers.join(","),
    ...rows.map((row) => {
      const data = row as Record<string, unknown>;
      return headers.map((header) => escapeCsvValue(data[header])).join(",");
    }),
  ];

  const filename = `appointments_${serviceDate}.csv`;
  const content = `\uFEFF${lines.join("\n")}`;
  return csvResponse(content, filename);
}

async function listRoles(env: Env) {
  const result = await env.DB.prepare(
    `SELECT id, scope, name FROM role ORDER BY name`
  ).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function createRole(request: Request, env: Env) {
  const body = await parseJson<{ clinic_id: string; name: string; scope?: string }>(request);
  const requestId = getRequestId(request);
  if (!body.clinic_id) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!body.name) {
    throw new AppError("validation_error", 400, { name: "required" });
  }

  const clinicInfo = await getClinicOrg(env, body.clinic_id);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const id = await ensureRole(env, body.name, body.scope ?? "org");
  await writeAuditLog(env, {
    orgId: clinicInfo.orgId,
    clinicId: body.clinic_id,
    actorType: "staff",
    action: "create",
    entityTable: "role",
    entityId: id,
    after: {
      id,
      name: body.name,
      scope: body.scope ?? "org",
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function listStaffUsers(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  if (!clinicId) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  const clinicInfo = await getClinicOrg(env, clinicId);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const result = await env.DB.prepare(
    `SELECT staff_user.id, staff_user.email, staff_user.name, staff_user.clinic_id, staff_user.is_active,
            GROUP_CONCAT(role.name, ',') AS roles
     FROM staff_user
     LEFT JOIN staff_user_role ON staff_user_role.staff_user_id = staff_user.id
     LEFT JOIN role ON role.id = staff_user_role.role_id
     WHERE staff_user.org_id = ?
       AND (staff_user.clinic_id IS NULL OR staff_user.clinic_id = ?)
     GROUP BY staff_user.id
     ORDER BY staff_user.created_at DESC`
  ).bind(clinicInfo.orgId, clinicId).all();

  const rows = (result.results ?? []).map((row) => ({
    ...row,
    roles: row.roles ? String(row.roles).split(",").filter(Boolean) : [],
  }));
  return jsonResponse({ data: rows });
}

async function createStaffUser(request: Request, env: Env) {
  const body = await parseJson<{
    clinic_id: string;
    email: string;
    name?: string;
    cf_subject?: string;
    roles?: string[];
  }>(request);
  const requestId = getRequestId(request);

  if (!body.clinic_id) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!body.email) {
    throw new AppError("validation_error", 400, { email: "required" });
  }

  const clinicInfo = await getClinicOrg(env, body.clinic_id);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const existing = await env.DB.prepare(
    `SELECT id FROM staff_user WHERE email = ?`
  ).bind(body.email).first();
  if (existing) {
    throw new AppError("conflict", 409, { email: "already_exists" });
  }

  const now = Date.now();
  const id = crypto.randomUUID();
  const cfSubject = body.cf_subject ?? body.email;

  await env.DB.prepare(
    `INSERT INTO staff_user
      (id, org_id, clinic_id, cf_subject, email, name, is_active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
  ).bind(
    id,
    clinicInfo.orgId,
    body.clinic_id,
    cfSubject,
    body.email,
    body.name ?? null,
    now
  ).run();

  const roleNames = (body.roles && body.roles.length)
    ? body.roles
    : ["staff"];
  await setStaffRoles(env, id, roleNames);

  await writeAuditLog(env, {
    orgId: clinicInfo.orgId,
    clinicId: body.clinic_id,
    actorType: "staff",
    action: "create",
    entityTable: "staff_user",
    entityId: id,
    after: {
      id,
      email: body.email,
      name: body.name ?? null,
      clinic_id: body.clinic_id,
      roles: roleNames,
    },
    requestId,
  });

  return jsonResponse({ data: { id } }, { status: 201 });
}

async function updateStaffUser(request: Request, env: Env, id: string) {
  const body = await parseJson<{
    clinic_id?: string;
    name?: string;
    is_active?: boolean;
    roles?: string[];
  }>(request);
  const requestId = getRequestId(request);

  const existing = await env.DB.prepare(
    `SELECT id, org_id, clinic_id, email, name, is_active
     FROM staff_user WHERE id = ?`
  ).bind(id).first();
  if (!existing) {
    throw new AppError("not_found", 404, { staff_user: "not_found" });
  }

  let clinicId = existing.clinic_id as string | null;
  let orgId = existing.org_id as string;
  if (body.clinic_id) {
    const clinicInfo = await getClinicOrg(env, body.clinic_id);
    if (!clinicInfo) {
      throw new AppError("not_found", 404, { clinic_id: "not_found" });
    }
    clinicId = body.clinic_id;
    orgId = clinicInfo.orgId;
  }

  await env.DB.prepare(
    `UPDATE staff_user
     SET org_id = ?, clinic_id = ?, name = ?, is_active = ?
     WHERE id = ?`
  ).bind(
    orgId,
    clinicId,
    body.name ?? existing.name ?? null,
    body.is_active === undefined ? existing.is_active : body.is_active ? 1 : 0,
    id
  ).run();

  if (body.roles) {
    await setStaffRoles(env, id, body.roles);
  }

  await writeAuditLog(env, {
    orgId,
    clinicId,
    actorType: "staff",
    action: "update",
    entityTable: "staff_user",
    entityId: id,
    before: existing,
    after: {
      id,
      clinic_id: clinicId,
      name: body.name ?? existing.name ?? null,
      is_active: body.is_active === undefined ? existing.is_active : body.is_active ? 1 : 0,
      roles: body.roles ?? undefined,
    },
    requestId,
  });

  return jsonResponse({ data: { id } });
}

function normalizeQueueNumbers(input: unknown): number[] {
  let values: Array<string | number> = [];
  if (Array.isArray(input)) {
    values = input as Array<string | number>;
  } else if (typeof input === "string") {
    values = input.split(/[,，\s]+/).filter(Boolean);
  }

  const numbers = values
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0);
  const unique = Array.from(new Set(numbers));
  unique.sort((a, b) => a - b);
  return unique;
}

function filterNotificationContacts(contacts: Array<{ type: string; value: string }>) {
  const emailContacts = contacts.filter((contact) => contact.type === "email");
  if (emailContacts.length) return emailContacts;
  return contacts.filter((contact) => contact.type === "line");
}

async function listQueueStatus(env: Env, url: URL) {
  const providerId = url.searchParams.get("provider_id");
  const serviceDate = url.searchParams.get("service_date_local");
  if (!providerId) {
    throw new AppError("validation_error", 400, { provider_id: "required" });
  }
  if (!serviceDate || !isValidDateString(serviceDate)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }

  const providerInfo = await getProviderOrgClinic(env, providerId);
  if (!providerInfo) {
    throw new AppError("not_found", 404, { provider_id: "not_found" });
  }

  const reservedResult = await env.DB.prepare(
    `SELECT queue_no
     FROM queue_reserved
     WHERE clinic_id = ? AND service_date_local = ?
     ORDER BY queue_no`
  ).bind(providerInfo.clinicId, serviceDate).all();
  const reservedQueue = (reservedResult.results ?? []).map((row) => Number(row.queue_no));
  const reservedSet = new Set(reservedQueue);

  const apptResult = await env.DB.prepare(
    `SELECT queue_no, status
     FROM appointment
     WHERE provider_id = ? AND service_date_local = ?
       AND status NOT IN ('cancelled', 'done', 'no_show')
     ORDER BY queue_no ASC`
  ).bind(providerId, serviceDate).all();

  const appointments = apptResult.results ?? [];
  const currentCandidates = appointments
    .filter((row) => row.status === "called" || row.status === "in_room")
    .map((row) => Number(row.queue_no));
  const currentQueueNo = currentCandidates.length ? Math.max(...currentCandidates) : null;

  let nextQueueNo: number | null = null;
  const startFrom = currentQueueNo ?? 0;
  for (const row of appointments) {
    const queueNo = Number(row.queue_no);
    if (queueNo <= startFrom) continue;
    if (reservedSet.has(queueNo)) continue;
    if (row.status === "booked" || row.status === "checked_in") {
      nextQueueNo = queueNo;
      break;
    }
  }

  const updatedRow = await env.DB.prepare(
    `SELECT MAX(updated_at) AS updated_at
     FROM appointment
     WHERE provider_id = ? AND service_date_local = ?`
  ).bind(providerId, serviceDate).first();

  return jsonResponse({
    data: {
      current_queue_no: currentQueueNo,
      next_queue_no: nextQueueNo,
      reserved_queue_no: reservedQueue,
      updated_at: updatedRow?.updated_at ? Number(updatedRow.updated_at) : null,
    },
  });
}

async function setReservedQueueNumbers(request: Request, env: Env) {
  const body = await parseJson<{
    clinic_id: string;
    service_date_local: string;
    queue_nos?: Array<number | string> | string;
    note?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.clinic_id) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!body.service_date_local || !isValidDateString(body.service_date_local)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }

  const clinicInfo = await getClinicOrg(env, body.clinic_id);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const queueNos = normalizeQueueNumbers(body.queue_nos ?? []);
  const now = Date.now();

  const statements = [
    env.DB.prepare(
      `DELETE FROM queue_reserved WHERE clinic_id = ? AND service_date_local = ?`
    ).bind(body.clinic_id, body.service_date_local),
    ...queueNos.map((queueNo) =>
      env.DB.prepare(
        `INSERT INTO queue_reserved
          (id, clinic_id, service_date_local, queue_no, note, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        crypto.randomUUID(),
        body.clinic_id,
        body.service_date_local,
        queueNo,
        body.note ?? null,
        now
      )
    ),
  ];
  await env.DB.batch(statements);

  await writeAuditLog(env, {
    orgId: clinicInfo.orgId,
    clinicId: clinicInfo.clinicId,
    actorType: "staff",
    action: "set_reserved",
    entityTable: "queue_reserved",
    entityId: `${body.clinic_id}:${body.service_date_local}`,
    after: {
      clinic_id: body.clinic_id,
      service_date_local: body.service_date_local,
      queue_nos: queueNos,
      note: body.note ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { queue_nos: queueNos } });
}

async function updateAppointmentStatus(request: Request, env: Env, appointmentId: string) {
  const body = await parseJson<{ to_status: string; note?: string; notify?: boolean }>(request);
  const requestId = getRequestId(request);
  if (!body.to_status) {
    throw new AppError("validation_error", 400, { to_status: "required" });
  }

  const appointment = await env.DB.prepare(
    `SELECT appointment.id, appointment.status, appointment.queue_no, appointment.patient_id,
            appointment.provider_id, appointment.clinic_id, appointment.org_id, appointment.service_date_local,
            patient.display_name AS patient_name
     FROM appointment
     JOIN patient ON appointment.patient_id = patient.id
     WHERE appointment.id = ?`
  ).bind(appointmentId).first();

  if (!appointment) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }

  const currentStatus = appointment.status as string;
  const toStatus = body.to_status;

  if (currentStatus === toStatus) {
    return jsonResponse({ data: { id: appointment.id, status: currentStatus } });
  }

  const transitions: Record<string, string[]> = {
    booked: ["checked_in", "called", "no_show", "cancelled"],
    checked_in: ["called", "in_room", "done", "no_show", "cancelled"],
    called: ["in_room", "done", "no_show", "cancelled"],
    in_room: ["done", "no_show", "cancelled"],
    done: [],
    no_show: [],
    cancelled: [],
  };

  if (!Object.prototype.hasOwnProperty.call(transitions, toStatus)) {
    throw new AppError("validation_error", 400, { to_status: "invalid" });
  }

  const allowed = transitions[currentStatus] ?? [];
  if (!allowed.includes(toStatus)) {
    throw new AppError("conflict", 409, { status: "transition_not_allowed" });
  }

  const now = Date.now();
  if (toStatus === "cancelled") {
    await env.DB.prepare(
      `UPDATE appointment
       SET status = ?, updated_at = ?, cancelled_at = ?
       WHERE id = ?`
    ).bind(toStatus, now, now, appointmentId).run();
  } else {
    await env.DB.prepare(
      `UPDATE appointment
       SET status = ?, updated_at = ?
       WHERE id = ?`
    ).bind(toStatus, now, appointmentId).run();
  }

  if (toStatus === "no_show") {
    const restriction = await env.DB.prepare(
      `SELECT no_show_count_recent, locked_until
       FROM patient_restriction
       WHERE patient_id = ?`
    ).bind(appointment.patient_id as string).first();

    const currentCount = Number(restriction?.no_show_count_recent ?? 0);
    const nextCount = currentCount + 1;
    const lockUntil = nextCount >= 3
      ? now
      : restriction?.locked_until ?? null;

    await env.DB.prepare(
      `INSERT INTO patient_restriction
        (patient_id, no_show_count_recent, locked_until, lock_reason, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(patient_id)
       DO UPDATE SET no_show_count_recent = ?, locked_until = ?, lock_reason = ?, updated_at = ?`
    ).bind(
      appointment.patient_id,
      nextCount,
      lockUntil,
      "no_show",
      now,
      nextCount,
      lockUntil,
      "no_show",
      now
    ).run();
  }

  await env.DB.prepare(
    `INSERT INTO appointment_status_history
      (id, appointment_id, from_status, to_status, changed_by_type, changed_by_id, changed_at, meta)
     VALUES (?, ?, ?, ?, 'staff', NULL, ?, ?)`
  ).bind(
    crypto.randomUUID(),
    appointmentId,
    currentStatus,
    toStatus,
    now,
    body.note ? JSON.stringify({ note: body.note }) : null
  ).run();

  if (toStatus === "called" && body.notify) {
    let contacts = await env.DB.prepare(
      `SELECT type, value
       FROM patient_contact
       WHERE patient_id = ? AND is_primary = 1`
    ).bind(appointment.patient_id as string).all();

    if (!contacts.results?.length) {
      contacts = await env.DB.prepare(
        `SELECT type, value
         FROM patient_contact
         WHERE patient_id = ?`
      ).bind(appointment.patient_id as string).all();
    }

    if (contacts.results?.length) {
      const providerRow = await env.DB.prepare(
        `SELECT name FROM provider WHERE id = ?`
      ).bind(appointment.provider_id as string).first();
      const clinicRow = await env.DB.prepare(
        `SELECT name FROM clinic WHERE id = ?`
      ).bind(appointment.clinic_id as string).first();

      const contactRows = filterNotificationContacts(contacts.results ?? []);

      for (const contact of contactRows) {

        const exists = await env.DB.prepare(
          `SELECT id FROM notification_job
           WHERE event_type = 'queue_called'
             AND appointment_id = ?
             AND channel = ?`
        ).bind(appointment.id, contact.type).first();
        if (exists) continue;

        await env.DB.prepare(
          `INSERT INTO notification_job
            (id, event_type, channel, patient_id, appointment_id, payload_json, scheduled_at, status, created_at)
           VALUES (?, 'queue_called', ?, ?, ?, ?, ?, 'queued', ?)`
        ).bind(
          crypto.randomUUID(),
          contact.type,
          appointment.patient_id,
          appointment.id,
          JSON.stringify({
            reason: "叫號通知",
            service_date_local: appointment.service_date_local,
            queue_no: appointment.queue_no,
            patient_name: appointment.patient_name,
            provider_name: providerRow?.name ?? null,
            clinic_name: clinicRow?.name ?? null,
            contact: contact.value,
          }),
          now,
          now
        ).run();
      }
    }
  }

  const apptInfo = await getAppointmentOrgClinic(env, appointment.id as string);
  if (apptInfo) {
    await writeAuditLog(env, {
      orgId: apptInfo.orgId,
      clinicId: apptInfo.clinicId,
      actorType: "staff",
      action: "update_status",
      entityTable: "appointment",
      entityId: appointment.id as string,
      before: { status: currentStatus },
      after: { status: toStatus },
      requestId,
    });
  }

  return jsonResponse({
    data: {
      id: appointment.id,
      queue_no: appointment.queue_no,
      status: toStatus,
    },
  });
}

async function upsertPatientContact(
  env: Env,
  orgId: string,
  patientId: string,
  type: "phone" | "email" | "line",
  value: string | null | undefined,
  now: number
) {
  if (value === undefined) return undefined;
  const normalized = (value ?? "").trim();
  if (!normalized) {
    await env.DB.prepare(
      `DELETE FROM patient_contact WHERE patient_id = ? AND type = ?`
    ).bind(patientId, type).run();
    return null;
  }

  const conflict = await env.DB.prepare(
    `SELECT patient_id
     FROM patient_contact
     WHERE org_id = ? AND type = ? AND value = ? AND patient_id != ?`
  ).bind(orgId, type, normalized, patientId).first();
  if (conflict) {
    throw new AppError("conflict", 409, { [type]: "already_in_use" });
  }

  const existing = await env.DB.prepare(
    `SELECT id
     FROM patient_contact
     WHERE patient_id = ? AND type = ?
     ORDER BY is_primary DESC, created_at ASC
     LIMIT 1`
  ).bind(patientId, type).first();

  if (existing) {
    await env.DB.prepare(
      `UPDATE patient_contact
       SET value = ?, is_primary = 1
       WHERE id = ?`
    ).bind(normalized, existing.id).run();

    await env.DB.prepare(
      `UPDATE patient_contact
       SET is_primary = 0
       WHERE patient_id = ? AND type = ? AND id != ?`
    ).bind(patientId, type, existing.id).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO patient_contact
        (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
       VALUES (?, ?, ?, ?, ?, 1, 0, ?)`
    ).bind(
      crypto.randomUUID(),
      orgId,
      patientId,
      type,
      normalized,
      now
    ).run();
  }

  return normalized;
}

async function listPatients(request: Request, env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const query = url.searchParams.get("q");
  const nationalId = url.searchParams.get("national_id");

  if (!clinicId) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }

  const clinicInfo = await getClinicOrg(env, clinicId);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const where: string[] = ["patient.org_id = ?", "patient.deleted_at IS NULL"];
  const params: unknown[] = [clinicInfo.orgId];

  if (nationalId) {
    const normalizedId = normalizeTWId(nationalId);
    if (!isValidTWId(normalizedId, true)) {
      throw new AppError("validation_error", 400, { national_id: "invalid" });
    }
    where.push("patient_identity.national_id = ?");
    params.push(normalizedId);
  }

  if (query) {
    const likeQuery = `%${query}%`;
    where.push(
      `(patient.display_name LIKE ?
        OR patient_identity.national_id LIKE ?
        OR EXISTS (
          SELECT 1 FROM patient_contact
          WHERE patient_contact.patient_id = patient.id
            AND patient_contact.value LIKE ?
        ))`
    );
    params.push(likeQuery, likeQuery, likeQuery);
  }

  const sql = `SELECT patient.id,
                     patient.display_name,
                     patient.gender,
                     patient_identity.national_id,
                     patient_identity.dob,
                     (SELECT value
                        FROM patient_contact
                       WHERE patient_contact.patient_id = patient.id
                         AND patient_contact.type = 'phone'
                       ORDER BY is_primary DESC, created_at ASC
                       LIMIT 1) AS phone,
                     (SELECT value
                        FROM patient_contact
                       WHERE patient_contact.patient_id = patient.id
                         AND patient_contact.type = 'email'
                       ORDER BY is_primary DESC, created_at ASC
                       LIMIT 1) AS email,
                     patient_restriction.no_show_count_recent,
                     patient_restriction.locked_until
              FROM patient
              JOIN patient_identity ON patient_identity.patient_id = patient.id
              LEFT JOIN patient_restriction ON patient_restriction.patient_id = patient.id
              WHERE ${where.join(" AND ")}
              ORDER BY patient.updated_at DESC
              LIMIT 100`;

  const result = await env.DB.prepare(sql).bind(...params).all();
  return jsonResponse({ data: result.results ?? [] });
}

async function getPatientById(request: Request, env: Env, patientId: string) {
  const staff = await getStaffContext(request, env);
  const row = await env.DB.prepare(
    `SELECT patient.id,
            patient.org_id,
            patient.display_name,
            patient.gender,
            patient_identity.national_id,
            patient_identity.dob,
            (SELECT value
               FROM patient_contact
              WHERE patient_contact.patient_id = patient.id
                AND patient_contact.type = 'phone'
              ORDER BY is_primary DESC, created_at ASC
              LIMIT 1) AS phone,
            (SELECT value
               FROM patient_contact
              WHERE patient_contact.patient_id = patient.id
                AND patient_contact.type = 'email'
              ORDER BY is_primary DESC, created_at ASC
              LIMIT 1) AS email,
            patient_restriction.no_show_count_recent,
            patient_restriction.locked_until
     FROM patient
     JOIN patient_identity ON patient_identity.patient_id = patient.id
     LEFT JOIN patient_restriction ON patient_restriction.patient_id = patient.id
     WHERE patient.id = ? AND patient.deleted_at IS NULL`
  ).bind(patientId).first();

  if (!row) {
    throw new AppError("not_found", 404, { patient: "not_found" });
  }

  if (staff.orgId && row.org_id !== staff.orgId) {
    throw new AppError("forbidden", 403);
  }

  const { org_id: _orgId, ...data } = row as Record<string, unknown>;
  return jsonResponse({ data });
}

function parseCursor(value: string | null): { date: string; id: string } | null {
  if (!value) return null;
  const [date, id] = value.split(":");
  if (!date || !id) return null;
  return { date, id };
}

async function listPatientAppointmentsAdmin(env: Env, url: URL, patientId: string) {
  const limitParam = Number(url.searchParams.get("limit") || 20);
  const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 100) : 20;
  const status = url.searchParams.get("status");
  const fromDate = url.searchParams.get("from_date");
  const toDate = url.searchParams.get("to_date");
  const clinicId = url.searchParams.get("clinic_id");
  const cursor = parseCursor(url.searchParams.get("cursor"));

  if (!clinicId) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }

  const clinicInfo = await getClinicOrg(env, clinicId);
  if (!clinicInfo) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  if (fromDate && !isValidDateString(fromDate)) {
    throw new AppError("validation_error", 400, { from_date: "invalid" });
  }
  if (toDate && !isValidDateString(toDate)) {
    throw new AppError("validation_error", 400, { to_date: "invalid" });
  }
  if (cursor && !isValidDateString(cursor.date)) {
    throw new AppError("validation_error", 400, { cursor: "invalid" });
  }

  const where: string[] = ["appointment.patient_id = ?", "appointment.clinic_id = ?"];
  const params: unknown[] = [patientId, clinicId];

  if (status) {
    where.push("appointment.status = ?");
    params.push(status);
  }
  if (fromDate) {
    where.push("appointment.service_date_local >= ?");
    params.push(fromDate);
  }
  if (toDate) {
    where.push("appointment.service_date_local <= ?");
    params.push(toDate);
  }
  if (cursor) {
    where.push(
      "(appointment.service_date_local < ? OR (appointment.service_date_local = ? AND appointment.id < ?))"
    );
    params.push(cursor.date, cursor.date, cursor.id);
  }

  const sql = `SELECT appointment.id,
                     appointment.service_date_local,
                     appointment.queue_no,
                     appointment.status,
                     appointment.booking_ref,
                     clinic.name AS clinic_name,
                     provider.name AS provider_name
              FROM appointment
              JOIN clinic ON clinic.id = appointment.clinic_id
              JOIN provider ON provider.id = appointment.provider_id
              WHERE ${where.join(" AND ")}
              ORDER BY appointment.service_date_local DESC, appointment.id DESC
              LIMIT ?`;

  const result = await env.DB.prepare(sql).bind(...params, limit + 1).all();
  const rows = result.results ?? [];
  let nextCursor: string | null = null;
  if (rows.length > limit) {
    const next = rows.pop() as { service_date_local: string; id: string };
    nextCursor = `${next.service_date_local}:${next.id}`;
  }

  return jsonResponse({ data: rows, next_cursor: nextCursor });
}

async function updatePatient(request: Request, env: Env, patientId: string) {
  const body = await parseJson<{
    display_name?: string | null;
    gender?: string | null;
    phone?: string | null;
    email?: string | null;
  }>(request);
  const requestId = getRequestId(request);

  const existing = await env.DB.prepare(
    `SELECT id, org_id, display_name, gender, deleted_at
     FROM patient
     WHERE id = ?`
  ).bind(patientId).first();

  if (!existing || existing.deleted_at) {
    throw new AppError("not_found", 404, { patient: "not_found" });
  }

  const hasDisplayName = Object.prototype.hasOwnProperty.call(body, "display_name");
  const hasGender = Object.prototype.hasOwnProperty.call(body, "gender");
  const now = Date.now();
  const nextDisplayName = hasDisplayName
    ? (body.display_name ?? "").trim() || null
    : (existing.display_name as string | null);
  const nextGender = hasGender
    ? (body.gender ?? "").trim() || null
    : (existing.gender as string | null);

  await env.DB.prepare(
    `UPDATE patient
     SET display_name = ?, gender = ?, updated_at = ?
     WHERE id = ?`
  ).bind(nextDisplayName, nextGender, now, patientId).run();

  const updatedPhone = await upsertPatientContact(
    env,
    existing.org_id as string,
    patientId,
    "phone",
    body.phone,
    now
  );
  const updatedEmail = await upsertPatientContact(
    env,
    existing.org_id as string,
    patientId,
    "email",
    body.email,
    now
  );

  await writeAuditLog(env, {
    orgId: existing.org_id as string,
    clinicId: null,
    actorType: "staff",
    action: "update",
    entityTable: "patient",
    entityId: patientId,
    before: {
      display_name: existing.display_name,
      gender: existing.gender,
    },
    after: {
      display_name: nextDisplayName,
      gender: nextGender,
      phone: updatedPhone ?? undefined,
      email: updatedEmail ?? undefined,
    },
    requestId,
  });

  return jsonResponse({ data: { id: patientId } });
}

async function deletePatient(request: Request, env: Env, patientId: string) {
  const requestId = getRequestId(request);
  const existing = await env.DB.prepare(
    `SELECT id, org_id, deleted_at
     FROM patient
     WHERE id = ?`
  ).bind(patientId).first();

  if (!existing) {
    throw new AppError("not_found", 404, { patient: "not_found" });
  }

  if (!existing.deleted_at) {
    const now = Date.now();
    await env.DB.prepare(
      `UPDATE patient
       SET deleted_at = ?, updated_at = ?
       WHERE id = ?`
    ).bind(now, now, patientId).run();

    await writeAuditLog(env, {
      orgId: existing.org_id as string,
      clinicId: null,
      actorType: "staff",
      action: "delete",
      entityTable: "patient",
      entityId: patientId,
      before: { deleted_at: existing.deleted_at },
      after: { deleted_at: now },
      requestId,
    });
  }

  return jsonResponse({ data: { id: patientId, deleted: true } });
}

async function unlockPatientRestriction(request: Request, env: Env, patientId: string) {
  const requestId = getRequestId(request);
  const staff = await getStaffContext(request, env);
  const now = Date.now();

  const patient = await env.DB.prepare(
    `SELECT id, org_id FROM patient WHERE id = ?`
  ).bind(patientId).first();
  if (!patient) {
    throw new AppError("not_found", 404, { patient: "not_found" });
  }

  const restriction = await env.DB.prepare(
    `SELECT no_show_count_recent, locked_until
     FROM patient_restriction
     WHERE patient_id = ?`
  ).bind(patientId).first();

  await env.DB.prepare(
    `INSERT INTO patient_restriction
      (patient_id, no_show_count_recent, locked_until, lock_reason, updated_at)
     VALUES (?, 0, NULL, NULL, ?)
     ON CONFLICT(patient_id)
     DO UPDATE SET no_show_count_recent = 0, locked_until = NULL, lock_reason = NULL, updated_at = ?`
  ).bind(patientId, now, now).run();

  await writeAuditLog(env, {
    orgId: (patient.org_id as string) ?? staff.orgId ?? "system",
    clinicId: null,
    actorType: "staff",
    action: "update",
    entityTable: "patient_restriction",
    entityId: patientId,
    before: {
      no_show_count_recent: restriction?.no_show_count_recent ?? null,
      locked_until: restriction?.locked_until ?? null,
    },
    after: {
      no_show_count_recent: 0,
      locked_until: null,
    },
    requestId,
  });

  return jsonResponse({ data: { patient_id: patientId, unlocked: true } });
}

async function lookupPatient(request: Request, env: Env) {
  const body = await parseJson<{ national_id: string }>(request);
  const normalizedId = normalizeTWId(body.national_id ?? "");
  if (!isValidTWId(normalizedId, true)) {
    throw new AppError("validation_error", 400, { national_id: "invalid" });
  }

  const row = await env.DB.prepare(
    `SELECT patient.id, patient.display_name, patient_identity.dob
     FROM patient
     JOIN patient_identity ON patient.id = patient_identity.patient_id
     WHERE patient_identity.national_id = ?`
  ).bind(normalizedId).first();

  if (!row) {
    throw new AppError("not_found", 404, { patient: "not_found" });
  }

  return jsonResponse({ data: row });
}

async function quickCreatePatient(request: Request, env: Env) {
  const body = await parseJson<{
    clinic_id: string;
    national_id: string;
    dob: string;
    display_name?: string;
    phone?: string;
    email?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.clinic_id) {
    throw new AppError("validation_error", 400, { clinic_id: "required" });
  }
  if (!body.national_id) {
    throw new AppError("validation_error", 400, { national_id: "required" });
  }
  if (!body.dob || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(body.dob)) {
    throw new AppError("validation_error", 400, { dob: "invalid" });
  }
  if (!body.phone && !body.email) {
    throw new AppError("validation_error", 400, { contact: "required" });
  }

  const normalizedId = normalizeTWId(body.national_id);
  if (!isValidTWId(normalizedId, true)) {
    throw new AppError("validation_error", 400, { national_id: "invalid" });
  }

  const existing = await env.DB.prepare(
    `SELECT patient_id, dob FROM patient_identity WHERE national_id = ?`
  ).bind(normalizedId).first();

  if (existing) {
    if (existing.dob !== body.dob) {
      throw new AppError("validation_error", 400, { dob: "mismatch" });
    }
    return jsonResponse({ data: { patient_id: existing.patient_id } });
  }

  const clinicRow = await env.DB.prepare(
    `SELECT org_id FROM clinic WHERE id = ?`
  ).bind(body.clinic_id).first();

  if (!clinicRow) {
    throw new AppError("not_found", 404, { clinic_id: "not_found" });
  }

  const now = Date.now();
  const patientId = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO patient (id, org_id, display_name, gender, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(
    patientId,
    clinicRow.org_id,
    body.display_name ?? null,
    null,
    now,
    now
  ).run();

  await env.DB.prepare(
    `INSERT INTO patient_identity (patient_id, national_id, dob, verified_level, created_at, updated_at)
     VALUES (?, ?, ?, 0, ?, ?)`
  ).bind(patientId, normalizedId, body.dob, now, now).run();

  if (body.phone) {
    await env.DB.prepare(
      `INSERT INTO patient_contact
        (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
       VALUES (?, ?, ?, 'phone', ?, 1, 0, ?)`
    ).bind(crypto.randomUUID(), clinicRow.org_id, patientId, body.phone, now).run();
  }

  if (body.email) {
    const isPrimary = body.phone ? 0 : 1;
    await env.DB.prepare(
      `INSERT INTO patient_contact
        (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
       VALUES (?, ?, ?, 'email', ?, ?, 0, ?)`
    ).bind(crypto.randomUUID(), clinicRow.org_id, patientId, body.email, isPrimary, now).run();
  }

  await writeAuditLog(env, {
    orgId: clinicRow.org_id as string,
    clinicId: body.clinic_id,
    actorType: "staff",
    action: "create",
    entityTable: "patient",
    entityId: patientId,
    after: {
      id: patientId,
      display_name: body.display_name ?? null,
      national_id: normalizedId,
      dob: body.dob,
      phone: body.phone ?? null,
      email: body.email ?? null,
    },
    requestId,
  });

  return jsonResponse({ data: { patient_id: patientId } }, { status: 201 });
}

async function bookAppointmentByStaff(request: Request, env: Env) {
  const body = await parseJson<{
    patient_id: string;
    slot_id: string;
    notify?: boolean;
    reason?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.patient_id) {
    throw new AppError("validation_error", 400, { patient_id: "required" });
  }
  if (!body.slot_id) {
    throw new AppError("validation_error", 400, { slot_id: "required" });
  }

  const stub = await getBookingStubBySlot(env, body.slot_id);
  const result = await stub.bookSlotForPatient({
    slotId: body.slot_id,
    patientId: body.patient_id,
    source: "staff_admin",
    now: Date.now(),
  });

  if (body.notify) {
    let contacts = await env.DB.prepare(
      `SELECT type, value
       FROM patient_contact
       WHERE patient_id = ? AND is_primary = 1`
    ).bind(body.patient_id).all();

    if (!contacts.results?.length) {
      contacts = await env.DB.prepare(
        `SELECT type, value
         FROM patient_contact
         WHERE patient_id = ?`
      ).bind(body.patient_id).all();
    }

    const now = Date.now();
    const contactRows = filterNotificationContacts(contacts.results ?? []);
    for (const contact of contactRows) {

      await env.DB.prepare(
        `INSERT INTO notification_job
          (id, event_type, channel, patient_id, appointment_id, payload_json, scheduled_at, status, created_at)
         VALUES (?, 'booking_confirm', ?, ?, ?, ?, ?, 'queued', ?)`
      ).bind(
        crypto.randomUUID(),
        contact.type,
        body.patient_id,
        result.appointmentId,
        JSON.stringify({
          reason: body.reason ?? "後台掛號",
          service_date_local: result.serviceDateLocal,
          contact: contact.value,
        }),
        now,
        now
      ).run();
    }
  }

  const apptInfo = await getAppointmentOrgClinic(env, result.appointmentId);
  if (apptInfo) {
    await writeAuditLog(env, {
      orgId: apptInfo.orgId,
      clinicId: apptInfo.clinicId,
      actorType: "staff",
      action: "create",
      entityTable: "appointment",
      entityId: result.appointmentId,
      after: {
        booking_ref: result.bookingRef,
        queue_no: result.queueNo,
        status: result.status,
        service_date_local: result.serviceDateLocal,
        source: "staff_admin",
      },
      requestId,
    });
  }

  return jsonResponse({
    data: {
      appointment_id: result.appointmentId,
      booking_ref: result.bookingRef,
      queue_no: result.queueNo,
      status: result.status,
      service_date_local: result.serviceDateLocal,
    },
  });
}

async function rescheduleAppointment(request: Request, env: Env) {
  const body = await parseJson<{
    appointment_id: string;
    new_slot_id: string;
    notify?: boolean;
    reason?: string;
  }>(request);
  const requestId = getRequestId(request);

  if (!body.appointment_id) {
    throw new AppError("validation_error", 400, { appointment_id: "required" });
  }
  if (!body.new_slot_id) {
    throw new AppError("validation_error", 400, { new_slot_id: "required" });
  }

  const appointment = await env.DB.prepare(
    `SELECT id, patient_id, provider_id, clinic_id, org_id, status
     FROM appointment
     WHERE id = ?`
  ).bind(body.appointment_id).first();

  if (!appointment) {
    throw new AppError("not_found", 404, { appointment_id: "not_found" });
  }

  if (appointment.status === "done") {
    throw new AppError("conflict", 409, { status: "not_reschedulable" });
  }

  const stub = await getBookingStubBySlot(env, body.new_slot_id);
  const result = await stub.bookSlotForPatient({
    slotId: body.new_slot_id,
    patientId: appointment.patient_id,
    source: "staff_admin",
    now: Date.now(),
  });

  const now = Date.now();
  await env.DB.prepare(
    `UPDATE appointment
     SET status = 'cancelled', cancelled_at = ?, updated_at = ?,
         note_internal = 'rescheduled'
     WHERE id = ? AND status != 'cancelled'`
  ).bind(now, now, appointment.id).run();

  await writeAuditLog(env, {
    orgId: appointment.org_id as string,
    clinicId: appointment.clinic_id as string,
    actorType: "staff",
    action: "cancel",
    entityTable: "appointment",
    entityId: appointment.id as string,
    before: { status: appointment.status },
    after: {
      status: "cancelled",
      note_internal: "rescheduled",
      new_appointment_id: result.appointmentId,
    },
    requestId,
  });

  const newApptInfo = await getAppointmentOrgClinic(env, result.appointmentId);
  if (newApptInfo) {
    await writeAuditLog(env, {
      orgId: newApptInfo.orgId,
      clinicId: newApptInfo.clinicId,
      actorType: "staff",
      action: "create",
      entityTable: "appointment",
      entityId: result.appointmentId,
      after: {
        booking_ref: result.bookingRef,
        queue_no: result.queueNo,
        status: "booked",
        service_date_local: result.serviceDateLocal,
        source: "staff_admin",
        rescheduled_from: appointment.id,
      },
      requestId,
    });
  }

  if (body.notify) {
    let contacts = await env.DB.prepare(
      `SELECT type, value
       FROM patient_contact
       WHERE patient_id = ? AND is_primary = 1`
    ).bind(appointment.patient_id).all();

    if (!contacts.results?.length) {
      contacts = await env.DB.prepare(
        `SELECT type, value
         FROM patient_contact
         WHERE patient_id = ?`
      ).bind(appointment.patient_id).all();
    }

    const contactRows = filterNotificationContacts(contacts.results ?? []);
    for (const contact of contactRows) {

      await env.DB.prepare(
        `INSERT INTO notification_job
          (id, event_type, channel, patient_id, appointment_id, payload_json, scheduled_at, status, created_at)
         VALUES (?, 'manual', ?, ?, ?, ?, ?, 'queued', ?)`
      ).bind(
        crypto.randomUUID(),
        contact.type,
        appointment.patient_id,
        result.appointmentId,
        JSON.stringify({
          reason: body.reason ?? "改約通知",
          service_date_local: result.serviceDateLocal,
          contact: contact.value,
        }),
        now,
        now
      ).run();
    }
  }

  return jsonResponse({
    data: {
      new_appointment_id: result.appointmentId,
      booking_ref: result.bookingRef,
      queue_no: result.queueNo,
      service_date_local: result.serviceDateLocal,
    },
  });
}


async function listDailyReport(env: Env, url: URL) {
  const serviceDate = url.searchParams.get("service_date_local");
  const clinicId = url.searchParams.get("clinic_id");
  const providerId = url.searchParams.get("provider_id");

  if (!serviceDate || !isValidDateString(serviceDate)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }

  const where: string[] = ["appointment.service_date_local = ?"];
  const params: unknown[] = [serviceDate];
  if (clinicId) {
    where.push("appointment.clinic_id = ?");
    params.push(clinicId);
  }
  if (providerId) {
    where.push("appointment.provider_id = ?");
    params.push(providerId);
  }

  const summary = await env.DB.prepare(
    `SELECT COUNT(*) AS total_count,
            SUM(CASE WHEN status = 'booked' THEN 1 ELSE 0 END) AS booked_count,
            SUM(CASE WHEN status = 'checked_in' THEN 1 ELSE 0 END) AS checked_in_count,
            SUM(CASE WHEN status = 'called' THEN 1 ELSE 0 END) AS called_count,
            SUM(CASE WHEN status = 'in_room' THEN 1 ELSE 0 END) AS in_room_count,
            SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) AS done_count,
            SUM(CASE WHEN status = 'no_show' THEN 1 ELSE 0 END) AS no_show_count,
            SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_count
     FROM appointment
     WHERE ${where.join(" AND ")}`
  ).bind(...params).first();

  const patientCountRow = await env.DB.prepare(
    `SELECT COUNT(DISTINCT patient_id) AS patient_count
     FROM appointment
     WHERE ${where.join(" AND ")}`
  ).bind(...params).first();

  const slotWhere: string[] = ["slot.service_date_local = ?"];
  const slotParams: unknown[] = [serviceDate];
  if (clinicId) {
    slotWhere.push("slot.clinic_id = ?");
    slotParams.push(clinicId);
  }
  if (providerId) {
    slotWhere.push("slot.provider_id = ?");
    slotParams.push(providerId);
  }

  const slotSummary = await env.DB.prepare(
    `SELECT COUNT(*) AS slot_count,
            SUM(slot_inventory.capacity) AS total_capacity,
            SUM(slot_inventory.booked_count) AS total_booked
     FROM slot
     JOIN slot_inventory ON slot_inventory.slot_id = slot.id
     WHERE ${slotWhere.join(" AND ")}`
  ).bind(...slotParams).first();

  return jsonResponse({
    data: {
      service_date_local: serviceDate,
      clinic_id: clinicId ?? null,
      provider_id: providerId ?? null,
      total_count: Number(summary?.total_count ?? 0),
      booked_count: Number(summary?.booked_count ?? 0),
      checked_in_count: Number(summary?.checked_in_count ?? 0),
      called_count: Number(summary?.called_count ?? 0),
      in_room_count: Number(summary?.in_room_count ?? 0),
      done_count: Number(summary?.done_count ?? 0),
      no_show_count: Number(summary?.no_show_count ?? 0),
      cancelled_count: Number(summary?.cancelled_count ?? 0),
      patient_count: Number(patientCountRow?.patient_count ?? 0),
      slot_count: Number(slotSummary?.slot_count ?? 0),
      total_capacity: Number(slotSummary?.total_capacity ?? 0),
      total_booked: Number(slotSummary?.total_booked ?? 0),
    },
  });
}

async function exportSlotsCsv(env: Env, url: URL) {
  const serviceDate = url.searchParams.get("service_date_local");
  const clinicId = url.searchParams.get("clinic_id");
  const providerId = url.searchParams.get("provider_id");

  if (!serviceDate || !isValidDateString(serviceDate)) {
    throw new AppError("validation_error", 400, { service_date_local: "invalid" });
  }

  const where: string[] = ["slot.service_date_local = ?"];
  const params: unknown[] = [serviceDate];
  if (clinicId) {
    where.push("slot.clinic_id = ?");
    params.push(clinicId);
  }
  if (providerId) {
    where.push("slot.provider_id = ?");
    params.push(providerId);
  }

  const result = await env.DB.prepare(
    `SELECT slot.clinic_id, slot.provider_id, slot.service_date_local,
            slot.start_at_utc, slot.end_at_utc, slot.status,
            slot_inventory.capacity
     FROM slot
     JOIN slot_inventory ON slot_inventory.slot_id = slot.id
     WHERE ${where.join(" AND ")}
     ORDER BY slot.start_at_utc ASC`
  ).bind(...params).all();

  const header = "clinic_id,provider_id,service_date_local,start_time_local,end_time_local,capacity,status";
  const lines = [header];
  for (const row of result.results ?? []) {
    const startTime = formatTaipeiTime(Number(row.start_at_utc));
    const endTime = formatTaipeiTime(Number(row.end_at_utc));
    lines.push([
      row.clinic_id,
      row.provider_id,
      row.service_date_local,
      startTime,
      endTime,
      row.capacity,
      row.status,
    ].join(","));
  }

  const filename = `slots-${serviceDate}.csv`;
  return csvResponse(lines.join("\n"), filename);
}

async function importSlotsCsv(request: Request, env: Env) {
  const contentType = request.headers.get("content-type") || "";
  let csvText = "";
  if (contentType.includes("text/csv")) {
    csvText = await request.text();
  } else {
    const body = await parseJson<{ csv: string }>(request);
    csvText = body.csv || "";
  }

  if (!csvText.trim()) {
    throw new AppError("validation_error", 400, { csv: "required" });
  }

  const rows = parseCsv(csvText);
  if (rows.length < 2) {
    throw new AppError("validation_error", 400, { csv: "no_rows" });
  }

  const header = rows[0].map((value) => value.trim().toLowerCase());
  const idxClinic = header.indexOf("clinic_id");
  const idxProvider = header.indexOf("provider_id");
  const idxDate = header.indexOf("service_date_local");
  const idxStart = header.indexOf("start_time_local");
  const idxEnd = header.indexOf("end_time_local");
  const idxCapacity = header.indexOf("capacity");
  const idxStatus = header.indexOf("status");

  if (idxClinic === -1 || idxProvider === -1 || idxDate === -1 || idxStart === -1 || idxEnd === -1) {
    throw new AppError("validation_error", 400, { csv: "missing_headers" });
  }

  let created = 0;
  let updated = 0;
  let skipped = 0;
  const errors: Array<{ row: number; reason: string }> = [];
  const now = Date.now();

  for (let i = 1; i < rows.length; i += 1) {
    const row = rows[i];
    const clinicId = row[idxClinic] || "";
    const providerId = row[idxProvider] || "";
    const serviceDate = row[idxDate] || "";
    const startTime = row[idxStart] || "";
    const endTime = row[idxEnd] || "";
    const capacityValue = idxCapacity >= 0 ? row[idxCapacity] : "";
    const statusValue = idxStatus >= 0 ? row[idxStatus] : "";

    if (!clinicId || !providerId || !serviceDate || !startTime || !endTime) {
      skipped += 1;
      errors.push({ row: i + 1, reason: "missing_required" });
      continue;
    }
    if (!isValidDateString(serviceDate) || !isValidTimeString(startTime) || !isValidTimeString(endTime)) {
      skipped += 1;
      errors.push({ row: i + 1, reason: "invalid_date_or_time" });
      continue;
    }

    const capacity = Math.max(Number(capacityValue || 1), 1);
    const status = statusValue || "open";
    const startAtUtc = toUtcEpochMs(serviceDate, startTime);
    const endAtUtc = toUtcEpochMs(serviceDate, endTime);
    if (endAtUtc <= startAtUtc) {
      skipped += 1;
      errors.push({ row: i + 1, reason: "end_before_start" });
      continue;
    }

    const existing = await env.DB.prepare(
      `SELECT id FROM slot
       WHERE clinic_id = ? AND provider_id = ? AND service_date_local = ? AND start_at_utc = ?`
    ).bind(clinicId, providerId, serviceDate, startAtUtc).first();

    if (!existing) {
      const slotId = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO slot
          (id, provider_id, clinic_id, service_date_local, start_at_utc, end_at_utc, capacity, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        slotId,
        providerId,
        clinicId,
        serviceDate,
        startAtUtc,
        endAtUtc,
        capacity,
        status,
        now
      ).run();

      await env.DB.prepare(
        `INSERT INTO slot_inventory (slot_id, capacity, booked_count, version)
         VALUES (?, ?, 0, 0)`
      ).bind(slotId, capacity).run();

      created += 1;
      continue;
    }

    const inventory = await env.DB.prepare(
      `SELECT booked_count FROM slot_inventory WHERE slot_id = ?`
    ).bind(existing.id).first();
    const bookedCount = Number(inventory?.booked_count ?? 0);
    if (bookedCount > capacity) {
      skipped += 1;
      errors.push({ row: i + 1, reason: "capacity_below_booked" });
      continue;
    }

    await env.DB.prepare(
      `UPDATE slot
       SET end_at_utc = ?, capacity = ?, status = ?
       WHERE id = ?`
    ).bind(endAtUtc, capacity, status, existing.id).run();

    await env.DB.prepare(
      `UPDATE slot_inventory
       SET capacity = ?
       WHERE slot_id = ?`
    ).bind(capacity, existing.id).run();

    updated += 1;
  }

  return jsonResponse({ data: { created, updated, skipped, errors } });
}

async function listAuditLogs(env: Env, url: URL) {
  const clinicId = url.searchParams.get("clinic_id");
  const actorType = url.searchParams.get("actor_type");
  const entityTable = url.searchParams.get("entity_table");
  const dateFrom = url.searchParams.get("date_from");
  const dateTo = url.searchParams.get("date_to");
  const limit = Math.min(Number(url.searchParams.get("limit") ?? 50), 200);

  const where: string[] = [];
  const params: unknown[] = [];
  if (clinicId) {
    where.push("audit_log.clinic_id = ?");
    params.push(clinicId);
  }
  if (actorType) {
    where.push("audit_log.actor_type = ?");
    params.push(actorType);
  }
  if (entityTable) {
    where.push("audit_log.entity_table = ?");
    params.push(entityTable);
  }
  if (dateFrom && isValidDateString(dateFrom)) {
    const [fromYear, fromMonth, fromDay] = dateFrom.split("-").map((value) => Number(value));
    const start = Date.UTC(fromYear, fromMonth - 1, fromDay, 0 - 8, 0, 0);
    where.push("audit_log.created_at >= ?");
    params.push(start);
  }
  if (dateTo && isValidDateString(dateTo)) {
    const [toYear, toMonth, toDay] = dateTo.split("-").map((value) => Number(value));
    const end = Date.UTC(toYear, toMonth - 1, toDay, 23 - 8, 59, 59);
    where.push("audit_log.created_at <= ?");
    params.push(end);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const result = await env.DB.prepare(
    `SELECT audit_log.id, audit_log.actor_type, audit_log.actor_id, audit_log.action,
            audit_log.entity_table, audit_log.entity_id, audit_log.request_id,
            audit_log.created_at, audit_log.before_json, audit_log.after_json,
            staff_user.email AS staff_email, staff_user.name AS staff_name,
            patient.display_name AS patient_name
     FROM audit_log
     LEFT JOIN staff_user ON audit_log.actor_type = 'staff' AND staff_user.id = audit_log.actor_id
     LEFT JOIN patient ON audit_log.actor_type = 'patient' AND patient.id = audit_log.actor_id
     ${whereSql}
     ORDER BY audit_log.created_at DESC
     LIMIT ?`
  ).bind(...params, limit).all();

  return jsonResponse({ data: result.results ?? [] });
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
        "access-control-allow-headers": "content-type,authorization,x-idempotency-key,x-device-id,x-staff-email",
      },
    });
  }

  if (path.startsWith("/api/v1/admin")) {
    await enforceAdminAccess(request, env);
  }

  if (path === "/api/v1/dev/seed" && method === "POST") {
    return seedDevData(env, request);
  }

  if (path === "/api/v1/public/clinics" && method === "GET") {
    return listClinics(env);
  }

  if (path === "/api/v1/public/auth/verify" && method === "POST") {
    return verifyAuth(request, env);
  }

  if (path === "/api/v1/public/auth/login" && method === "POST") {
    return loginAuth(request, env);
  }

  if (path === "/api/v1/public/auth/bind" && method === "POST") {
    return bindAuth(request, env);
  }

  if (path === "/api/v1/public/me" && method === "GET") {
    return getPatientProfile(request, env);
  }

  if (path === "/api/v1/public/me/appointments" && method === "GET") {
    return listPatientAppointments(request, env, url);
  }

  if (path.startsWith("/api/v1/public/me/appointments/") && method === "POST" && path.endsWith("/cancel")) {
    const id = path.split("/").slice(-2)[0] ?? "";
    return cancelAppointmentByPatient(request, env, id);
  }

  if (path.startsWith("/api/v1/public/me/appointments/") && method === "GET" && path.endsWith("/calendar")) {
    const id = path.split("/").slice(-2)[0] ?? "";
    return getMemberAppointmentCalendar(request, env, id);
  }

  if (path.startsWith("/api/v1/public/me/appointments/") && method === "POST" && path.endsWith("/checkin-token")) {
    const id = path.split("/").slice(-2)[0] ?? "";
    return createCheckinTokenForMember(request, env, id);
  }

  if (path === "/api/v1/public/clinic-notice" && method === "GET") {
    return getClinicNotice(env, url);
  }

  if (path === "/api/v1/public/forms" && method === "GET") {
    return getPublicFormDefinition(env, url);
  }

  if (path === "/api/v1/public/forms/submission" && method === "GET") {
    return getPatientFormSubmission(request, env, url);
  }

  if (path === "/api/v1/public/email-verifications" && method === "POST") {
    return requestEmailVerification(request, env);
  }

  if (path === "/api/v1/public/email-verifications/verify" && method === "POST") {
    return verifyEmailVerification(request, env);
  }

  if (path === "/api/v1/public/forms/submit" && method === "POST") {
    return submitPatientForm(request, env);
  }

  if (path === "/api/v1/admin/clinics" && method === "GET") {
    return listClinicsAdmin(request, env);
  }

  if (path === "/api/v1/admin/me" && method === "GET") {
    return getAdminProfile(request, env);
  }

  if (path === "/api/v1/admin/clinics" && method === "POST") {
    return createClinic(request, env);
  }

  if (path.startsWith("/api/v1/admin/clinics/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updateClinic(request, env, id);
  }

  if (path === "/api/v1/public/providers" && method === "GET") {
    return listProviders(env, url);
  }

  if (path === "/api/v1/public/slots" && method === "GET") {
    return listSlots(request, env, url);
  }

  if (path === "/api/v1/admin/providers" && method === "GET") {
    return listProvidersAdmin(env, url);
  }

  if (path === "/api/v1/admin/providers" && method === "POST") {
    return createProvider(request, env);
  }

  if (path.startsWith("/api/v1/admin/providers/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updateProvider(request, env, id);
  }

  if (path === "/api/v1/admin/schedule-rules" && method === "GET") {
    return listScheduleRules(env, url);
  }

  if (path === "/api/v1/admin/schedule-rules" && method === "POST") {
    return createScheduleRule(request, env);
  }

  if (path.startsWith("/api/v1/admin/schedule-rules/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updateScheduleRule(request, env, id);
  }

  if (path.startsWith("/api/v1/admin/schedule-rules/") && method === "DELETE") {
    const id = path.split("/").pop() ?? "";
    return deleteScheduleRule(request, env, id);
  }

  if (path === "/api/v1/admin/schedule-exceptions" && method === "GET") {
    return listScheduleExceptions(env, url);
  }

  if (path === "/api/v1/admin/schedule-exceptions" && method === "POST") {
    return createScheduleException(request, env);
  }

  if (path.startsWith("/api/v1/admin/schedule-exceptions/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updateScheduleException(request, env, id);
  }

  if (path.startsWith("/api/v1/admin/schedule-exceptions/") && method === "DELETE") {
    const id = path.split("/").pop() ?? "";
    return deleteScheduleException(request, env, id);
  }

  if (path === "/api/v1/admin/slots/generate" && method === "POST") {
    return generateSlots(request, env);
  }

  if (path === "/api/v1/admin/slots/close" && method === "POST") {
    return closeSlots(request, env);
  }

  if (path === "/api/v1/admin/slots/export" && method === "GET") {
    return exportSlotsCsv(env, url);
  }

  if (path === "/api/v1/admin/slots/import" && method === "POST") {
    return importSlotsCsv(request, env);
  }

  if (path === "/api/v1/admin/appointments" && method === "GET") {
    return listAppointments(env, url);
  }

  if (path === "/api/v1/admin/appointments/export" && method === "GET") {
    return exportAppointmentsCsv(env, url);
  }

  if (path === "/api/v1/admin/reports/daily" && method === "GET") {
    return listDailyReport(env, url);
  }

  if (path === "/api/v1/admin/audit-logs" && method === "GET") {
    return listAuditLogs(env, url);
  }

  if (path === "/api/v1/admin/roles" && method === "GET") {
    return listRoles(env);
  }

  if (path === "/api/v1/admin/roles" && method === "POST") {
    return createRole(request, env);
  }

  if (path === "/api/v1/admin/patient-auth" && method === "GET") {
    return listPatientAuth(request, env, url);
  }

  if (path.startsWith("/api/v1/admin/patient-auth/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updatePatientAuth(request, env, id);
  }

  if (path === "/api/v1/admin/clinic-notice" && method === "POST") {
    return upsertClinicNotice(request, env);
  }

  if (path === "/api/v1/admin/forms" && method === "GET") {
    return listFormDefinitionsAdmin(request, env, url);
  }

  if (path === "/api/v1/admin/forms" && method === "POST") {
    return createFormDefinition(request, env);
  }

  if (path.startsWith("/api/v1/admin/forms/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updateFormDefinition(request, env, id);
  }

  if (path === "/api/v1/admin/form-submissions" && method === "GET") {
    return listFormSubmissionsAdmin(request, env, url);
  }

  if (path === "/api/v1/admin/staff-users" && method === "GET") {
    return listStaffUsers(env, url);
  }

  if (path === "/api/v1/admin/staff-users" && method === "POST") {
    return createStaffUser(request, env);
  }

  if (path.startsWith("/api/v1/admin/staff-users/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updateStaffUser(request, env, id);
  }

  if (path.startsWith("/api/v1/admin/appointments/") && path.endsWith("/status") && method === "POST") {
    const id = path.split("/").slice(-2)[0] ?? "";
    return updateAppointmentStatus(request, env, id);
  }

  if (path === "/api/v1/admin/queue/reserved" && method === "POST") {
    return setReservedQueueNumbers(request, env);
  }

  if (path === "/api/v1/admin/patients/lookup" && method === "POST") {
    return lookupPatient(request, env);
  }

  if (path === "/api/v1/admin/patients" && method === "GET") {
    return listPatients(request, env, url);
  }

  if (path.startsWith("/api/v1/admin/patients/") && path.endsWith("/appointments") && method === "GET") {
    const id = path.split("/").slice(-2)[0] ?? "";
    return listPatientAppointmentsAdmin(env, url, id);
  }

  if (path.startsWith("/api/v1/admin/patients/") && path.endsWith("/unlock") && method === "POST") {
    const id = path.split("/").slice(-2)[0] ?? "";
    return unlockPatientRestriction(request, env, id);
  }

  if (path.startsWith("/api/v1/admin/patients/") && method === "GET") {
    const id = path.split("/").pop() ?? "";
    return getPatientById(request, env, id);
  }

  if (path === "/api/v1/admin/patients/quick-create" && method === "POST") {
    return quickCreatePatient(request, env);
  }

  if (path.startsWith("/api/v1/admin/patients/") && method === "PATCH") {
    const id = path.split("/").pop() ?? "";
    return updatePatient(request, env, id);
  }

  if (path.startsWith("/api/v1/admin/patients/") && method === "DELETE") {
    const id = path.split("/").pop() ?? "";
    return deletePatient(request, env, id);
  }

  if (path === "/api/v1/admin/appointments/book" && method === "POST") {
    return bookAppointmentByStaff(request, env);
  }

  if (path === "/api/v1/admin/appointments/reschedule" && method === "POST") {
    return rescheduleAppointment(request, env);
  }

  if (path === "/api/v1/admin/notifications/jobs" && method === "GET") {
    return listNotificationJobs(env, url);
  }
  const notificationRetryMatch = path.match(/^\/api\/v1\/admin\/notifications\/jobs\/([^/]+)\/retry$/);
  if (notificationRetryMatch && method === "POST") {
    return retryNotificationJob(request, env, notificationRetryMatch[1]);
  }


  if (path === "/api/v1/admin/message-templates" && method === "GET") {
    return listMessageTemplates(env, url);
  }

  if (path === "/api/v1/admin/message-templates" && method === "POST") {
    return createMessageTemplate(request, env);
  }

  if (path === "/api/v1/admin/message-templates/preview" && method === "POST") {
    return previewMessageTemplate(request, env);
  }

  if (path === "/api/v1/admin/notifications/send" && method === "POST") {
    return sendManualNotification(request, env);
  }

  if (path === "/api/v1/admin/notifications/process" && method === "POST") {
    return processNotificationJobs(request, env);
  }

  if (path === "/api/v1/public/holds" && method === "POST") {
    return createHold(request, env);
  }

  if (path === "/api/v1/public/appointments" && method === "POST") {
    return confirmBooking(request, env);
  }

  if (path === "/api/v1/public/checkin" && method === "POST") {
    return checkinAppointmentByToken(request, env);
  }

  if (path === "/api/v1/public/queue-status" && method === "GET") {
    return listQueueStatus(env, url);
  }

  if (path.startsWith("/api/v1/public/appointments/") && method === "GET" && path.endsWith("/calendar")) {
    const bookingRef = path.split("/").slice(-2)[0] ?? "";
    return getAppointmentCalendar(env, url, bookingRef);
  }

  if (path.startsWith("/api/v1/public/appointments/") && method === "POST" && path.endsWith("/checkin-token")) {
    const bookingRef = path.split("/").slice(-2)[0] ?? "";
    return createCheckinTokenByBookingRef(request, env, bookingRef);
  }

  if (path.startsWith("/api/v1/public/appointments/") && method === "GET") {
    const bookingRef = path.split("/").pop() ?? "";
    return lookupAppointment(env, url, bookingRef);
  }

  if (path.startsWith("/api/v1/public/appointments/") && method === "POST" && path.endsWith("/cancel")) {
    const bookingRef = path.split("/").slice(-2)[0] ?? "";
    return cancelAppointment(request, env, bookingRef);
  }

  return jsonResponse({ error: { code: "not_found", message: "Not Found" } }, { status: 404 });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      return errorResponse(error);
    }
  },
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const requestId = `cron_${event.scheduledTime}`;
    ctx.waitUntil(
      (async () => {
        await scheduleAppointmentReminders(env, event.scheduledTime, requestId);
        await processNotificationJobsInternal(env, 50, requestId);
        await purgeOldRecords(env, event.scheduledTime);
      })()
    );
  },
};

export { BookingDurableObject };
