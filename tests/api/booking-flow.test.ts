import { Miniflare } from "miniflare";
import { afterAll, beforeAll, expect, test } from "vitest";
import { build } from "esbuild";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const apiSourceDir = path.resolve("apps/api/src");
const schemaPath = path.resolve("db/schema.sql");

let mf: Miniflare;
let seededDates: string[] = [];
let workerDir: string | null = null;
let workerPath: string | null = null;
let db: any;

const LETTER_CODE: Record<string, number> = {
  A: 10, B: 11, C: 12, D: 13, E: 14, F: 15, G: 16, H: 17,
  I: 34, J: 18, K: 19, L: 20, M: 21, N: 22, O: 35, P: 23,
  Q: 24, R: 25, S: 26, T: 27, U: 28, V: 29, W: 32, X: 30,
  Y: 31, Z: 33,
};
const WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 1, 1];

function makeNationalId(letter: string, gender: number, digits7: number[]) {
  const code = LETTER_CODE[letter];
  if (!code) throw new Error(`invalid_letter:${letter}`);
  if (digits7.length !== 7) throw new Error("digits7_required");
  const a1 = Math.floor(code / 10);
  const a2 = code % 10;
  const digits = [gender, ...digits7, 0];
  const sum = digits.slice(0, 8).reduce((acc, digit, index) => acc + digit * WEIGHTS[index], a1 * 1 + a2 * 9);
  const checksum = (10 - (sum % 10)) % 10;
  digits[8] = checksum;
  return `${letter}${digits.join("")}`;
}

async function buildWorkerBundle() {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clinic-worker-"));
  const entries = await fs.readdir(apiSourceDir);
  await Promise.all(
    entries.map(async (entry) => {
      const input = await fs.readFile(path.join(apiSourceDir, entry), "utf8");
      await fs.writeFile(path.join(tempDir, entry), input, "utf8");
    })
  );
  const entry = path.join(tempDir, "index.ts");
  const outFile = path.join(tempDir, "worker.mjs");
  await build({
    entryPoints: [entry],
    outfile: outFile,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    external: ["cloudflare:workers"],
  });
  return { tempDir, outFile };
}

async function jsonFetch(url: string, init?: RequestInit & { body?: unknown }) {
  const headers = { "content-type": "application/json", ...(init?.headers || {}) };
  const body =
    init?.body && typeof init.body !== "string" ? JSON.stringify(init.body) : (init?.body as string | undefined);
  const response = await mf.dispatchFetch(`http://localhost${url}`, {
    ...init,
    headers,
    body,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  return { response, data };
}

async function textFetch(url: string, init?: RequestInit) {
  const response = await mf.dispatchFetch(`http://localhost${url}`, init);
  const text = await response.text();
  return { response, text };
}

async function getClinicAndProvider() {
  const clinics = await jsonFetch("/api/v1/public/clinics");
  if (!clinics.response.ok) {
    throw new Error(`clinics_failed: ${JSON.stringify(clinics.data)}`);
  }
  const clinicId = clinics.data?.data?.[0]?.id;
  if (!clinicId) {
    throw new Error("clinics_empty");
  }

  const providers = await jsonFetch(`/api/v1/public/providers?clinic_id=${clinicId}`);
  if (!providers.response.ok) {
    throw new Error(`providers_failed: ${JSON.stringify(providers.data)}`);
  }
  const providerId = providers.data?.data?.[0]?.id;
  if (!providerId) {
    throw new Error("providers_empty");
  }

  return { clinicId, providerId };
}

async function getFirstSlot(clinicId: string, providerId: string, serviceDate: string) {
  const slots = await jsonFetch(
    `/api/v1/public/slots?clinic_id=${clinicId}&provider_id=${providerId}&service_date_local=${serviceDate}`
  );
  if (!slots.response.ok) {
    throw new Error(`slots_failed: ${JSON.stringify(slots.data)}`);
  }
  const slotId = slots.data?.data?.[0]?.slot_id;
  if (!slotId) {
    throw new Error("slots_empty");
  }
  return slotId as string;
}

async function getSlots(clinicId: string, providerId: string, serviceDate: string) {
  const slots = await jsonFetch(
    `/api/v1/public/slots?clinic_id=${clinicId}&provider_id=${providerId}&service_date_local=${serviceDate}`
  );
  if (!slots.response.ok) {
    throw new Error(`slots_failed: ${JSON.stringify(slots.data)}`);
  }
  return (slots.data?.data || []) as Array<{ slot_id: string }>;
}

beforeAll(async () => {
  const bundle = await buildWorkerBundle();
  workerDir = bundle.tempDir;
  workerPath = bundle.outFile;
  mf = new Miniflare({
    scriptPath: workerPath,
    modules: true,
    compatibilityDate: "2024-04-03",
    bindings: {
      APP_ENV: "dev",
      EMAIL_PROVIDER: "resend",
    },
    d1Databases: ["DB"],
    durableObjects: {
      BOOKING_DO: "BookingDurableObject",
    },
  });

  db = await mf.getD1Database("DB");
  const schema = await fs.readFile(schemaPath, "utf8");
  const schemaWithoutComments = schema
    .split(/\r?\n/)
    .filter((line) => {
      const trimmed = line.trim();
      return trimmed && !trimmed.startsWith("--") && !trimmed.startsWith("PRAGMA");
    })
    .join("\n");
  const statements = schemaWithoutComments
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement);
  for (const statement of statements) {
    await db.prepare(statement).run();
  }

  const seed = await jsonFetch("/api/v1/dev/seed", {
    method: "POST",
    body: { days: 2 },
  });
  expect(seed.response.ok).toBe(true);
  seededDates = seed.data?.data?.service_dates || [];
  expect(seededDates.length).toBeGreaterThan(0);
});

afterAll(async () => {
  if (mf) {
    await mf.dispose();
  }
  if (workerDir) {
    await fs.rm(workerDir, { recursive: true, force: true });
  }
});

test("email verification request and verify", async () => {
  const request = await jsonFetch("/api/v1/public/email-verifications", {
    method: "POST",
    body: { email: "patient@example.com", purpose: "booking" },
  });
  if (!request.response.ok) {
    throw new Error(`email_verification_request_failed: ${JSON.stringify(request.data)}`);
  }
  const verificationId = request.data?.data?.verification_id;
  const debugCode = request.data?.data?.debug_code;
  expect(verificationId).toBeTruthy();
  expect(debugCode).toBeTruthy();

  const verify = await jsonFetch("/api/v1/public/email-verifications/verify", {
    method: "POST",
    body: {
      verification_id: verificationId,
      code: debugCode,
      email: "patient@example.com",
      purpose: "booking",
    },
  });
  if (!verify.response.ok) {
    throw new Error(`email_verification_verify_failed: ${JSON.stringify(verify.data)}`);
  }
  expect(verify.data?.data?.valid).toBe(true);
});

test("booking can consume email verification", async () => {
  const { clinicId, providerId } = await getClinicAndProvider();
  const serviceDate = seededDates[0];
  const slotId = await getFirstSlot(clinicId, providerId, serviceDate);

  const hold = await jsonFetch("/api/v1/public/holds", {
    method: "POST",
    body: { slot_id: slotId },
  });
  if (!hold.response.ok) {
    throw new Error(`hold_failed: ${JSON.stringify(hold.data)}`);
  }
  const holdToken = hold.data?.data?.hold_token;
  expect(holdToken).toBeTruthy();

  const emailVerification = await jsonFetch("/api/v1/public/email-verifications", {
    method: "POST",
    body: { email: "verify@example.com", purpose: "booking" },
  });
  if (!emailVerification.response.ok) {
    throw new Error(`email_verification_request_failed: ${JSON.stringify(emailVerification.data)}`);
  }
  const verificationId = emailVerification.data?.data?.verification_id;
  const debugCode = emailVerification.data?.data?.debug_code;
  expect(verificationId).toBeTruthy();
  expect(debugCode).toBeTruthy();

  const booking = await jsonFetch("/api/v1/public/appointments", {
    method: "POST",
    body: {
      hold_token: holdToken,
      national_id: "A123456789",
      dob: "1990-01-01",
      email: "verify@example.com",
      display_name: "測試病人",
      email_verification_id: verificationId,
      email_verification_code: debugCode,
    },
  });
  if (!booking.response.ok) {
    throw new Error(`booking_failed: ${JSON.stringify(booking.data)}`);
  }

  const verificationRow = await db.prepare(
    "SELECT used_at FROM email_verification WHERE id = ?"
  ).bind(verificationId).first();
  expect(Number(verificationRow?.used_at ?? 0)).toBeGreaterThan(0);
});

test("patient booking flow (hold → book → lookup → cancel)", async () => {
  const slotCount = await db.prepare("SELECT COUNT(*) as count FROM slot").first();
  expect(Number(slotCount?.count ?? 0)).toBeGreaterThan(0);
  const { clinicId, providerId } = await getClinicAndProvider();

  const serviceDate = seededDates[0];
  const slotId = await getFirstSlot(clinicId, providerId, serviceDate);

  const hold = await jsonFetch("/api/v1/public/holds", {
    method: "POST",
    body: { slot_id: slotId },
  });
  if (!hold.response.ok) {
    throw new Error(`hold_failed: ${JSON.stringify(hold.data)}`);
  }
  const holdToken = hold.data?.data?.hold_token;
  expect(holdToken).toBeTruthy();

  const booking = await jsonFetch("/api/v1/public/appointments", {
    method: "POST",
    body: {
      hold_token: holdToken,
      national_id: "A123456789",
      dob: "1990-01-01",
      email: "patient@example.com",
      display_name: "測試病人",
    },
  });
  if (!booking.response.ok) {
    throw new Error(`booking_failed: ${JSON.stringify(booking.data)}`);
  }
  const appointmentId = booking.data?.data?.appointment_id;
  expect(appointmentId).toBeTruthy();
  const bookingRef = booking.data?.data?.booking_ref;
  expect(bookingRef).toBeTruthy();

  const confirmJobs = await db.prepare(
    "SELECT COUNT(*) as count FROM notification_job WHERE appointment_id = ? AND event_type = 'booking_confirm'"
  ).bind(appointmentId).first();
  expect(Number(confirmJobs?.count ?? 0)).toBeGreaterThan(0);

  const lookup = await jsonFetch(
    `/api/v1/public/appointments/${bookingRef}?dob=1990-01-01&email=patient@example.com`
  );
  expect(lookup.response.ok).toBe(true);
  expect(lookup.data?.data?.status).toBe("booked");

  const cancel = await jsonFetch(`/api/v1/public/appointments/${bookingRef}/cancel`, {
    method: "POST",
    body: {
      dob: "1990-01-01",
      email: "patient@example.com",
    },
  });
  expect(cancel.response.ok).toBe(true);
  expect(cancel.data?.data?.status).toBe("cancelled");
});

test("patient calendar and check-in token flow", async () => {
  const { clinicId, providerId } = await getClinicAndProvider();
  const serviceDate = seededDates[0];
  const slotId = await getFirstSlot(clinicId, providerId, serviceDate);

  const hold = await jsonFetch("/api/v1/public/holds", {
    method: "POST",
    body: { slot_id: slotId },
  });
  if (!hold.response.ok) {
    throw new Error(`hold_failed: ${JSON.stringify(hold.data)}`);
  }
  const holdToken = hold.data?.data?.hold_token;
  expect(holdToken).toBeTruthy();

  const booking = await jsonFetch("/api/v1/public/appointments", {
    method: "POST",
    body: {
      hold_token: holdToken,
      national_id: "A123456789",
      dob: "1990-01-01",
      email: "patient@example.com",
      display_name: "測試病人",
    },
  });
  if (!booking.response.ok) {
    throw new Error(`booking_failed: ${JSON.stringify(booking.data)}`);
  }
  const bookingRef = booking.data?.data?.booking_ref;
  expect(bookingRef).toBeTruthy();

  const calendar = await textFetch(
    `/api/v1/public/appointments/${bookingRef}/calendar?dob=1990-01-01&email=patient@example.com`
  );
  expect(calendar.response.ok).toBe(true);
  expect(calendar.text).toContain("BEGIN:VCALENDAR");
  expect(calendar.text).toContain(String(bookingRef));

  const tokenResp = await jsonFetch(`/api/v1/public/appointments/${bookingRef}/checkin-token`, {
    method: "POST",
    body: { dob: "1990-01-01", email: "patient@example.com" },
  });
  if (!tokenResp.response.ok) {
    throw new Error(`checkin_token_failed: ${JSON.stringify(tokenResp.data)}`);
  }
  const token = tokenResp.data?.data?.checkin_token;
  expect(token).toBeTruthy();

  const checkin = await jsonFetch("/api/v1/public/checkin", {
    method: "POST",
    body: { token },
  });
  expect(checkin.response.ok).toBe(true);
  expect(checkin.data?.data?.status).toBe("checked_in");
});

test("admin booking flow (book → checked_in → called) with queue notification", async () => {
  const { clinicId, providerId } = await getClinicAndProvider();
  const serviceDate = seededDates[0];
  const slotId = await getFirstSlot(clinicId, providerId, serviceDate);

  const patient = await jsonFetch("/api/v1/admin/patients/quick-create", {
    method: "POST",
    body: {
      clinic_id: clinicId,
      national_id: "A123456789",
      dob: "1990-01-01",
      email: "patient@example.com",
      display_name: "測試病人",
    },
  });
  if (!patient.response.ok) {
    throw new Error(`patient_create_failed: ${JSON.stringify(patient.data)}`);
  }
  const patientId = patient.data?.data?.patient_id;
  expect(patientId).toBeTruthy();

  const booking = await jsonFetch("/api/v1/admin/appointments/book", {
    method: "POST",
    body: {
      patient_id: patientId,
      slot_id: slotId,
      notify: true,
    },
  });
  if (!booking.response.ok) {
    throw new Error(`admin_booking_failed: ${JSON.stringify(booking.data)}`);
  }
  const appointmentId = booking.data?.data?.appointment_id;
  const queueNo = booking.data?.data?.queue_no;
  expect(appointmentId).toBeTruthy();
  expect(queueNo).toBeTruthy();

  const checkedIn = await jsonFetch(`/api/v1/admin/appointments/${appointmentId}/status`, {
    method: "POST",
    body: { to_status: "checked_in" },
  });
  if (!checkedIn.response.ok) {
    throw new Error(`checked_in_failed: ${JSON.stringify(checkedIn.data)}`);
  }

  const called = await jsonFetch(`/api/v1/admin/appointments/${appointmentId}/status`, {
    method: "POST",
    body: { to_status: "called", notify: true },
  });
  if (!called.response.ok) {
    throw new Error(`called_failed: ${JSON.stringify(called.data)}`);
  }

  const queueStatus = await jsonFetch(
    `/api/v1/public/queue-status?provider_id=${providerId}&service_date_local=${serviceDate}`
  );
  if (!queueStatus.response.ok) {
    throw new Error(`queue_status_failed: ${JSON.stringify(queueStatus.data)}`);
  }
  expect(Number(queueStatus.data?.data?.current_queue_no ?? 0)).toBe(Number(queueNo));

  const calledJobs = await db.prepare(
    "SELECT COUNT(*) as count FROM notification_job WHERE appointment_id = ? AND event_type = 'queue_called'"
  ).bind(appointmentId).first();
  expect(Number(calledJobs?.count ?? 0)).toBeGreaterThan(0);
});

test("admin daily report and slots csv import/export", async () => {
  const { clinicId, providerId } = await getClinicAndProvider();
  const serviceDate = seededDates[0];

  const report = await jsonFetch(
    `/api/v1/admin/reports/daily?service_date_local=${serviceDate}&clinic_id=${clinicId}&provider_id=${providerId}`
  );
  if (!report.response.ok) {
    throw new Error(`daily_report_failed: ${JSON.stringify(report.data)}`);
  }
  expect(report.data?.data?.service_date_local).toBe(serviceDate);

  const csv = await textFetch(
    `/api/v1/admin/slots/export?service_date_local=${serviceDate}&clinic_id=${clinicId}&provider_id=${providerId}`
  );
  if (!csv.response.ok) {
    throw new Error("slots_export_failed");
  }
  expect(csv.text).toContain("clinic_id,provider_id,service_date_local");

  const csvImport = await jsonFetch("/api/v1/admin/slots/import", {
    method: "POST",
    body: { csv: csv.text },
  });
  if (!csvImport.response.ok) {
    throw new Error(`slots_import_failed: ${JSON.stringify(csvImport.data)}`);
  }
  expect(csvImport.data?.data?.created).toBeGreaterThanOrEqual(0);
});

test("reserved queue numbers are skipped for clinic", async () => {
  const { clinicId, providerId } = await getClinicAndProvider();
  const serviceDate = seededDates[1] || seededDates[0];
  const reserve = await jsonFetch("/api/v1/admin/queue/reserved", {
    method: "POST",
    body: {
      clinic_id: clinicId,
      service_date_local: serviceDate,
      queue_nos: [4, 5],
    },
  });
  if (!reserve.response.ok) {
    throw new Error(`reserve_failed: ${JSON.stringify(reserve.data)}`);
  }

  const slots = await getSlots(clinicId, providerId, serviceDate);
  expect(slots.length).toBeGreaterThan(5);
  const slotIds = slots.slice(0, 6).map((slot) => slot.slot_id);

  const patient = await jsonFetch("/api/v1/admin/patients/quick-create", {
    method: "POST",
    body: {
      clinic_id: clinicId,
      national_id: "A123456789",
      dob: "1990-01-01",
      email: "patient@example.com",
      display_name: "測試病人",
    },
  });
  expect(patient.response.ok).toBe(true);
  const patientId = patient.data?.data?.patient_id;
  expect(patientId).toBeTruthy();

  const queueNos: number[] = [];
  for (const slotId of slotIds) {
    const booking = await jsonFetch("/api/v1/admin/appointments/book", {
      method: "POST",
      body: { patient_id: patientId, slot_id: slotId },
    });
    if (!booking.response.ok) {
      throw new Error(`admin_booking_failed: ${JSON.stringify(booking.data)}`);
    }
    queueNos.push(Number(booking.data?.data?.queue_no ?? 0));
  }

  expect(queueNos).toHaveLength(6);
  expect(queueNos).not.toContain(4);
  expect(queueNos).not.toContain(5);
  expect(Math.max(...queueNos)).toBeGreaterThanOrEqual(6);
});

test("patient is locked after repeated no-show and booking is blocked", async () => {
  const { clinicId, providerId } = await getClinicAndProvider();
  const serviceDate = seededDates[0];
  const slots = await getSlots(clinicId, providerId, serviceDate);
  expect(slots.length).toBeGreaterThan(3);
  const slotIds = slots.slice(0, 4).map((slot) => slot.slot_id);

  const nationalId = makeNationalId("B", 1, [1, 2, 3, 4, 5, 6, 7]);
  const patient = await jsonFetch("/api/v1/admin/patients/quick-create", {
    method: "POST",
    body: {
      clinic_id: clinicId,
      national_id: nationalId,
      dob: "1991-01-01",
      phone: "0912000111",
      display_name: "未到診測試",
    },
  });
  if (!patient.response.ok) {
    throw new Error(`patient_create_failed: ${JSON.stringify(patient.data)}`);
  }
  const patientId = patient.data?.data?.patient_id;
  expect(patientId).toBeTruthy();

  for (const slotId of slotIds.slice(0, 3)) {
    const booking = await jsonFetch("/api/v1/admin/appointments/book", {
      method: "POST",
      body: { patient_id: patientId, slot_id: slotId },
    });
    if (!booking.response.ok) {
      throw new Error(`admin_booking_failed: ${JSON.stringify(booking.data)}`);
    }
    const appointmentId = booking.data?.data?.appointment_id;
    const noShow = await jsonFetch(`/api/v1/admin/appointments/${appointmentId}/status`, {
      method: "POST",
      body: { to_status: "no_show" },
    });
    if (!noShow.response.ok) {
      throw new Error(`no_show_failed: ${JSON.stringify(noShow.data)}`);
    }
  }

  const restriction = await db.prepare(
    "SELECT no_show_count_recent, locked_until FROM patient_restriction WHERE patient_id = ?"
  ).bind(patientId).first();
  expect(Number(restriction?.no_show_count_recent ?? 0)).toBeGreaterThanOrEqual(3);
  expect(Number(restriction?.locked_until ?? 0)).toBeGreaterThan(0);

  const hold = await jsonFetch("/api/v1/public/holds", {
    method: "POST",
    body: { slot_id: slotIds[3] },
  });
  expect(hold.response.ok).toBe(true);
  const holdToken = hold.data?.data?.hold_token;
  expect(holdToken).toBeTruthy();

  const booking = await jsonFetch("/api/v1/public/appointments", {
    method: "POST",
    body: {
      hold_token: holdToken,
      national_id: nationalId,
      dob: "1991-01-01",
      phone: "0912000111",
      display_name: "未到診測試",
    },
  });
  expect(booking.response.status).toBe(403);
  expect(booking.data?.error?.code).toBe("patient_locked");
});
