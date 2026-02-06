import { DurableObject } from "cloudflare:workers";
import { AppError } from "./errors";
import { generateBookingRef, isValidTWId, normalizeTWId } from "./validators";

type Env = {
  DB: D1Database;
  APP_ENV?: string;
};

type CreateHoldInput = {
  slotId: string;
  patientProvisionalKey?: string;
  now?: number;
};

type CreateHoldOutput = {
  holdToken: string;
  expiresAt: number;
};

type ConfirmBookingInput = {
  holdToken: string;
  nationalId: string;
  dob: string;
  displayName?: string;
  phone?: string;
  email?: string;
  source?: string;
  idempotencyKey?: string;
  now?: number;
};

type ConfirmBookingOutput = {
  appointmentId: string;
  bookingRef: string;
  queueNo: number;
  status: string;
  serviceDateLocal: string;
};

type CancelBookingInput = {
  appointmentId: string;
  now?: number;
};

type CancelBookingOutput = {
  status: string;
  cancelledAt: number;
};

type StaffBookingInput = {
  slotId: string;
  patientId: string;
  source?: string;
  now?: number;
};

type StaffBookingOutput = {
  appointmentId: string;
  bookingRef: string;
  queueNo: number;
  status: string;
  serviceDateLocal: string;
};

const HOLD_TTL_MS = 5 * 60 * 1000;

export class BookingDurableObject extends DurableObject<Env> {
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.env = env;
  }

  private async allocateQueueNo(
    clinicId: string,
    providerId: string,
    serviceDateLocal: string
  ): Promise<number> {
    const reservedResult = await this.env.DB.prepare(
      `SELECT queue_no FROM queue_reserved
       WHERE clinic_id = ? AND service_date_local = ?`
    ).bind(clinicId, serviceDateLocal).all();
    const reservedSet = new Set(
      (reservedResult.results ?? []).map((row) => Number(row.queue_no))
    );

    const counterRow = await this.env.DB.prepare(
      `SELECT next_queue_no FROM queue_counter
       WHERE provider_id = ? AND service_date_local = ?`
    ).bind(providerId, serviceDateLocal).first();

    let queueNo = counterRow ? Number(counterRow.next_queue_no) : 1;
    while (reservedSet.has(queueNo)) {
      queueNo += 1;
    }

    const nextQueueNo = queueNo + 1;
    if (!counterRow) {
      await this.env.DB.prepare(
        `INSERT INTO queue_counter (provider_id, service_date_local, next_queue_no)
         VALUES (?, ?, ?)`
      ).bind(providerId, serviceDateLocal, nextQueueNo).run();
    } else {
      await this.env.DB.prepare(
        `UPDATE queue_counter
         SET next_queue_no = ?
         WHERE provider_id = ? AND service_date_local = ?`
      ).bind(nextQueueNo, providerId, serviceDateLocal).run();
    }

    return queueNo;
  }

  async createHold(input: CreateHoldInput): Promise<CreateHoldOutput> {
    if (!input?.slotId) {
      throw new AppError("validation_error", 400, { slot_id: "required" });
    }

    const now = input.now ?? Date.now();
    const slotRow = await this.env.DB.prepare(
      `SELECT slot.id, slot.clinic_id, slot.provider_id, slot.status,
              slot_inventory.capacity, slot_inventory.booked_count
       FROM slot
       JOIN slot_inventory ON slot_inventory.slot_id = slot.id
       WHERE slot.id = ?`
    ).bind(input.slotId).first();

    if (!slotRow) {
      throw new AppError("not_found", 404, { slot_id: "not_found" });
    }

    if (slotRow.status !== "open") {
      throw new AppError("slot_closed", 409);
    }

    const holdCountRow = await this.env.DB.prepare(
      `SELECT COUNT(1) as hold_count
       FROM appointment_hold
       WHERE slot_id = ? AND expires_at > ?`
    ).bind(input.slotId, now).first();

    const activeHolds = Number(holdCountRow?.hold_count ?? 0);
    const capacity = Number(slotRow.capacity ?? 0);
    const bookedCount = Number(slotRow.booked_count ?? 0);

    if (bookedCount + activeHolds >= capacity) {
      throw new AppError("slot_full", 409);
    }

    const holdToken = crypto.randomUUID();
    const expiresAt = now + HOLD_TTL_MS;

    await this.env.DB.prepare(
      `INSERT INTO appointment_hold
        (id, slot_id, clinic_id, provider_id, patient_provisional_key, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      holdToken,
      input.slotId,
      slotRow.clinic_id,
      slotRow.provider_id,
      input.patientProvisionalKey ?? null,
      expiresAt,
      now
    ).run();

    return { holdToken, expiresAt };
  }

  async confirmBooking(input: ConfirmBookingInput): Promise<ConfirmBookingOutput> {
    if (!input?.holdToken) {
      throw new AppError("validation_error", 400, { hold_token: "required" });
    }
    if (!input.nationalId || !isValidTWId(input.nationalId, true)) {
      throw new AppError("validation_error", 400, { national_id: "invalid" });
    }
    if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(input.dob)) {
      throw new AppError("validation_error", 400, { dob: "invalid" });
    }
    if (!input.phone && !input.email) {
      throw new AppError("validation_error", 400, { contact: "required" });
    }

    const now = input.now ?? Date.now();
    const idempotencyKey = input.idempotencyKey?.trim();
    let idempotencyInserted = false;

    if (idempotencyKey) {
      const existing = await this.env.DB.prepare(
        `SELECT response_json FROM idempotency_key
         WHERE key = ? AND scope = 'public_booking'`
      ).bind(idempotencyKey).first();
      if (existing?.response_json) {
        return JSON.parse(existing.response_json as string) as ConfirmBookingOutput;
      }
      if (existing) {
        throw new AppError("conflict", 409, { idempotency: "in_progress" });
      }
      await this.env.DB.prepare(
        `INSERT INTO idempotency_key (key, scope, response_json, created_at)
         VALUES (?, 'public_booking', NULL, ?)`
      ).bind(idempotencyKey, now).run();
      idempotencyInserted = true;
    }
    try {
      const holdRow = await this.env.DB.prepare(
        `SELECT id, slot_id, clinic_id, provider_id, expires_at
         FROM appointment_hold
         WHERE id = ?`
      ).bind(input.holdToken).first();

      if (!holdRow || Number(holdRow.expires_at) <= now) {
        throw new AppError("hold_expired", 410);
      }

      const slotRow = await this.env.DB.prepare(
        `SELECT slot.id, slot.service_date_local
         FROM slot
         WHERE slot.id = ?`
      ).bind(holdRow.slot_id).first();

      if (!slotRow) {
        throw new AppError("not_found", 404, { slot_id: "not_found" });
      }

      const clinicRow = await this.env.DB.prepare(
        `SELECT org_id FROM clinic WHERE id = ?`
      ).bind(holdRow.clinic_id).first();

      if (!clinicRow) {
        throw new AppError("not_found", 404, { clinic_id: "not_found" });
      }

      const normalizedId = normalizeTWId(input.nationalId);
      let patientId: string | null = null;

      const identityRow = await this.env.DB.prepare(
        `SELECT patient_id, dob FROM patient_identity WHERE national_id = ?`
      ).bind(normalizedId).first();

      if (identityRow) {
        if (identityRow.dob !== input.dob) {
          throw new AppError("validation_error", 400, { dob: "mismatch" });
        }
        patientId = identityRow.patient_id as string;
      }

      if (!patientId) {
        patientId = crypto.randomUUID();
        await this.env.DB.prepare(
          `INSERT INTO patient (id, org_id, display_name, gender, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(
          patientId,
          clinicRow.org_id,
          input.displayName ?? null,
          null,
          now,
          now
        ).run();

        await this.env.DB.prepare(
          `INSERT INTO patient_identity (patient_id, national_id, dob, verified_level, created_at, updated_at)
           VALUES (?, ?, ?, 0, ?, ?)`
        ).bind(patientId, normalizedId, input.dob, now, now).run();
      }

      if (input.phone) {
        await this.env.DB.prepare(
          `INSERT OR IGNORE INTO patient_contact
             (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
           VALUES (?, ?, ?, 'phone', ?, 1, 0, ?)`
        ).bind(crypto.randomUUID(), clinicRow.org_id, patientId, input.phone, now).run();
      }

      if (input.email) {
        await this.env.DB.prepare(
          `INSERT OR IGNORE INTO patient_contact
             (id, org_id, patient_id, type, value, is_primary, is_verified, created_at)
           VALUES (?, ?, ?, 'email', ?, 0, 0, ?)`
        ).bind(crypto.randomUUID(), clinicRow.org_id, patientId, input.email, now).run();
      }

      const restrictionRow = await this.env.DB.prepare(
        `SELECT locked_until FROM patient_restriction WHERE patient_id = ?`
      ).bind(patientId).first();

      if (restrictionRow?.locked_until && Number(restrictionRow.locked_until) > now) {
        throw new AppError("patient_locked", 403);
      }

      const appointmentId = crypto.randomUUID();
      const bookingRef = generateBookingRef();
      const source = input.source ?? "patient_web";

      const useTx = this.env.APP_ENV !== "dev" && this.env.APP_ENV !== "test";
      if (useTx) {
        await this.env.DB.exec("BEGIN");
      }
      try {
        const updateResult = await this.env.DB.prepare(
          `UPDATE slot_inventory
           SET booked_count = booked_count + 1, version = version + 1
           WHERE slot_id = ? AND booked_count < capacity`
        ).bind(holdRow.slot_id).run();

        if (updateResult.meta.changes !== 1) {
          throw new AppError("slot_full", 409);
        }

        const queueNo = await this.allocateQueueNo(
          holdRow.clinic_id as string,
          holdRow.provider_id as string,
          slotRow.service_date_local as string
        );

        await this.env.DB.prepare(
          `INSERT INTO appointment
            (id, org_id, clinic_id, provider_id, slot_id, patient_id, service_date_local,
             queue_no, source, status, booking_ref, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'booked', ?, ?, ?)`
        ).bind(
          appointmentId,
          clinicRow.org_id,
          holdRow.clinic_id,
          holdRow.provider_id,
          holdRow.slot_id,
          patientId,
          slotRow.service_date_local,
          queueNo,
          source,
          bookingRef,
          now,
          now
        ).run();

        await this.env.DB.prepare(
          `DELETE FROM appointment_hold WHERE id = ?`
        ).bind(input.holdToken).run();

        if (useTx) {
          await this.env.DB.exec("COMMIT");
        }
        const output = {
          appointmentId,
          bookingRef,
          queueNo,
          status: "booked",
          serviceDateLocal: slotRow.service_date_local as string,
        };

        if (idempotencyKey) {
          await this.env.DB.prepare(
            `UPDATE idempotency_key
             SET response_json = ?
             WHERE key = ? AND scope = 'public_booking'`
          ).bind(JSON.stringify(output), idempotencyKey).run();
        }

        return output;
      } catch (error) {
        if (useTx) {
          await this.env.DB.exec("ROLLBACK");
        }
        if (error instanceof AppError) {
          throw error;
        }
        throw new AppError("conflict", 409);
      }
    } catch (error) {
      if (idempotencyInserted && idempotencyKey) {
        await this.env.DB.prepare(
          `DELETE FROM idempotency_key WHERE key = ? AND scope = 'public_booking'`
        ).bind(idempotencyKey).run();
      }
      throw error;
    }
  }

  async cancelBooking(input: CancelBookingInput): Promise<CancelBookingOutput> {
    if (!input?.appointmentId) {
      throw new AppError("validation_error", 400, { appointment_id: "required" });
    }

    const now = input.now ?? Date.now();
    const appointmentRow = await this.env.DB.prepare(
      `SELECT id, slot_id, status
       FROM appointment
       WHERE id = ?`
    ).bind(input.appointmentId).first();

    if (!appointmentRow) {
      throw new AppError("not_found", 404, { appointment_id: "not_found" });
    }

    if (["cancelled", "done", "no_show"].includes(appointmentRow.status)) {
      throw new AppError("conflict", 409, { status: "not_cancelable" });
    }

    const useTx = this.env.APP_ENV !== "dev" && this.env.APP_ENV !== "test";
    if (useTx) {
      await this.env.DB.exec("BEGIN");
    }
    try {
      const updateAppointment = await this.env.DB.prepare(
        `UPDATE appointment
         SET status = 'cancelled', cancelled_at = ?, updated_at = ?
         WHERE id = ?`
      ).bind(now, now, input.appointmentId).run();

      if (updateAppointment.meta.changes !== 1) {
        throw new AppError("conflict", 409);
      }

      await this.env.DB.prepare(
        `UPDATE slot_inventory
         SET booked_count = booked_count - 1, version = version + 1
         WHERE slot_id = ? AND booked_count > 0`
      ).bind(appointmentRow.slot_id).run();

      if (useTx) {
        await this.env.DB.exec("COMMIT");
      }
      return { status: "cancelled", cancelledAt: now };
    } catch (error) {
      if (useTx) {
        await this.env.DB.exec("ROLLBACK");
      }
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError("conflict", 409);
    }
  }

  async bookSlotForPatient(input: StaffBookingInput): Promise<StaffBookingOutput> {
    if (!input?.slotId) {
      throw new AppError("validation_error", 400, { slot_id: "required" });
    }
    if (!input?.patientId) {
      throw new AppError("validation_error", 400, { patient_id: "required" });
    }

    const now = input.now ?? Date.now();
    const slotRow = await this.env.DB.prepare(
      `SELECT slot.id, slot.clinic_id, slot.provider_id, slot.status, slot.service_date_local
       FROM slot
       WHERE slot.id = ?`
    ).bind(input.slotId).first();

    if (!slotRow) {
      throw new AppError("not_found", 404, { slot_id: "not_found" });
    }

    if (slotRow.status !== "open") {
      throw new AppError("slot_closed", 409);
    }

    const clinicRow = await this.env.DB.prepare(
      `SELECT org_id FROM clinic WHERE id = ?`
    ).bind(slotRow.clinic_id).first();

    if (!clinicRow) {
      throw new AppError("not_found", 404, { clinic_id: "not_found" });
    }

    const restrictionRow = await this.env.DB.prepare(
      `SELECT locked_until FROM patient_restriction WHERE patient_id = ?`
    ).bind(input.patientId).first();

    if (restrictionRow?.locked_until && Number(restrictionRow.locked_until) > now) {
      throw new AppError("patient_locked", 403);
    }

    const appointmentId = crypto.randomUUID();
    const bookingRef = generateBookingRef();
    const source = input.source ?? "staff_admin";

    const useTx = this.env.APP_ENV !== "dev" && this.env.APP_ENV !== "test";
    if (useTx) {
      await this.env.DB.exec("BEGIN");
    }
    try {
      const updateResult = await this.env.DB.prepare(
        `UPDATE slot_inventory
         SET booked_count = booked_count + 1, version = version + 1
         WHERE slot_id = ? AND booked_count < capacity`
      ).bind(input.slotId).run();

      if (updateResult.meta.changes !== 1) {
        throw new AppError("slot_full", 409);
      }

      const queueNo = await this.allocateQueueNo(
        slotRow.clinic_id as string,
        slotRow.provider_id as string,
        slotRow.service_date_local as string
      );

      await this.env.DB.prepare(
        `INSERT INTO appointment
          (id, org_id, clinic_id, provider_id, slot_id, patient_id, service_date_local,
           queue_no, source, status, booking_ref, created_at, updated_at, note_internal)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'booked', ?, ?, ?, ?)`
      ).bind(
        appointmentId,
        clinicRow.org_id,
        slotRow.clinic_id,
        slotRow.provider_id,
        slotRow.id,
        input.patientId,
        slotRow.service_date_local,
        queueNo,
        source,
        bookingRef,
        now,
        now,
        "rescheduled"
      ).run();

      if (useTx) {
        await this.env.DB.exec("COMMIT");
      }

      return {
        appointmentId,
        bookingRef,
        queueNo,
        status: "booked",
        serviceDateLocal: slotRow.service_date_local as string,
      };
    } catch (error) {
      if (useTx) {
        await this.env.DB.exec("ROLLBACK");
      }
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError("conflict", 409);
    }
  }
}
