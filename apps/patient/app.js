import {
  normalizeTWId,
  isValidTWId,
  normalizeBookingRef,
  isValidBookingRef,
  generateBookingRef,
} from "./validators.js";

const apiBase = document.body.dataset.apiBase || "/api/v1";
const mockEnabled = document.body.dataset.mock === "true";
const turnstileSiteKey = document.body.dataset.turnstileSiteKey || "";
const WEEKDAYS = ["週日", "週一", "週二", "週三", "週四", "週五", "週六"];

const el = {
  clinicSelect: document.getElementById("clinic-select"),
  specialtySelect: document.getElementById("specialty-select"),
  doctorSearch: document.getElementById("doctor-search"),
  quickDateButtons: Array.from(document.querySelectorAll("[data-role='quick-date']")),
  selectedDateDisplay: document.getElementById("selected-date-display"),
  slotDateLabel: document.getElementById("slot-date-label"),
  slotGrid: document.getElementById("slot-grid"),
  slotsEmpty: document.getElementById("slots-empty"),
  doctorPhoto: document.getElementById("doctor-photo"),
  doctorName: document.getElementById("doctor-name"),
  doctorTitle: document.getElementById("doctor-title"),
  doctorSpecialtyBadge: document.getElementById("doctor-specialty-badge"),
  doctorTags: document.getElementById("doctor-tags"),
  bookingModal: document.getElementById("booking-modal"),
  bookingBackdrop: document.querySelector("#booking-modal [data-role='backdrop']"),
  bookingClose: document.getElementById("booking-close"),
  bookingCancel: document.getElementById("booking-cancel"),
  bookingForm: document.getElementById("booking-form"),
  bookingClinic: document.getElementById("booking-clinic"),
  bookingDoctor: document.getElementById("booking-doctor"),
  bookingTitle: document.getElementById("booking-title"),
  bookingDatetime: document.getElementById("booking-datetime"),
  patientName: document.getElementById("patient-name"),
  patientId: document.getElementById("patient-id"),
  patientDob: document.getElementById("patient-dob"),
  patientPhone: document.getElementById("patient-phone"),
  patientEmail: document.getElementById("patient-email"),
  idError: document.getElementById("id-error"),
  termsCheck: document.getElementById("terms-check"),
  formError: document.getElementById("form-error"),
  formSuccess: document.getElementById("form-success"),
  bookingRefOutput: document.getElementById("booking-ref-output"),
  bookingRefCopy: document.getElementById("booking-ref-copy"),
  bookingRefCopied: document.getElementById("booking-ref-copied"),
  bookingIcsLink: document.getElementById("booking-ics-link"),
  bookingCheckinButton: document.getElementById("booking-checkin-button"),
  bookingCheckinPanel: document.getElementById("booking-checkin-panel"),
  bookingCheckinQr: document.getElementById("booking-checkin-qr"),
  bookingCheckinUrl: document.getElementById("booking-checkin-url"),
  bookingCheckinExpiry: document.getElementById("booking-checkin-expiry"),
  turnstileWrapper: document.getElementById("turnstile-wrapper"),
  turnstileContainer: document.getElementById("turnstile-container"),
  turnstileError: document.getElementById("turnstile-error"),
  emailVerifySection: document.getElementById("email-verify-section"),
  emailVerifyToggle: document.getElementById("email-verify-toggle"),
  emailVerifySend: document.getElementById("email-verify-send"),
  emailVerifyCode: document.getElementById("email-verify-code"),
  emailVerifyStatus: document.getElementById("email-verify-status"),
  emailVerifyDebug: document.getElementById("email-verify-debug"),
  lookupForm: document.getElementById("lookup-form"),
  lookupBookingRef: document.getElementById("lookup-booking-ref"),
  lookupDob: document.getElementById("lookup-dob"),
  lookupPhone: document.getElementById("lookup-phone"),
  lookupEmail: document.getElementById("lookup-email"),
  lookupRefError: document.getElementById("lookup-ref-error"),
  lookupError: document.getElementById("lookup-error"),
  lookupSuccess: document.getElementById("lookup-success"),
  lookupActionLabel: document.getElementById("lookup-action-label"),
  authLoginForm: document.getElementById("auth-login-form"),
  authLoginMessage: document.getElementById("auth-login-message"),
  authBindForm: document.getElementById("auth-bind-form"),
  authBindMessage: document.getElementById("auth-bind-message"),
  memberRefresh: document.getElementById("member-refresh"),
  memberStatus: document.getElementById("member-status"),
  memberAppointments: document.getElementById("member-appointments"),
  memberMessage: document.getElementById("member-message"),
};

const state = {
  clinics: [],
  providers: [],
  slots: [],
  selectedClinicId: "",
  selectedProviderId: "",
  selectedDate: "",
  selectedDateLabel: "",
  selectedSlot: null,
  holdToken: "",
  emailVerification: null,
  turnstileToken: "",
  useEmailVerification: false,
};

const mockData = {
  clinics: [
    { id: "clinic-tp", name: "台北敦南院區 (總院)" },
    { id: "clinic-tp2", name: "台北站前院區" },
    { id: "clinic-tc", name: "台中公益院區" },
    { id: "clinic-ks", name: "高雄博愛院區" },
  ],
  providers: [
    {
      id: "provider-retina",
      clinic_id: "clinic-tp",
      name: "王大明 醫師",
      title: "視網膜專家門診",
      specialty: "retina",
      photo_url:
        "https://lh3.googleusercontent.com/aida-public/AB6AXuB8seP-4B0_0ico_5tpy7rDR4dHBFitxyQ9cwIKUzT3CRPEoWGWbzbu78I9SpoR6JrFCXXYBvO64hpZr_boO5oyyA6dzBbA1p3ZXV39Brso1kC90Ph1-kaa86j1gGoDNSldEXaadSoM1FuzovX4bjzpyKEvfcAiqBOR-XR8m82J_bvNKyfxQ0w0hExUrN3924yoSshHF_bflDCZcJZwWwlqXOX4OrhRg79AlmL04IPbDdKdFzwMQc7it2l_irH3ME8ozXZzv8q2qKzo",
    },
    {
      id: "provider-glaucoma",
      clinic_id: "clinic-tp",
      name: "陳美玲 醫師",
      title: "青光眼專家門診",
      specialty: "glaucoma",
      photo_url: "",
    },
  ],
};

const mockStore = {
  holds: {},
  appointments: {},
  slotCache: {},
  emailVerifications: {},
};

function getOrCreateDeviceId() {
  const key = "clinicDeviceId";
  let current = localStorage.getItem(key);
  if (!current) {
    current = crypto?.randomUUID
      ? crypto.randomUUID()
      : `device_${Math.random().toString(36).slice(2, 10)}`;
    localStorage.setItem(key, current);
  }
  return current;
}

const deviceId = getOrCreateDeviceId();

function setHidden(node, hidden) {
  if (!node) return;
  node.classList.toggle("hidden", hidden);
}

function setText(node, text) {
  if (!node) return;
  node.textContent = text ?? "";
}

function formatDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function buildDateLabel(value) {
  const date = new Date(`${value}T00:00:00`);
  if (Number.isNaN(date.getTime())) return value;
  return `${formatDate(date)} (${WEEKDAYS[date.getDay()]})`;
}

function formatTime(ms) {
  const date = new Date(ms);
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${hours}:${minutes}`;
}

function formatIcsDate(ms) {
  return new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function buildCalendarText(appointment) {
  return [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Clinic Booking//EN",
    "BEGIN:VEVENT",
    `UID:${appointment.booking_ref}`,
    `DTSTAMP:${formatIcsDate(Date.now())}`,
    `DTSTART:${formatIcsDate(appointment.start_at_utc)}`,
    `DTEND:${formatIcsDate(appointment.end_at_utc)}`,
    `SUMMARY:${appointment.summary}`,
    "END:VEVENT",
    "END:VCALENDAR",
  ].join("\n");
}

function extractApiError(error) {
  if (error?.data?.error) return error.data.error;
  if (error?.code) return { code: error.code, fields: error.fields };
  return { code: "unknown" };
}

function buildErrorMessage(apiError) {
  const code = apiError?.code;
  const fields = apiError?.fields || {};
  if (code === "patient_locked") {
    return "因多次未到診，網路掛號權限已停止，請洽櫃台協助解鎖。";
  }
  if (code === "turnstile_required") return "請完成 Turnstile 驗證或改用 Email 驗證碼。";
  if (code === "turnstile_failed") return "Turnstile 驗證失敗，請重試或改用 Email 驗證碼。";
  if (code === "email_verification_required") return "請先完成 Email 驗證碼。";
  if (code === "email_verification_too_soon") return "驗證碼寄送太頻繁，請稍後再試。";
  if (code === "email_verification_locked") return "驗證碼錯誤次數過多，請稍後再試。";
  if (code && code.startsWith("email_verification")) {
    return "Email 驗證碼錯誤或過期，請重新寄送。";
  }
  if (code === "validation_error") {
    if (fields.display_name) return "請輸入姓名。";
    if (fields.national_id) return "身分證格式不正確。";
    if (fields.dob) return "生日格式不正確。";
    if (fields.contact) return "請填寫手機或 Email。";
  }
  return `操作失敗：${code || "unknown"}`;
}

function buildMockSlots(clinicId, providerId, serviceDate) {
  const key = `${clinicId}:${providerId}:${serviceDate}`;
  if (mockStore.slotCache[key]) return mockStore.slotCache[key];
  const times = [
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
  const slots = times.map((time, index) => {
    const start = new Date(`${serviceDate}T${time}:00+08:00`).getTime();
    return {
      slot_id: `${key}:${time}`,
      clinic_id: clinicId,
      provider_id: providerId,
      service_date_local: serviceDate,
      start_at_utc: start,
      end_at_utc: start + 15 * 60 * 1000,
      capacity: 4,
      booked_count: index % 5 === 0 ? 4 : 0,
      status: "open",
    };
  });
  mockStore.slotCache[key] = slots;
  return slots;
}

function mockFindSlot(slotId) {
  const lists = Object.values(mockStore.slotCache);
  for (const list of lists) {
    const found = list.find((slot) => slot.slot_id === slotId);
    if (found) return found;
  }
  return null;
}

function mockCreateHold(slotId) {
  const slot = mockFindSlot(slotId);
  if (!slot) throw { code: "not_found" };
  if (slot.booked_count >= slot.capacity) throw { code: "slot_full" };
  const holdToken = `hold_${generateBookingRef(10)}`;
  const expiresAt = Date.now() + 10 * 60 * 1000;
  mockStore.holds[holdToken] = { slotId, expiresAt };
  return { hold_token: holdToken, expires_at: expiresAt };
}

function mockCreateAppointment(payload) {
  const normalizedId = normalizeTWId(payload.national_id || "");
  if (!payload.display_name) throw { code: "validation_error", fields: { display_name: "required" } };
  if (!isValidTWId(normalizedId)) throw { code: "validation_error", fields: { national_id: "invalid" } };
  if (!payload.dob) throw { code: "validation_error", fields: { dob: "invalid" } };
  if (!payload.phone && !payload.email) throw { code: "validation_error", fields: { contact: "required" } };
  const hold = mockStore.holds[payload.hold_token];
  if (!hold || hold.expiresAt <= Date.now()) throw { code: "hold_expired" };
  const slot = mockFindSlot(hold.slotId);
  if (!slot) throw { code: "not_found" };
  if (slot.booked_count >= slot.capacity) throw { code: "slot_full" };
  slot.booked_count += 1;
  const bookingRef = generateBookingRef();
  const appointment = {
    booking_ref: bookingRef,
    queue_no: Object.keys(mockStore.appointments).length + 1,
    status: "booked",
    service_date_local: slot.service_date_local,
    start_at_utc: slot.start_at_utc,
    end_at_utc: slot.end_at_utc,
  };
  mockStore.appointments[bookingRef] = appointment;
  return {
    appointment_id: `apt_${generateBookingRef(8)}`,
    booking_ref: bookingRef,
    queue_no: appointment.queue_no,
    status: appointment.status,
    service_date_local: appointment.service_date_local,
  };
}

function mockLookupAppointment(bookingRef) {
  const appointment = mockStore.appointments[bookingRef];
  if (!appointment) throw { code: "not_found" };
  return appointment;
}

function mockCancelAppointment(bookingRef) {
  const appointment = mockStore.appointments[bookingRef];
  if (!appointment) throw { code: "not_found" };
  appointment.status = "cancelled";
  return { status: appointment.status };
}

function mockCheckinToken(bookingRef) {
  const appointment = mockStore.appointments[bookingRef];
  if (!appointment) throw { code: "not_found" };
  const token = `checkin_${generateBookingRef(10)}`;
  const expiresAt = Date.now() + 10 * 60 * 1000;
  mockStore.holds[token] = { bookingRef, expiresAt };
  return { checkin_token: token, expires_at: expiresAt };
}

function mockRequestEmailVerification(email) {
  const id = `ev_${generateBookingRef(10)}`;
  const code = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
  const expiresAt = Date.now() + 10 * 60 * 1000;
  mockStore.emailVerifications[id] = { email, code, expiresAt };
  return { verification_id: id, expires_at: expiresAt, debug_code: code };
}

async function fetchJson(path, init = {}) {
  const headers = { "x-device-id": deviceId, ...(init.headers || {}) };
  if (init.body !== undefined && !headers["content-type"]) headers["content-type"] = "application/json";
  const body = init.body && typeof init.body !== "string" ? JSON.stringify(init.body) : init.body;
  const response = await fetch(`${apiBase}${path}`, { ...init, headers, body });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const error = new Error("api_error");
    error.data = data;
    throw error;
  }
  return data;
}

const api = {
  async listClinics() {
    if (mockEnabled) return mockData.clinics;
    const result = await fetchJson("/public/clinics");
    return result?.data ?? [];
  },
  async listProviders({ clinicId, specialty, query }) {
    if (mockEnabled) {
      return mockData.providers.filter((provider) => {
        if (clinicId && provider.clinic_id !== clinicId) return false;
        if (specialty && specialty !== "all" && provider.specialty !== specialty) return false;
        if (query && !provider.name.includes(query)) return false;
        return true;
      });
    }
    const params = new URLSearchParams();
    if (clinicId) params.set("clinic_id", clinicId);
    if (specialty) params.set("specialty", specialty);
    if (query) params.set("q", query);
    const result = await fetchJson(`/public/providers?${params.toString()}`);
    return result?.data ?? [];
  },
  async listSlots({ clinicId, providerId, serviceDate }) {
    if (mockEnabled) return buildMockSlots(clinicId, providerId, serviceDate);
    const params = new URLSearchParams();
    params.set("clinic_id", clinicId);
    params.set("provider_id", providerId);
    params.set("service_date_local", serviceDate);
    const result = await fetchJson(`/public/slots?${params.toString()}`);
    return result?.data ?? [];
  },
  async createHold(slotId) {
    if (mockEnabled) return mockCreateHold(slotId);
    const result = await fetchJson("/public/holds", { method: "POST", body: { slot_id: slotId } });
    return result?.data;
  },
  async createAppointment(payload) {
    if (mockEnabled) return mockCreateAppointment(payload);
    const idempotencyKey = crypto?.randomUUID ? crypto.randomUUID() : `id_${Date.now()}`;
    const result = await fetchJson("/public/appointments", {
      method: "POST",
      headers: { "x-idempotency-key": idempotencyKey },
      body: payload,
    });
    return result?.data;
  },
  async lookupAppointment(bookingRef, params) {
    if (mockEnabled) return mockLookupAppointment(bookingRef);
    const query = new URLSearchParams(params);
    const result = await fetchJson(`/public/appointments/${bookingRef}?${query.toString()}`);
    return result?.data;
  },
  async cancelAppointment(bookingRef, payload) {
    if (mockEnabled) return mockCancelAppointment(bookingRef);
    const result = await fetchJson(`/public/appointments/${bookingRef}/cancel`, { method: "POST", body: payload });
    return result?.data;
  },
  async createCheckinToken(bookingRef, payload) {
    if (mockEnabled) return mockCheckinToken(bookingRef);
    const result = await fetchJson(`/public/appointments/${bookingRef}/checkin-token`, {
      method: "POST",
      body: payload,
    });
    return result?.data;
  },
  async requestEmailVerification(email) {
    if (mockEnabled) return mockRequestEmailVerification(email);
    const result = await fetchJson("/public/email-verifications", {
      method: "POST",
      body: { email, purpose: "booking" },
    });
    return result?.data;
  },
};

function updateSelectedDate(dateStr) {
  state.selectedDate = dateStr;
  state.selectedDateLabel = buildDateLabel(dateStr);
  document.body.dataset.selectedDate = dateStr;
  document.body.dataset.selectedDateLabel = state.selectedDateLabel;
  setText(el.selectedDateDisplay, `已選日期：${state.selectedDateLabel}`);
  setText(el.slotDateLabel, `目前日期：${state.selectedDateLabel}`);
  el.quickDateButtons.forEach((button) => {
    button.classList.toggle("is-selected", button.dataset.date === dateStr);
  });
  loadSlots();
}

function initQuickDates() {
  const baseDate = new Date();
  el.quickDateButtons.forEach((button, index) => {
    const date = new Date(baseDate);
    date.setDate(baseDate.getDate() + index);
    const dateStr = formatDate(date);
    button.dataset.date = dateStr;
    button.dataset.weekday = WEEKDAYS[date.getDay()];
    const spans = button.querySelectorAll("span");
    if (spans[0]) spans[0].textContent = WEEKDAYS[date.getDay()];
    if (spans[1]) spans[1].textContent = String(date.getDate());
  });
  updateSelectedDate(el.quickDateButtons[0]?.dataset.date || formatDate(baseDate));
}

async function loadClinics() {
  state.clinics = await api.listClinics();
  if (el.clinicSelect) {
    el.clinicSelect.innerHTML = "";
    state.clinics.forEach((clinic) => {
      const option = document.createElement("option");
      option.value = clinic.id;
      option.textContent = clinic.name;
      el.clinicSelect.appendChild(option);
    });
    state.selectedClinicId = el.clinicSelect.value || state.clinics[0]?.id || "";
  }
  await loadProviders();
}

async function loadProviders() {
  if (!state.selectedClinicId) return;
  const specialty = el.specialtySelect?.value || "all";
  const query = el.doctorSearch?.value?.trim() || "";
  state.providers = await api.listProviders({ clinicId: state.selectedClinicId, specialty, query });
  state.selectedProviderId = state.providers[0]?.id || "";
  renderDoctor();
  await loadSlots();
}

async function loadSlots() {
  if (!state.selectedClinicId || !state.selectedProviderId || !state.selectedDate) return;
  try {
    state.slots = await api.listSlots({
      clinicId: state.selectedClinicId,
      providerId: state.selectedProviderId,
      serviceDate: state.selectedDate,
    });
    renderSlots();
  } catch (error) {
    state.slots = [];
    renderSlots("尚無可預約時段");
  }
}

function renderDoctor() {
  const provider = state.providers[0];
  if (!provider) return;
  setText(el.doctorName, provider.name || "-");
  setText(el.doctorTitle, provider.title || "");
  if (provider.specialty && el.doctorSpecialtyBadge) {
    el.doctorSpecialtyBadge.textContent = provider.specialty;
    setHidden(el.doctorSpecialtyBadge, false);
  }
  if (el.doctorPhoto && provider.photo_url) {
    el.doctorPhoto.style.backgroundImage = `url('${provider.photo_url}')`;
  }
  if (el.doctorTags) {
    el.doctorTags.innerHTML = "";
    if (provider.specialty) {
      const tag = document.createElement("span");
      tag.className = "px-3 py-1.5 bg-gray-100 dark:bg-gray-800 text-[#617589] text-sm rounded-lg";
      tag.textContent = provider.specialty;
      el.doctorTags.appendChild(tag);
    }
  }
}

function renderSlots(emptyMessage) {
  if (!el.slotGrid) return;
  el.slotGrid.innerHTML = "";
  const slots = state.slots || [];
  const hasSlots = slots.length > 0;
  setHidden(el.slotsEmpty, hasSlots);
  if (!hasSlots && el.slotsEmpty) {
    el.slotsEmpty.textContent = emptyMessage || "尚無可預約時段";
  }
  slots.forEach((slot) => {
    const isAvailable = slot.status === "open" && Number(slot.booked_count) < Number(slot.capacity);
    const button = document.createElement("button");
    button.textContent = formatTime(slot.start_at_utc);
    button.className = `slot-btn ${isAvailable ? "slot-btn-available" : "slot-btn-booked"}`;
    if (!isAvailable) button.disabled = true;
    button.addEventListener("click", () => openBookingModal(slot));
    el.slotGrid.appendChild(button);
  });
}

function resetBookingStatus(resetEmail = false) {
  setHidden(el.formError, true);
  setHidden(el.formSuccess, true);
  setHidden(el.bookingCheckinPanel, true);
  setHidden(el.turnstileError, true);
  if (el.emailVerifyStatus) setText(el.emailVerifyStatus, "");
  if (el.emailVerifyDebug) setHidden(el.emailVerifyDebug, true);
  if (el.bookingRefCopied) setHidden(el.bookingRefCopied, true);
  if (resetEmail) {
    state.emailVerification = null;
    setEmailVerificationVisible(false);
  }
}

function setEmailVerificationVisible(visible) {
  state.useEmailVerification = visible;
  setHidden(el.emailVerifySection, !visible);
  if (el.emailVerifyToggle) {
    el.emailVerifyToggle.textContent = visible ? "收起 Email 驗證碼" : "改用 Email 驗證碼";
    el.emailVerifyToggle.setAttribute("aria-expanded", visible ? "true" : "false");
  }
}

async function openBookingModal(slot) {
  state.selectedSlot = slot;
  const clinic = state.clinics.find((item) => item.id === state.selectedClinicId);
  const provider = state.providers.find((item) => item.id === state.selectedProviderId);
  setText(el.bookingClinic, clinic?.name || "-");
  setText(el.bookingDoctor, provider?.name || "-");
  setText(el.bookingTitle, provider?.title || "");
  setText(el.bookingDatetime, `${state.selectedDateLabel} ${formatTime(slot.start_at_utc)}`);
  setHidden(el.bookingModal, false);
  document.body.style.overflow = "hidden";
  resetBookingStatus(true);
  await ensureHoldToken();
}

function closeBookingModal() {
  setHidden(el.bookingModal, true);
  document.body.style.overflow = "";
}

async function ensureHoldToken() {
  if (!state.selectedSlot) return;
  try {
    const result = await api.createHold(state.selectedSlot.slot_id);
    state.holdToken = result?.hold_token || "";
  } catch (error) {
    const apiError = extractApiError(error);
    setText(el.formError, buildErrorMessage(apiError));
    setHidden(el.formError, false);
  }
}

function validateBookingInput() {
  const displayName = el.patientName?.value?.trim() || "";
  const nationalId = normalizeTWId(el.patientId?.value || "");
  const dob = el.patientDob?.value || "";
  const phone = el.patientPhone?.value?.trim() || "";
  const email = el.patientEmail?.value?.trim() || "";
  if (!displayName) return { valid: false, message: "請輸入姓名" };
  if (!isValidTWId(nationalId)) return { valid: false, message: "身分證格式不正確" };
  if (!dob) return { valid: false, message: "請輸入生日" };
  if (!phone && !email) return { valid: false, message: "請填寫手機或 Email" };
  if (!el.termsCheck?.checked) return { valid: false, message: "請勾選同意服務條款" };
  return { valid: true, data: { displayName, nationalId, dob, phone, email } };
}

async function submitBooking(event) {
  event.preventDefault();
  resetBookingStatus();
  const validation = validateBookingInput();
  if (!validation.valid) {
    setText(el.formError, validation.message);
    setHidden(el.formError, false);
    return;
  }
  if (!state.holdToken) await ensureHoldToken();
  if (!state.holdToken) return;
  const emailVerificationId = state.emailVerification?.verification_id;
  const emailVerificationCode = el.emailVerifyCode?.value?.trim();
  if (state.useEmailVerification) {
    if (!validation.data.email) {
      setText(el.formError, "請先填寫 Email 以寄送驗證碼");
      setHidden(el.formError, false);
      return;
    }
    if (!emailVerificationId || !emailVerificationCode) {
      setText(el.formError, "請先完成 Email 驗證碼");
      setHidden(el.formError, false);
      return;
    }
  }
  const payload = {
    hold_token: state.holdToken,
    national_id: validation.data.nationalId,
    dob: validation.data.dob,
    display_name: validation.data.displayName,
    phone: validation.data.phone || undefined,
    email: validation.data.email || undefined,
    source: "patient_web",
  };
  if (state.turnstileToken) payload.turnstile_token = state.turnstileToken;
  if (emailVerificationId && emailVerificationCode) {
    payload.email_verification_id = emailVerificationId;
    payload.email_verification_code = emailVerificationCode;
  }
  try {
    const result = await api.createAppointment(payload);
    setHidden(el.formSuccess, false);
    setText(el.bookingRefOutput, result.booking_ref);
    if (el.bookingIcsLink && state.selectedSlot) {
      if (mockEnabled) {
        const ics = buildCalendarText({
          booking_ref: result.booking_ref,
          start_at_utc: state.selectedSlot.start_at_utc,
          end_at_utc: state.selectedSlot.end_at_utc,
          summary: `門診預約 #${result.booking_ref}`,
        });
        el.bookingIcsLink.href = `data:text/calendar;charset=utf-8,${encodeURIComponent(ics)}`;
      } else {
        const query = new URLSearchParams();
        query.set("dob", validation.data.dob);
        if (validation.data.phone) query.set("phone", validation.data.phone);
        if (validation.data.email) query.set("email", validation.data.email);
        el.bookingIcsLink.href = `${apiBase}/public/appointments/${result.booking_ref}/calendar?${query.toString()}`;
      }
    }
  } catch (error) {
    const apiError = extractApiError(error);
    if (apiError.code === "turnstile_required" || apiError.code === "turnstile_failed") {
      setHidden(el.turnstileError, false);
      setEmailVerificationVisible(true);
    }
    setText(el.formError, buildErrorMessage(apiError));
    setHidden(el.formError, false);
  }
}

async function handleEmailVerificationSend() {
  const email = el.patientEmail?.value?.trim();
  if (!email) {
    setText(el.emailVerifyStatus, "請先填寫 Email");
    return;
  }
  setEmailVerificationVisible(true);
  try {
    const result = await api.requestEmailVerification(email);
    state.emailVerification = result;
    const expires = new Date(result.expires_at).toLocaleTimeString("zh-TW", {
      hour: "2-digit",
      minute: "2-digit",
    });
    setText(el.emailVerifyStatus, `驗證碼已寄送，有效至 ${expires}`);
    if (result.debug_code && el.emailVerifyDebug) {
      el.emailVerifyDebug.textContent = `debug：${result.debug_code}`;
      setHidden(el.emailVerifyDebug, false);
    }
  } catch (error) {
    const apiError = extractApiError(error);
    setText(el.emailVerifyStatus, buildErrorMessage(apiError));
  }
}

async function showCheckinQr() {
  const bookingRef = el.bookingRefOutput?.textContent?.trim();
  if (!bookingRef) return;
  const dob = el.patientDob?.value || "";
  const phone = el.patientPhone?.value?.trim() || "";
  const email = el.patientEmail?.value?.trim() || "";
  try {
    const result = await api.createCheckinToken(bookingRef, {
      dob,
      phone: phone || undefined,
      email: email || undefined,
    });
    const checkinUrl = new URL("../checkin/", window.location.href);
    checkinUrl.searchParams.set("token", result.checkin_token);
    setText(el.bookingCheckinUrl, checkinUrl.toString());
    const expires = new Date(result.expires_at).toLocaleTimeString("zh-TW", {
      hour: "2-digit",
      minute: "2-digit",
    });
    setText(el.bookingCheckinExpiry, `有效至 ${expires}`);
    if (window.QRCode) {
      const dataUrl = await window.QRCode.toDataURL(checkinUrl.toString(), { width: 128, margin: 1 });
      el.bookingCheckinQr.innerHTML = "";
      const img = new Image();
      img.src = dataUrl;
      el.bookingCheckinQr.appendChild(img);
    }
    setHidden(el.bookingCheckinPanel, false);
  } catch (error) {
    const apiError = extractApiError(error);
    setText(el.bookingCheckinExpiry, buildErrorMessage(apiError));
    setHidden(el.bookingCheckinPanel, false);
  }
}

async function submitLookup(event) {
  event.preventDefault();
  setHidden(el.lookupError, true);
  setHidden(el.lookupSuccess, true);
  const bookingRef = normalizeBookingRef(el.lookupBookingRef?.value || "");
  if (!isValidBookingRef(bookingRef)) {
    setHidden(el.lookupRefError, false);
    setText(el.lookupError, "查詢碼格式不正確");
    setHidden(el.lookupError, false);
    return;
  }
  setHidden(el.lookupRefError, true);
  const dob = el.lookupDob?.value || "";
  const phone = el.lookupPhone?.value?.trim() || "";
  const email = el.lookupEmail?.value?.trim() || "";
  if (!dob || (!phone && !email)) {
    setText(el.lookupError, "請確認必填欄位與聯絡方式");
    setHidden(el.lookupError, false);
    return;
  }
  const action = event.submitter?.value || "lookup";
  try {
    if (action === "lookup") {
      const params = { dob };
      if (phone) params.phone = phone;
      if (email) params.email = email;
      await api.lookupAppointment(bookingRef, params);
    } else {
      await api.cancelAppointment(bookingRef, { dob, phone: phone || undefined, email: email || undefined });
    }
    if (el.lookupActionLabel) el.lookupActionLabel.textContent = action === "lookup" ? "查詢" : "取消";
    setHidden(el.lookupSuccess, false);
  } catch (error) {
    const apiError = extractApiError(error);
    setText(el.lookupError, buildErrorMessage(apiError));
    setHidden(el.lookupError, false);
  }
}

function initTurnstile() {
  if (!turnstileSiteKey) {
    setHidden(el.turnstileWrapper, true);
    return;
  }
  setHidden(el.turnstileWrapper, false);
  if (window.turnstile && el.turnstileContainer) {
    window.turnstile.render(el.turnstileContainer, {
      sitekey: turnstileSiteKey,
      callback: (token) => {
        state.turnstileToken = token;
        setHidden(el.turnstileError, true);
      },
      "error-callback": () => {
        state.turnstileToken = "";
      },
    });
    return;
  }
  const script = document.createElement("script");
  script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
  script.async = true;
  script.defer = true;
  script.onload = () => initTurnstile();
  document.head.appendChild(script);
}

function bindEvents() {
  el.quickDateButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.disabled === "true") return;
      updateSelectedDate(button.dataset.date || state.selectedDate);
    });
  });
  el.clinicSelect?.addEventListener("change", async () => {
    state.selectedClinicId = el.clinicSelect.value;
    await loadProviders();
  });
  el.specialtySelect?.addEventListener("change", loadProviders);
  el.doctorSearch?.addEventListener("input", () => {
    clearTimeout(el.doctorSearch._timer);
    el.doctorSearch._timer = setTimeout(loadProviders, 250);
  });
  el.bookingClose?.addEventListener("click", closeBookingModal);
  el.bookingCancel?.addEventListener("click", closeBookingModal);
  el.bookingBackdrop?.addEventListener("click", closeBookingModal);
  el.bookingForm?.addEventListener("submit", submitBooking);
  el.emailVerifyToggle?.addEventListener("click", () => {
    setEmailVerificationVisible(!state.useEmailVerification);
  });
  el.emailVerifySend?.addEventListener("click", handleEmailVerificationSend);
  el.patientEmail?.addEventListener("input", () => {
    state.emailVerification = null;
    if (el.emailVerifyStatus) setText(el.emailVerifyStatus, "");
    if (el.emailVerifyDebug) setHidden(el.emailVerifyDebug, true);
  });
  el.lookupForm?.addEventListener("submit", submitLookup);
  el.bookingRefCopy?.addEventListener("click", async () => {
    const text = el.bookingRefOutput?.textContent || "";
    if (!text) return;
    await navigator.clipboard.writeText(text).catch(() => null);
    setHidden(el.bookingRefCopied, false);
    setTimeout(() => setHidden(el.bookingRefCopied, true), 1500);
  });
  el.bookingCheckinButton?.addEventListener("click", showCheckinQr);
  el.authLoginForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    setText(el.authLoginMessage, "此區為後端登入示意，需連線 API 才可使用。");
  });
  el.authBindForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    setText(el.authBindMessage, "此區為後端綁定示意，需連線 API 才可使用。");
  });
  el.memberRefresh?.addEventListener("click", () => {
    setText(el.memberMessage, "請先登入會員。");
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeBookingModal();
  });
}

async function init() {
  initQuickDates();
  bindEvents();
  initTurnstile();
  await loadClinics();
}

init();
