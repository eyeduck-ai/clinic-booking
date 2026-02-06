const apiBase = document.body.dataset.apiBase || "/api/v1";

const clinicSelect = document.getElementById("clinic-select");
const providerSelect = document.getElementById("provider-select");
const providerSummary = document.getElementById("provider-summary");
const seedButton = document.getElementById("seed-data");

const clinicRefresh = document.getElementById("clinic-refresh");
const clinicForm = document.getElementById("clinic-form");
const clinicIdInput = document.getElementById("clinic-id");
const clinicNameInput = document.getElementById("clinic-name");
const clinicTimezoneInput = document.getElementById("clinic-timezone");
const clinicPhoneInput = document.getElementById("clinic-phone");
const clinicAddressInput = document.getElementById("clinic-address");
const clinicSubmit = document.getElementById("clinic-submit");
const clinicCancelEdit = document.getElementById("clinic-cancel-edit");
const clinicList = document.getElementById("clinic-list");
const clinicMessage = document.getElementById("clinic-message");

const providerRefresh = document.getElementById("provider-refresh");
const providerFormAdmin = document.getElementById("provider-form");
const providerIdInput = document.getElementById("provider-id");
const providerClinicSelect = document.getElementById("provider-clinic");
const providerNameInput = document.getElementById("provider-name");
const providerTitleInput = document.getElementById("provider-title");
const providerSpecialtyInput = document.getElementById("provider-specialty");
const providerPhotoInput = document.getElementById("provider-photo");
const providerBioInput = document.getElementById("provider-bio");
const providerActiveInput = document.getElementById("provider-active");
const providerSubmit = document.getElementById("provider-submit");
const providerCancelEdit = document.getElementById("provider-cancel-edit");
const providerList = document.getElementById("provider-list");
const providerMessage = document.getElementById("provider-message");
const noticeForm = document.getElementById("notice-form");
const noticeClinic = document.getElementById("notice-clinic");
const noticeContent = document.getElementById("notice-content");
const noticeMessage = document.getElementById("notice-message");

const ruleForm = document.getElementById("rule-form");
const ruleId = document.getElementById("rule-id");
const ruleWeekday = document.getElementById("rule-weekday");
const ruleStart = document.getElementById("rule-start");
const ruleEnd = document.getElementById("rule-end");
const ruleSlot = document.getElementById("rule-slot");
const ruleCapacity = document.getElementById("rule-capacity");
const ruleFrom = document.getElementById("rule-from");
const ruleTo = document.getElementById("rule-to");
const ruleMessage = document.getElementById("rule-message");
const ruleSubmit = document.getElementById("rule-submit");
const ruleCancelEdit = document.getElementById("rule-cancel-edit");

const exceptionForm = document.getElementById("exception-form");
const exceptionId = document.getElementById("exception-id");
const exceptionDate = document.getElementById("exception-date");
const exceptionType = document.getElementById("exception-type");
const exceptionStart = document.getElementById("exception-start");
const exceptionEnd = document.getElementById("exception-end");
const exceptionSlot = document.getElementById("exception-slot");
const exceptionCapacity = document.getElementById("exception-capacity");
const exceptionNote = document.getElementById("exception-note");
const exceptionMessage = document.getElementById("exception-message");
const exceptionOverrideFields = document.getElementById("exception-override-fields");
const exceptionSubmit = document.getElementById("exception-submit");
const exceptionCancelEdit = document.getElementById("exception-cancel-edit");

const generateForm = document.getElementById("generate-form");
const generateFrom = document.getElementById("generate-from");
const generateTo = document.getElementById("generate-to");
const generateMessage = document.getElementById("generate-message");
const generateReset = document.getElementById("generate-reset");
const generateOverwrite = document.getElementById("generate-overwrite");

const closeForm = document.getElementById("close-form");
const closeDate = document.getElementById("close-date");
const closeMode = document.getElementById("close-mode");
const closeNotify = document.getElementById("close-notify");
const closeReason = document.getElementById("close-reason");
const closeMessage = document.getElementById("close-message");

const ruleList = document.getElementById("rule-list");
const exceptionList = document.getElementById("exception-list");
const notificationList = document.getElementById("notification-list");
const notificationRefresh = document.getElementById("notification-refresh");
const notificationStatus = document.getElementById("notification-status");
const notificationProcess = document.getElementById("notification-process");
const notificationMessage = document.getElementById("notification-message");

const templateRefresh = document.getElementById("template-refresh");
const templateForm = document.getElementById("template-form");
const templateClinic = document.getElementById("template-clinic");
const templateChannel = document.getElementById("template-channel");
const templateName = document.getElementById("template-name");
const templateSubject = document.getElementById("template-subject");
const templateBody = document.getElementById("template-body");
const templateLocale = document.getElementById("template-locale");
const templatePayload = document.getElementById("template-payload");
const templatePreview = document.getElementById("template-preview");
const templatePreviewOutput = document.getElementById("template-preview-output");
const reportRefresh = document.getElementById("report-refresh");
const reportClinic = document.getElementById("report-clinic");
const reportProvider = document.getElementById("report-provider");
const reportDate = document.getElementById("report-date");
const reportOutput = document.getElementById("report-output");
const reportMessage = document.getElementById("report-message");
const csvClinic = document.getElementById("csv-clinic");
const csvProvider = document.getElementById("csv-provider");
const csvDate = document.getElementById("csv-date");
const csvFile = document.getElementById("csv-file");
const csvExport = document.getElementById("csv-export");
const csvImport = document.getElementById("csv-import");
const csvMessage = document.getElementById("csv-message");
const auditClinic = document.getElementById("audit-clinic");
const auditActor = document.getElementById("audit-actor");
const auditEntity = document.getElementById("audit-entity");
const auditDateFrom = document.getElementById("audit-date-from");
const auditDateTo = document.getElementById("audit-date-to");
const auditRefresh = document.getElementById("audit-refresh");
const auditList = document.getElementById("audit-list");
const auditMessage = document.getElementById("audit-message");
const templateList = document.getElementById("template-list");
const templateMessage = document.getElementById("template-message");

const staffRefresh = document.getElementById("staff-refresh");
const staffForm = document.getElementById("staff-form");
const staffClinic = document.getElementById("staff-clinic");
const staffEmail = document.getElementById("staff-email");
const staffName = document.getElementById("staff-name");
const staffRoles = document.getElementById("staff-roles");
const staffList = document.getElementById("staff-list");
const staffMessage = document.getElementById("staff-message");
const patientAuthRefresh = document.getElementById("patient-auth-refresh");
const patientAuthList = document.getElementById("patient-auth-list");
const patientAuthMessage = document.getElementById("patient-auth-message");
const patientRefresh = document.getElementById("patient-refresh");
const patientSearchForm = document.getElementById("patient-search");
const patientClinic = document.getElementById("patient-clinic");
const patientQuery = document.getElementById("patient-query");
const patientList = document.getElementById("patient-list");
const patientEditForm = document.getElementById("patient-edit");
const patientIdInput = document.getElementById("patient-id");
const patientNameInput = document.getElementById("patient-name");
const patientGenderInput = document.getElementById("patient-gender");
const patientNationalIdInput = document.getElementById("patient-national-id");
const patientDobInput = document.getElementById("patient-dob");
const patientPhoneInput = document.getElementById("patient-phone");
const patientEmailInput = document.getElementById("patient-email");
const patientClear = document.getElementById("patient-clear");
const patientDelete = document.getElementById("patient-delete");
const patientUnlock = document.getElementById("patient-unlock");
const patientCreateForm = document.getElementById("patient-create");
const patientCreateNationalId = document.getElementById("patient-create-national-id");
const patientCreateDob = document.getElementById("patient-create-dob");
const patientCreateName = document.getElementById("patient-create-name");
const patientCreatePhone = document.getElementById("patient-create-phone");
const patientCreateEmail = document.getElementById("patient-create-email");
const patientMessage = document.getElementById("patient-message");
const patientApptRefresh = document.getElementById("patient-appt-refresh");
const patientApptFilter = document.getElementById("patient-appt-filter");
const patientApptStatus = document.getElementById("patient-appt-status");
const patientApptFrom = document.getElementById("patient-appt-from");
const patientApptTo = document.getElementById("patient-appt-to");
const patientApptList = document.getElementById("patient-appt-list");
const patientApptMore = document.getElementById("patient-appt-more");
const patientApptMessage = document.getElementById("patient-appt-message");
const patientFormRefresh = document.getElementById("patient-form-refresh");
const patientFormList = document.getElementById("patient-form-list");
const patientFormMessage = document.getElementById("patient-form-message");
const formDefinitionRefresh = document.getElementById("form-definition-refresh");
const formDefinitionForm = document.getElementById("form-definition-form");
const formDefinitionType = document.getElementById("form-definition-type");
const formDefinitionTypes = document.getElementById("form-definition-types");
const formDefinitionActive = document.getElementById("form-definition-active");
const formDefinitionSchema = document.getElementById("form-definition-schema");
const formDefinitionSubmit = document.getElementById("form-definition-submit");
const formDefinitionClear = document.getElementById("form-definition-clear");
const formDefinitionList = document.getElementById("form-definition-list");
const formDefinitionMessage = document.getElementById("form-definition-message");

const rescheduleLookupForm = document.getElementById("reschedule-lookup");
const rescheduleBookingRef = document.getElementById("reschedule-booking-ref");
const rescheduleSummary = document.getElementById("reschedule-summary");
const rescheduleForm = document.getElementById("reschedule-form");
const rescheduleAppointmentId = document.getElementById("reschedule-appointment-id");
const rescheduleProviderId = document.getElementById("reschedule-provider-id");
const rescheduleClinicId = document.getElementById("reschedule-clinic-id");
const rescheduleDate = document.getElementById("reschedule-date");
const rescheduleSlot = document.getElementById("reschedule-slot");
const rescheduleNotify = document.getElementById("reschedule-notify");
const rescheduleReason = document.getElementById("reschedule-reason");
const rescheduleMessage = document.getElementById("reschedule-message");

const bookingLookupForm = document.getElementById("booking-lookup");
const bookingNationalId = document.getElementById("booking-national-id");
const bookingDob = document.getElementById("booking-dob");
const bookingPatientSummary = document.getElementById("booking-patient-summary");
const bookingCreateForm = document.getElementById("booking-create");
const bookingPatientId = document.getElementById("booking-patient-id");
const bookingName = document.getElementById("booking-name");
const bookingPhone = document.getElementById("booking-phone");
const bookingEmail = document.getElementById("booking-email");
const bookingDate = document.getElementById("booking-date");
const bookingSlot = document.getElementById("booking-slot");
const bookingNotify = document.getElementById("booking-notify");
const bookingReason = document.getElementById("booking-reason");
const bookingFormAdmin = document.getElementById("booking-form-admin");
const bookingMessage = document.getElementById("booking-message");

const queueForm = document.getElementById("queue-form");
const queueDate = document.getElementById("queue-date");
const queueReserved = document.getElementById("queue-reserved");
const queueCallInput = document.getElementById("queue-call-input");
const queueSaveReserved = document.getElementById("queue-save-reserved");
const queueNotifyCalled = document.getElementById("queue-notify-called");
const queueExport = document.getElementById("queue-export");
const queueNext = document.getElementById("queue-next");
const queueQuickCall = document.getElementById("queue-quick-call");
const queueSummary = document.getElementById("queue-summary");
const queueList = document.getElementById("queue-list");
const queueMessage = document.getElementById("queue-message");
const queueDetailRefresh = document.getElementById("queue-detail-refresh");
const queueDetailMeta = document.getElementById("queue-detail-meta");
const queueDetailBasic = document.getElementById("queue-detail-basic");
const queueDetailForms = document.getElementById("queue-detail-forms");
const queueDetailMessage = document.getElementById("queue-detail-message");
const queueDetailActions = document.getElementById("queue-detail-actions");
const queueAutoRefresh = document.getElementById("queue-auto-refresh");

const state = {
  clinics: [],
  providers: [],
  adminProviders: [],
  patients: [],
  queueAppointments: [],
  queueStatus: null,
  selectedPatientId: null,
  patientAppointmentsCursor: null,
  formSchemas: {},
  formDefinitions: [],
  formDefinitionsById: {},
  staffContext: null,
  isAdmin: false,
  selectedQueueAppointment: null,
};

const queueRefreshIntervalMs = 8000;
let queueRefreshTimer = null;

const weekdayLabels = ["週日", "週一", "週二", "週三", "週四", "週五", "週六"];
const timeFormatter = new Intl.DateTimeFormat("zh-TW", {
  timeZone: "Asia/Taipei",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});
const dateTimeFormatter = new Intl.DateTimeFormat("zh-TW", {
  timeZone: "Asia/Taipei",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

function getTaipeiDateString() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Taipei",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

function showMessage(target, message, isError = false) {
  target.textContent = message;
  target.className = `text-xs ${isError ? "text-red-600" : "text-[#3d8b44]"}`;
}

const ADMIN_ROLES = new Set(["system_admin", "group_admin", "clinic_admin", "dev_admin"]);

function isAdminRole(roles = []) {
  return roles.some((role) => ADMIN_ROLES.has(role));
}

function applyRoleVisibility() {
  const adminOnlyTargets = [
    clinicForm,
    providerFormAdmin,
    noticeForm,
    ruleForm,
    exceptionForm,
    closeForm,
    generateForm,
    ruleList,
    exceptionList,
    templateForm,
    staffForm,
    patientAuthList,
    formDefinitionForm,
  ];
  adminOnlyTargets.forEach((element) => {
    const section = element?.closest("section");
    if (section) {
      section.style.display = state.isAdmin ? "" : "none";
    }
  });
  if (patientDelete) {
    patientDelete.style.display = state.isAdmin ? "" : "none";
  }
  if (patientUnlock) {
    patientUnlock.style.display = state.isAdmin ? "" : "none";
  }
}

function renderAdminBadge() {
  const roles = state.staffContext?.roles ?? [];
  const container = document.querySelector("header .max-w-6xl");
  if (!container) return;
  let badge = document.getElementById("admin-role-badge");
  if (!badge) {
    badge = document.createElement("div");
    badge.id = "admin-role-badge";
    badge.className = "ml-auto text-xs text-[#617589] bg-white border border-[#dbe0e6] rounded-full px-3 py-1";
    container.appendChild(badge);
  }
  badge.textContent = roles.length ? `Roles: ${roles.join(", ")}` : "Roles: -";
}

async function loadAdminContext() {
  try {
    const response = await fetchJson(`${apiBase}/admin/me`);
    state.staffContext = response.data ?? { roles: [] };
  } catch {
    state.staffContext = { roles: [] };
  }
  const roles = state.staffContext?.roles ?? [];
  state.isAdmin = isAdminRole(roles);
  renderAdminBadge();
  applyRoleVisibility();
}


function populateClinicSelect(select, clinics) {
  if (!select) return;
  select.innerHTML = "";
  clinics.forEach((clinic) => {
    const option = document.createElement("option");
    option.value = clinic.id;
    option.textContent = clinic.name;
    select.appendChild(option);
  });
}

function renderClinicList(clinics) {
  if (!clinicList) return;
  clinicList.innerHTML = "";
  if (!clinics.length) {
    clinicList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無院所</p>";
    return;
  }
  clinics.forEach((clinic) => {
    const item = document.createElement("div");
    item.className = "p-3 border border-[#e5e7eb] rounded-lg space-y-1";
    item.innerHTML = `
      <div class="label">#${clinic.id.slice(0, 8)} · ${clinic.name}</div>
      <div>時區：${clinic.timezone || "-"}</div>
      <div>電話：${clinic.phone || "-"}</div>
      <div>地址：${clinic.address || "-"}</div>
      <button class="clinic-edit-btn text-xs text-primary hover:underline">編輯</button>
    `;
    item.querySelector(".clinic-edit-btn").addEventListener("click", () => {
      clinicIdInput.value = clinic.id;
      clinicNameInput.value = clinic.name;
      clinicTimezoneInput.value = clinic.timezone || "Asia/Taipei";
      clinicPhoneInput.value = clinic.phone || "";
      clinicAddressInput.value = clinic.address || "";
      clinicSubmit.textContent = "更新院所";
      clinicCancelEdit.classList.remove("hidden");
    });
    clinicList.appendChild(item);
  });
}

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload?.error?.code || "request_failed");
  }
  return response.json();
}

async function loadClinics() {
  const currentClinic = clinicSelect?.value || "";
  const currentTemplateClinic = templateClinic?.value || "";
  const currentStaffClinic = staffClinic?.value || "";
  const currentProviderClinic = providerClinicSelect?.value || "";
  const currentNoticeClinic = noticeClinic?.value || "";
  const currentPatientClinic = patientClinic?.value || "";
  const currentReportClinic = reportClinic?.value || "";
  const currentCsvClinic = csvClinic?.value || "";
  const currentAuditClinic = auditClinic?.value || "";

  const result = await fetchJson(`${apiBase}/admin/clinics`);
  state.clinics = result.data || [];
  populateClinicSelect(clinicSelect, state.clinics);
  populateClinicSelect(templateClinic, state.clinics);
  populateClinicSelect(staffClinic, state.clinics);
  populateClinicSelect(providerClinicSelect, state.clinics);
  populateClinicSelect(noticeClinic, state.clinics);
  populateClinicSelect(patientClinic, state.clinics);
  populateClinicSelect(reportClinic, state.clinics);
  populateClinicSelect(csvClinic, state.clinics);
  populateClinicSelect(auditClinic, state.clinics);

  if (currentClinic) clinicSelect.value = currentClinic;
  if (currentTemplateClinic) templateClinic.value = currentTemplateClinic;
  if (currentStaffClinic) staffClinic.value = currentStaffClinic;
  if (currentProviderClinic) providerClinicSelect.value = currentProviderClinic;
  if (currentNoticeClinic) noticeClinic.value = currentNoticeClinic;
  if (currentPatientClinic) patientClinic.value = currentPatientClinic;
  if (currentReportClinic) reportClinic.value = currentReportClinic;
  if (currentCsvClinic) csvClinic.value = currentCsvClinic;
  if (currentAuditClinic) auditClinic.value = currentAuditClinic;

  renderClinicList(state.clinics);
  await loadProvidersForSelect(reportProvider, reportClinic?.value || "");
  await loadProvidersForSelect(csvProvider, csvClinic?.value || "");
}

async function loadProviders() {
  const clinicId = clinicSelect.value;
  if (!clinicId) return;
  const result = await fetchJson(`${apiBase}/admin/providers?clinic_id=${clinicId}`);
  state.providers = result.data || [];
  providerSelect.innerHTML = "";
  state.providers.forEach((provider) => {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = `${provider.name} (${provider.specialty || ""})`;
    providerSelect.appendChild(option);
  });
  updateProviderSummary();
  await loadRulesAndExceptions();
  await refreshQueueDashboard();
}

async function loadProvidersForSelect(select, clinicId) {
  if (!select) return;
  select.innerHTML = "";
  if (!clinicId) return;
  const result = await fetchJson(`${apiBase}/admin/providers?clinic_id=${clinicId}`);
  (result.data || []).forEach((provider) => {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = `${provider.name} (${provider.specialty || ""})`;
    select.appendChild(option);
  });
}


function renderProvidersAdmin(providers) {
  if (!providerList) return;
  providerList.innerHTML = "";
  if (!providers.length) {
    providerList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無醫師</p>";
    return;
  }
  providers.forEach((provider) => {
    const item = document.createElement("div");
    item.className = "p-3 border border-[#e5e7eb] rounded-lg space-y-1";
    item.innerHTML = `
      <div class="label">#${provider.id.slice(0, 8)} · ${provider.name}</div>
      <div>門診：${provider.title || "-"}</div>
      <div>專科：${provider.specialty || "-"}</div>
      <div>啟用狀態：${Number(provider.is_active) === 1 ? "啟用" : "停用"}</div>
      <button class="provider-edit-btn text-xs text-primary hover:underline">編輯</button>
    `;
    item.querySelector(".provider-edit-btn").addEventListener("click", () => {
      providerIdInput.value = provider.id;
      providerClinicSelect.value = provider.clinic_id;
      providerNameInput.value = provider.name;
      providerTitleInput.value = provider.title || "";
      providerSpecialtyInput.value = provider.specialty || "";
      providerPhotoInput.value = provider.photo_url || "";
      providerBioInput.value = provider.bio || "";
      providerActiveInput.checked = Number(provider.is_active) === 1;
      providerSubmit.textContent = "更新醫師";
      providerCancelEdit.classList.remove("hidden");
    });
    providerList.appendChild(item);
  });
}

async function loadProvidersAdmin() {
  const clinicId = providerClinicSelect?.value || "";
  const query = clinicId ? `?clinic_id=${clinicId}` : "";
  const result = await fetchJson(`${apiBase}/admin/providers${query}`);
  state.adminProviders = result.data || [];
  renderProvidersAdmin(state.adminProviders);
}

async function loadClinicNotice() {
  const clinicId = noticeClinic?.value;
  if (!clinicId) return;
  const result = await fetchJson(`${apiBase}/public/clinic-notice?clinic_id=${clinicId}`);
  if (noticeContent) {
    noticeContent.value = result.data?.content || "";
  }
}

function formatAppointmentStatus(status) {
  return statusLabels[status] || status;
}

function renderPatientAppointments(appointments, { append } = { append: false }) {
  if (!patientApptList) return;
  if (!append) {
    patientApptList.innerHTML = "";
  }

  if (!appointments.length && !append) {
    patientApptList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無看診紀錄</p>";
    return;
  }

  appointments.forEach((appointment) => {
    const item = document.createElement("div");
    item.className = "p-3 border border-[#e5e7eb] rounded-lg space-y-1";
    item.innerHTML = `
      <div class="label">${appointment.service_date_local} · ${appointment.provider_name || "-"}</div>
      <div>院所：${appointment.clinic_name || "-"}</div>
      <div>狀態：${formatAppointmentStatus(appointment.status)}</div>
      <div>號碼：${appointment.queue_no ?? "-"}</div>
      <div>查詢碼：${appointment.booking_ref || "-"}</div>
    `;
    patientApptList.appendChild(item);
  });
}

function resetPatientAppointments() {
  state.patientAppointmentsCursor = null;
  if (patientApptList) {
    patientApptList.innerHTML = "<p class=\"text-[#9ca3af]\">尚未登入會員</p>";
  }
  if (patientApptMore) {
    patientApptMore.classList.add("hidden");
  }
}

function resetPatientForms() {
  if (patientFormList) {
    patientFormList.innerHTML = "<p class=\"text-[#9ca3af] text-sm\">尚未登入會員</p>";
  }
  if (patientFormMessage) {
    patientFormMessage.textContent = "";
  }
}

function parseSchemaJson(value) {
  if (!value) return null;
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
  return value;
}

async function loadFormSchemas() {
  const types = ["initial", "followup"];
  await Promise.all(types.map(async (type) => {
    if (state.formSchemas[type]) return;
    try {
      const response = await fetchJson(`${apiBase}/admin/forms?type=${type}`);
      const row = response.data?.[0];
      if (!row) return;
      const schema = parseSchemaJson(row.schema_json);
      if (schema) {
        state.formSchemas[type] = schema;
      }
    } catch {
      // ignore schema fetch errors
    }
  }));
}

function resetFormDefinitionEditor() {
  if (formDefinitionType) formDefinitionType.value = "";
  if (formDefinitionSchema) formDefinitionSchema.value = "";
  if (formDefinitionActive) formDefinitionActive.checked = true;
  if (formDefinitionMessage) formDefinitionMessage.textContent = "";
}

function fillFormDefinitionEditor(definition) {
  if (!definition) return;
  if (formDefinitionType) formDefinitionType.value = definition.type || "";
  if (formDefinitionSchema) {
    const parsed = parseSchemaJson(definition.schema_json);
    formDefinitionSchema.value = parsed ? JSON.stringify(parsed, null, 2) : definition.schema_json || "";
  }
  if (formDefinitionActive) formDefinitionActive.checked = true;
}

function renderFormDefinitionList(definitions) {
  if (!formDefinitionList) return;
  formDefinitionList.innerHTML = "";
  if (!definitions.length) {
    formDefinitionList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無表單定義</p>";
    return;
  }

  const types = {};
  definitions.forEach((item) => {
    if (!types[item.type]) types[item.type] = [];
    types[item.type].push(item);
  });

  if (formDefinitionTypes) {
    const uniqueTypes = Object.keys(types).sort();
    formDefinitionTypes.innerHTML = uniqueTypes.map((type) => `<option value="${type}"></option>`).join("");
  }

  Object.keys(types).sort().forEach((type) => {
    const group = document.createElement("div");
    group.className = "p-4 border border-[#e5e7eb] rounded-lg space-y-3";
    const header = document.createElement("div");
    header.className = "flex items-center justify-between";
    header.innerHTML = `<div class="label">${type}</div><div class="text-xs text-[#9ca3af]">版本數 ${types[type].length}</div>`;
    group.appendChild(header);

    types[type]
      .sort((a, b) => Number(b.version) - Number(a.version))
      .forEach((item) => {
        const row = document.createElement("div");
        row.className = "flex flex-col md:flex-row md:items-center md:justify-between gap-2 border border-[#f0f2f4] rounded-lg p-3";
        const schema = parseSchemaJson(item.schema_json);
        const title = schema?.title || "-";
        const createdAt = item.created_at ? dateTimeFormatter.format(new Date(item.created_at)) : "-";
        const isActive = Number(item.is_active) === 1;
        row.innerHTML = `
          <div class="space-y-1">
            <div class="font-semibold">v${item.version} ${isActive ? "（啟用中）" : ""}</div>
            <div class="text-xs text-[#9ca3af]">標題：${title}</div>
            <div class="text-xs text-[#9ca3af]">建立時間：${createdAt}</div>
          </div>
          <div class="flex flex-wrap gap-2 text-xs">
            ${isActive ? "" : `<button data-action="activate-form" data-id="${item.id}" class="h-8 px-3 rounded-lg border border-[#dbe0e6] hover:border-primary hover:text-primary">啟用</button>`}
            <button data-action="copy-form" data-id="${item.id}" class="h-8 px-3 rounded-lg border border-[#dbe0e6] hover:border-primary hover:text-primary">複製到編輯器</button>
          </div>
        `;
        group.appendChild(row);
      });

    formDefinitionList.appendChild(group);
  });
}

async function loadFormDefinitions() {
  if (!formDefinitionList) return;
  try {
    const response = await fetchJson(`${apiBase}/admin/forms`);
    const definitions = response.data || [];
    state.formDefinitions = definitions;
    state.formDefinitionsById = {};
    state.formSchemas = {};
    definitions.forEach((item) => {
      state.formDefinitionsById[item.id] = item;
    });
    renderFormDefinitionList(definitions);
    if (formDefinitionMessage) formDefinitionMessage.textContent = "";
  } catch (error) {
    if (formDefinitionMessage) {
      formDefinitionMessage.textContent = "載入表單定義失敗";
      formDefinitionMessage.className = "text-xs text-red-600 mt-3";
    }
  }
}

function renderFormFields(data, schema) {
  const container = document.createElement("div");
  container.className = "space-y-1 text-sm text-[#617589]";
  if (!data || Object.keys(data).length === 0) {
    const empty = document.createElement("div");
    empty.className = "text-[#9ca3af]";
    empty.textContent = "尚未填寫";
    container.appendChild(empty);
    return container;
  }

  const fields = schema?.fields?.length ? schema.fields : Object.keys(data).map((key) => ({ key, label: key }));
  fields.forEach((field) => {
    const value = data[field.key];
    if (value === undefined || value === null || value === "") return;
    const row = document.createElement("div");
    row.textContent = `${field.label || field.key}：${value}`;
    container.appendChild(row);
  });
  if (!container.childNodes.length) {
    const empty = document.createElement("div");
    empty.className = "text-[#9ca3af]";
    empty.textContent = "尚未填寫";
    container.appendChild(empty);
  }
  return container;
}

function renderFormsInto(container, submissions) {
  if (!container) return;
  container.innerHTML = "";
  if (!submissions || submissions.length === 0) {
    container.innerHTML = "<p class=\"text-[#9ca3af] text-sm\">尚未填寫</p>";
    return;
  }

  const latestByType = {};
  submissions.forEach((item) => {
    if (!latestByType[item.type]) {
      latestByType[item.type] = item;
    }
  });

  const types = ["initial", "followup"];
  types.forEach((type) => {
    const schema = state.formSchemas[type];
    const title = schema?.title || (type === "initial" ? "初診回報" : "複診回報");
    const submission = latestByType[type];
    const card = document.createElement("div");
    card.className = "p-4 border border-[#e5e7eb] rounded-lg space-y-2";
    const updatedAt = submission?.updated_at
      ? dateTimeFormatter.format(new Date(submission.updated_at))
      : "\\u5c1a\\u672a\\u586b\\u5beb";
    const versionLabel = submission?.form_version ? `v${submission.form_version}` : "";
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="label">${title}</div>
        <div class="text-xs text-[#9ca3af]">${versionLabel ? `${versionLabel}・${updatedAt}` : updatedAt}</div>
      </div>
    `;
    if (submission?.data_json) {
      const data = parseSchemaJson(submission.data_json) || {};
      card.appendChild(renderFormFields(data, schema));
    } else {
      card.appendChild(renderFormFields({}, schema));
    }
    container.appendChild(card);
  });
}

function renderPatientForms(submissions) {
  if (!patientFormList) return;
  renderFormsInto(patientFormList, submissions);
}

async function loadPatientForms() {
  if (!state.selectedPatientId) {
    resetPatientForms();
    return;
  }

  try {
    if (patientFormMessage) {
      patientFormMessage.textContent = "";
      patientFormMessage.className = "text-xs text-[#9ca3af] mt-2";
    }
    await loadFormSchemas();
    const result = await fetchJson(`${apiBase}/admin/form-submissions?patient_id=${state.selectedPatientId}`);
    renderPatientForms(result.data || []);
  } catch (error) {
    if (patientFormMessage) {
      patientFormMessage.textContent = "載入表單失敗";
      patientFormMessage.className = "text-xs text-red-600 mt-2";
    }
  }
}

async function loadPatientAppointments({ reset } = { reset: true }) {
  if (!state.selectedPatientId) {
    showMessage(patientApptMessage, "請先選擇病人", true);
    return;
  }
  if (!patientClinic?.value) {
    showMessage(patientApptMessage, "請先選擇院所", true);
    return;
  }
  const params = new URLSearchParams();
  params.set("limit", "20");
  params.set("clinic_id", patientClinic.value);
  if (patientApptStatus?.value) params.set("status", patientApptStatus.value);
  if (patientApptFrom?.value) params.set("from_date", patientApptFrom.value);
  if (patientApptTo?.value) params.set("to_date", patientApptTo.value);
  if (patientClinic?.value) params.set("clinic_id", patientClinic.value);

  if (!reset && state.patientAppointmentsCursor) {
    params.set("cursor", state.patientAppointmentsCursor);
  }

  try {
    const result = await fetchJson(
      `${apiBase}/admin/patients/${state.selectedPatientId}/appointments?${params.toString()}`
    );
    const appointments = result.data || [];
    renderPatientAppointments(appointments, { append: !reset });
    state.patientAppointmentsCursor = result.next_cursor || null;
    if (patientApptMore) {
      if (state.patientAppointmentsCursor) {
        patientApptMore.classList.remove("hidden");
      } else {
        patientApptMore.classList.add("hidden");
      }
    }
    if (patientApptMessage) patientApptMessage.textContent = "";
  } catch (error) {
    showMessage(patientApptMessage, "載入看診紀錄失敗", true);
  }
}

function selectPatient(patient) {
  patientIdInput.value = patient.id;
  patientNameInput.value = patient.display_name || "";
  patientGenderInput.value = patient.gender || "";
  patientNationalIdInput.value = patient.national_id || "";
  patientDobInput.value = patient.dob || "";
  patientPhoneInput.value = patient.phone || "";
  patientEmailInput.value = patient.email || "";
  state.selectedPatientId = patient.id;
  if (patientApptList) {
    patientApptList.innerHTML = "<p class=\"text-[#9ca3af]\">載入中...</p>";
  }
  if (patientFormList) {
    patientFormList.innerHTML = "<p class=\"text-[#9ca3af] text-sm\">載入中...</p>";
  }
  loadPatientAppointments({ reset: true });
  loadPatientForms();
}

function renderPatientList(patients) {
  if (!patientList) return;
  patientList.innerHTML = "";
  if (!patients.length) {
    patientList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無病人</p>";
    return;
  }

  patients.forEach((patient) => {
    const item = document.createElement("div");
    const lockedUntil = patient.locked_until
      ? dateTimeFormatter.format(new Date(patient.locked_until))
      : "";
    const lockLabel = lockedUntil ? `（鎖定至 ${lockedUntil}）` : "";
    item.className = "p-3 border border-[#e5e7eb] rounded-lg space-y-1";
    item.innerHTML = `
      <div class="label">#${patient.id.slice(0, 8)} · ${patient.display_name || "未命名"}</div>
      <div>身分證：${patient.national_id || "-"}</div>
      <div>生日：${patient.dob || "-"}</div>
      <div>電話：${patient.phone || "-"}</div>
      <div>Email：${patient.email || "-"}</div>
      <div>未到診次數：${patient.no_show_count_recent ?? 0} ${lockLabel}</div>
      <button class="patient-edit-btn text-xs text-primary hover:underline">編輯</button>
    `;
    item.querySelector(".patient-edit-btn").addEventListener("click", () => {
      selectPatient(patient);
    });
    patientList.appendChild(item);
  });
}

function clearPatientForm() {
  if (!patientIdInput) return;
  patientIdInput.value = "";
  patientNameInput.value = "";
  patientGenderInput.value = "";
  patientNationalIdInput.value = "";
  patientDobInput.value = "";
  patientPhoneInput.value = "";
  patientEmailInput.value = "";
  state.selectedPatientId = null;
  resetPatientAppointments();
  resetPatientForms();
}

async function loadPatients() {
  const clinicId = patientClinic?.value || clinicSelect?.value;
  if (!clinicId) {
    showMessage(patientMessage, "請先選擇院所", true);
    return;
  }
  const query = patientQuery?.value?.trim();
  const params = new URLSearchParams({ clinic_id: clinicId });
  if (query) params.set("q", query);
  try {
    const result = await fetchJson(`${apiBase}/admin/patients?${params.toString()}`);
    state.patients = result.data || [];
    renderPatientList(state.patients);
  } catch (error) {
    showMessage(patientMessage, "載入病人失敗", true);
  }
}

function updateProviderSummary() {
  const providerId = providerSelect.value;
  const provider = state.providers.find((item) => item.id === providerId);
  if (!provider) {
    providerSummary.textContent = "尚未選擇";
    return;
  }
  providerSummary.textContent = `${provider.title || ""} / ${provider.specialty || ""}`;
}

async function loadRulesAndExceptions() {
  const providerId = providerSelect.value;
  if (!providerId) return;

  const [rules, exceptions] = await Promise.all([
    fetchJson(`${apiBase}/admin/schedule-rules?provider_id=${providerId}`),
    fetchJson(`${apiBase}/admin/schedule-exceptions?provider_id=${providerId}`),
  ]);

  renderRules(rules.data || []);
  renderExceptions(exceptions.data || []);
}

function renderRules(rules) {
  ruleList.innerHTML = "";
  if (!rules.length) {
    ruleList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無規則</p>";
    return;
  }
  rules.forEach((rule) => {
    const item = document.createElement("div");
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = `${weekdayLabels[rule.weekday]} ${rule.start_time_local}～${rule.end_time_local}`;
    const detail = document.createElement("div");
    detail.textContent = `時段 ${rule.slot_minutes} 分鐘｜門診容量 ${rule.capacity_per_slot}`;
    const range = document.createElement("div");
    range.textContent = `適用日期 ${rule.effective_from || "不限"} ～ ${rule.effective_to || "不限"}`;

    const actions = document.createElement("div");
    actions.className = "flex gap-2 mt-2";
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "text-xs text-primary hover:underline";
    editBtn.textContent = "編輯";
    editBtn.dataset.action = "edit-rule";
    editBtn.dataset.id = rule.id;
    editBtn.dataset.weekday = rule.weekday;
    editBtn.dataset.start = rule.start_time_local;
    editBtn.dataset.end = rule.end_time_local;
    editBtn.dataset.slot = rule.slot_minutes;
    editBtn.dataset.capacity = rule.capacity_per_slot;
    editBtn.dataset.from = rule.effective_from || "";
    editBtn.dataset.to = rule.effective_to || "";

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "text-xs text-red-600 hover:underline";
    deleteBtn.textContent = "刪除";
    deleteBtn.dataset.action = "delete-rule";
    deleteBtn.dataset.id = rule.id;

    actions.appendChild(editBtn);
    actions.appendChild(deleteBtn);

    item.appendChild(label);
    item.appendChild(detail);
    item.appendChild(range);
    item.appendChild(actions);
    ruleList.appendChild(item);
  });
}

function renderExceptions(exceptions) {
  exceptionList.innerHTML = "";
  if (!exceptions.length) {
    exceptionList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無例外</p>";
    return;
  }
  exceptions.forEach((exception) => {
    const item = document.createElement("div");
    const isClosed = exception.type === "closed";
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = `${exception.service_date_local} · ${isClosed ? "關診" : "加開/覆寫"}`;
    const time = document.createElement("div");
    time.textContent = isClosed
      ? "不開診"
      : `${exception.override_start_time_local}～${exception.override_end_time_local} / 時段 ${exception.override_slot_minutes} 分`;
    const capacity = document.createElement("div");
    capacity.textContent = `容量：${isClosed ? "-" : exception.override_capacity_per_slot}`;
    const note = document.createElement("div");
    note.textContent = exception.note || "";

    const actions = document.createElement("div");
    actions.className = "flex gap-2 mt-2";
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "text-xs text-primary hover:underline";
    editBtn.textContent = "編輯";
    editBtn.dataset.action = "edit-exception";
    editBtn.dataset.id = exception.id;
    editBtn.dataset.date = exception.service_date_local;
    editBtn.dataset.type = exception.type;
    editBtn.dataset.start = exception.override_start_time_local || "";
    editBtn.dataset.end = exception.override_end_time_local || "";
    editBtn.dataset.slot = exception.override_slot_minutes || "";
    editBtn.dataset.capacity = exception.override_capacity_per_slot || "";
    editBtn.dataset.note = exception.note || "";

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "text-xs text-red-600 hover:underline";
    deleteBtn.textContent = "刪除";
    deleteBtn.dataset.action = "delete-exception";
    deleteBtn.dataset.id = exception.id;

    actions.appendChild(editBtn);
    actions.appendChild(deleteBtn);

    item.appendChild(label);
    item.appendChild(time);
    item.appendChild(capacity);
    item.appendChild(note);
    item.appendChild(actions);
    exceptionList.appendChild(item);
  });
}

function renderNotifications(jobs) {
  notificationList.innerHTML = "";
  if (!jobs.length) {
    notificationList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無通知</p>";
    return;
  }
  jobs.forEach((job) => {
    const item = document.createElement("div");
    item.innerHTML = `
      <div class="label">#${job.id.slice(0, 8)} · ${job.channel} · ${job.status}</div>
      <div>Event: ${job.event_type}｜Patient: ${job.patient_id}</div>
      <div>Scheduled: ${new Date(job.scheduled_at).toLocaleString()}</div>
    `;
    if (job.status === "failed") {
      const retryButton = document.createElement("button");
      retryButton.type = "button";
      retryButton.className = "mt-2 h-8 px-3 rounded-lg border border-[#dbe0e6] text-xs text-[#617589] hover:border-primary hover:text-primary";
      retryButton.textContent = "\u91cd\u9001";
      retryButton.addEventListener("click", async () => {
        try {
          await fetchJson(`${apiBase}/admin/notifications/jobs/${job.id}/retry`, { method: "POST" });
          showMessage(notificationMessage, "\u5df2\u91cd\u65b0\u6392\u7a0b");
          await loadNotifications();
        } catch (error) {
          showMessage(notificationMessage, "\u91cd\u9001\u5931\u6557", true);
        }
      });
      item.appendChild(retryButton);
    }
    notificationList.appendChild(item);
  });
}

async function loadNotifications() {
  const status = notificationStatus?.value || "";
  const query = status ? `?status=${status}` : "";
  const result = await fetchJson(`${apiBase}/admin/notifications/jobs${query}`);
  renderNotifications(result.data || []);
}

function renderTemplates(templates) {
  templateList.innerHTML = "";
  if (!templates.length) {
    templateList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無模板</p>";
    return;
  }
  templates.forEach((template) => {
    const item = document.createElement("div");
    item.className = "p-3 border border-[#e5e7eb] rounded-lg";
    const activeLabel = Number(template.is_active) === 1 ? "啟用" : "停用";
    const localeLabel = template.locale || "zh-TW";
    const versionLabel = template.version ? `v${template.version}` : "v1";
    item.innerHTML = `
      <div class="label">#${template.id.slice(0, 8)} · ${template.channel} · ${template.name} · ${versionLabel} · ${localeLabel} · ${activeLabel}</div>
      <div>Subject: ${template.subject || "-"}</div>
      <div>Body: ${template.body}</div>
    `;
    templateList.appendChild(item);
  });
}

async function loadTemplates() {
  const clinicId = templateClinic?.value || clinicSelect.value;
  if (!clinicId) return;
  const locale = templateLocale?.value || "";
  const params = new URLSearchParams({ clinic_id: clinicId });
  if (locale) params.set("locale", locale);
  params.set("include_versions", "1");
  const result = await fetchJson(`${apiBase}/admin/message-templates?${params.toString()}`);
  renderTemplates(result.data || []);
}

function renderReport(data) {
  if (!reportOutput) return;
  if (!data) {
    reportOutput.textContent = "No data";
    return;
  }
  reportOutput.innerHTML = `
    <div>Total: ${data.total_count}</div>
    <div>Booked: ${data.booked_count} | Checked-in: ${data.checked_in_count} | Called: ${data.called_count}</div>
    <div>In-room: ${data.in_room_count} | Done: ${data.done_count}</div>
    <div>No-show: ${data.no_show_count} | Cancelled: ${data.cancelled_count}</div>
    <div>Patients: ${data.patient_count}</div>
    <div>Slots: ${data.slot_count} | Capacity: ${data.total_capacity} | Booked: ${data.total_booked}</div>
  `;
}

async function loadDailyReport() {
  const clinicId = reportClinic?.value || clinicSelect.value;
  const providerId = reportProvider?.value || "";
  const date = reportDate?.value;
  if (!date) {
    if (reportMessage) reportMessage.textContent = "Select a date";
    return;
  }
  const params = new URLSearchParams({ service_date_local: date });
  if (clinicId) params.set("clinic_id", clinicId);
  if (providerId) params.set("provider_id", providerId);
  const result = await fetchJson(`${apiBase}/admin/reports/daily?${params.toString()}`);
  renderReport(result.data);
  if (reportMessage) reportMessage.textContent = "";
}

function renderAuditLogs(items) {
  if (!auditList) return;
  auditList.innerHTML = "";
  if (!items || !items.length) {
    auditList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無稽核紀錄</p>";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "p-2 border border-[#e5e7eb] rounded-lg";
    const actor = item.actor_type === "staff"
      ? item.staff_email || item.staff_name || "staff"
      : item.actor_type === "patient"
        ? item.patient_name || "patient"
        : item.actor_type;
    row.innerHTML = `
      <div class="label">${new Date(item.created_at).toLocaleString()} · ${actor}</div>
      <div>${item.action} ${item.entity_table} #${item.entity_id}</div>
    `;
    auditList.appendChild(row);
  });
}

async function loadAuditLogs() {
  const params = new URLSearchParams();
  if (auditClinic?.value) params.set("clinic_id", auditClinic.value);
  if (auditActor?.value) params.set("actor_type", auditActor.value);
  if (auditEntity?.value) params.set("entity_table", auditEntity.value);
  if (auditDateFrom?.value) params.set("date_from", auditDateFrom.value);
  if (auditDateTo?.value) params.set("date_to", auditDateTo.value);
  const result = await fetchJson(`${apiBase}/admin/audit-logs?${params.toString()}`);
  renderAuditLogs(result.data || []);
  if (auditMessage) auditMessage.textContent = "";
}

async function exportSlotsCsvAdmin() {
  const clinicId = csvClinic?.value || clinicSelect.value;
  const providerId = csvProvider?.value || "";
  const date = csvDate?.value;
  if (!date) {
    if (csvMessage) csvMessage.textContent = "Select a date";
    return;
  }
  const params = new URLSearchParams({ service_date_local: date });
  if (clinicId) params.set("clinic_id", clinicId);
  if (providerId) params.set("provider_id", providerId);
  const response = await fetch(`${apiBase}/admin/slots/export?${params.toString()}`);
  if (!response.ok) {
    if (csvMessage) csvMessage.textContent = "Export failed";
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `slots-${date}.csv`;
  link.click();
  URL.revokeObjectURL(url);
  if (csvMessage) csvMessage.textContent = "";
}

async function importSlotsCsvAdmin() {
  const file = csvFile?.files?.[0];
  if (!file) {
    if (csvMessage) csvMessage.textContent = "Choose a CSV file";
    return;
  }
  const text = await file.text();
  const result = await fetchJson(`${apiBase}/admin/slots/import`, {
    method: "POST",
    body: JSON.stringify({ csv: text }),
  });
  if (csvMessage) {
    const data = result.data || {};
    csvMessage.textContent = `Imported: created ${data.created || 0}, updated ${data.updated || 0}, skipped ${data.skipped || 0}`;
  }
  await loadBookingSlots();
}

function renderStaffUsers(users) {
  staffList.innerHTML = "";
  if (!users.length) {
    staffList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無人員</p>";
    return;
  }
  users.forEach((user) => {
    const item = document.createElement("div");
    item.className = "p-3 border border-[#e5e7eb] rounded-lg space-y-2";
    item.innerHTML = `
      <div class="label">#${user.id.slice(0, 8)} · ${user.email}</div>
      <div>姓名：${user.name || "-"}</div>
      <div>角色：${(user.roles || []).join(", ") || "-"}</div>
      <div class="flex flex-wrap gap-3 items-center">
        <label class="flex items-center gap-2 text-xs text-[#617589]">
          <input type="checkbox" class="staff-active-toggle size-4 rounded border-[#dbe0e6]" ${user.is_active ? "checked" : ""} />
          啟用
        </label>
        <input type="text" class="staff-role-input h-9 rounded-lg border border-[#dbe0e6] px-3 text-xs"
          value="${(user.roles || []).join(",")}" placeholder="system_admin,staff" />
        <button class="staff-update-btn h-9 px-3 rounded-lg border border-[#dbe0e6] text-xs text-[#617589] hover:border-primary hover:text-primary">
          更新
        </button>
      </div>
    `;
    item.querySelector(".staff-update-btn").addEventListener("click", async () => {
      const roleInput = item.querySelector(".staff-role-input");
      const activeToggle = item.querySelector(".staff-active-toggle");
      const roles = String(roleInput.value || "").split(/[,，\s]+/).filter(Boolean);
      try {
        await fetchJson(`${apiBase}/admin/staff-users/${user.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            clinic_id: staffClinic?.value || clinicSelect.value,
            roles,
            is_active: Boolean(activeToggle.checked),
          }),
        });
        showMessage(staffMessage, "已更新人員");
        await loadStaffUsers();
      } catch (error) {
        showMessage(staffMessage, "更新失敗", true);
      }
    });
    staffList.appendChild(item);
  });
}

async function loadStaffUsers() {
  const clinicId = staffClinic?.value || clinicSelect.value;
  if (!clinicId) return;
  const result = await fetchJson(`${apiBase}/admin/staff-users?clinic_id=${clinicId}`);
  renderStaffUsers(result.data || []);
}

function renderPatientAuth(items) {
  if (!patientAuthList) return;
  patientAuthList.innerHTML = "";
  if (!items.length) {
    patientAuthList.innerHTML = "<p class=\"text-[#9ca3af]\">尚無待審核</p>";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "p-3 border border-[#e5e7eb] rounded-lg space-y-1";
    row.innerHTML = `
      <div class="label">#${item.id.slice(0, 8)} · ${item.provider}</div>
      <div>病人：${item.display_name || item.patient_id}</div>
      <div>身分證：${item.national_id || "-"}</div>
      <div>綁定狀態：${item.bound_status}</div>
      <div class="flex gap-2 mt-2">
        <button class="patient-auth-approve h-8 px-3 rounded-lg bg-primary text-white text-xs">核准</button>
        <button class="patient-auth-reject h-8 px-3 rounded-lg border border-[#dbe0e6] text-xs text-[#617589]">拒絕</button>
      </div>
    `;
    row.querySelector(".patient-auth-approve").addEventListener("click", async () => {
      try {
        await fetchJson(`${apiBase}/admin/patient-auth/${item.id}`, {
          method: "PATCH",
          body: JSON.stringify({ bound_status: "approved" }),
        });
        showMessage(patientAuthMessage, "已核准");
        await loadPatientAuth();
      } catch (error) {
        showMessage(patientAuthMessage, "更新失敗", true);
      }
    });
    row.querySelector(".patient-auth-reject").addEventListener("click", async () => {
      try {
        await fetchJson(`${apiBase}/admin/patient-auth/${item.id}`, {
          method: "PATCH",
          body: JSON.stringify({ bound_status: "rejected" }),
        });
        showMessage(patientAuthMessage, "已拒絕");
        await loadPatientAuth();
      } catch (error) {
        showMessage(patientAuthMessage, "更新失敗", true);
      }
    });
    patientAuthList.appendChild(row);
  });
}

async function loadPatientAuth() {
  const result = await fetchJson(`${apiBase}/admin/patient-auth?status=pending_review`);
  renderPatientAuth(result.data || []);
}

const statusLabels = {
  booked: "已預約",
  checked_in: "已報到",
  called: "已叫號",
  in_room: "診間中",
  done: "完成",
  no_show: "未到",
  cancelled: "已取消",
};
const statusTransitions = {
  booked: ["checked_in", "called", "no_show", "cancelled"],
  checked_in: ["called", "in_room", "done", "no_show", "cancelled"],
  called: ["in_room", "done", "no_show", "cancelled"],
  in_room: ["done", "no_show", "cancelled"],
  done: [],
  no_show: [],
  cancelled: [],
};
const actionStatuses = ["checked_in", "called", "in_room", "done", "no_show"];

function parseQueueNumbersInput(value) {
  if (!value) return [];
  const parts = value.split(/[,，\s]+/).filter(Boolean);
  const numbers = parts
    .map((item) => Number(item))
    .filter((item) => Number.isInteger(item) && item > 0);
  return Array.from(new Set(numbers)).sort((a, b) => a - b);
}

function getCurrentQueueNo(appointments) {
  let current = null;
  appointments.forEach((item) => {
    if (item.status === "called" || item.status === "in_room") {
      const value = Number(item.queue_no);
      if (!Number.isFinite(value)) return;
      current = current === null ? value : Math.max(current, value);
    }
  });
  return current;
}

function getNextQueueAppointment() {
  const appointments = state.queueAppointments || [];
  if (!appointments.length) return null;
  const reserved = parseQueueNumbersInput(queueReserved?.value || "");
  const reservedSet = new Set(reserved);
  const current = getCurrentQueueNo(appointments);
  const sorted = [...appointments].sort((a, b) => a.queue_no - b.queue_no);
  for (const appointment of sorted) {
    const queueNo = Number(appointment.queue_no);
    if (!Number.isFinite(queueNo)) continue;
    if (current !== null && queueNo <= current) continue;
    if (reservedSet.has(queueNo)) continue;
    if (appointment.status === "booked" || appointment.status === "checked_in") {
      return appointment;
    }
  }
  return null;
}

function renderQueueSummary(status) {
  if (!queueSummary) return;
  if (!status) {
    queueSummary.textContent = "\u5C1A\u672A\u8F09\u5165";
    return;
  }
  const current = status.current_queue_no ?? "-";
  const next = status.next_queue_no ?? "-";
  const reserved = status.reserved_queue_no?.length ? status.reserved_queue_no.join(",") : "\u7121";
  const updated = status.updated_at ? timeFormatter.format(new Date(status.updated_at)) : "--";
  queueSummary.textContent = `\u76EE\u524D ${current} | \u4E0B\u4E00\u4F4D ${next} | \u4FDD\u7559 ${reserved} | \u66F4\u65B0 ${updated}`;
  if (queueReserved) {
    queueReserved.value = status.reserved_queue_no?.length ? status.reserved_queue_no.join(",") : "";
  }
}
function renderQueueList(appointments) {
  if (!queueList) return;
  queueList.innerHTML = "";
  if (!appointments.length) {
    queueList.innerHTML = "<p class=\"text-[#9ca3af]\">No data</p>";
    return;
  }

  const currentQueueNo = state.queueStatus?.current_queue_no;
  const nextQueueNo = state.queueStatus?.next_queue_no;

  appointments.forEach((appointment) => {
    const wrapper = document.createElement("div");
    const isSelected = state.selectedQueueAppointment?.id === appointment.id;
    wrapper.className = isSelected
      ? "flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 border border-primary rounded-lg bg-[#f8fdf9]"
      : "flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 border border-[#e5e7eb] rounded-lg";

    const queueNo = Number(appointment.queue_no);
    const badges = [];
    if (Number.isFinite(queueNo)) {
      if (currentQueueNo !== null && queueNo === Number(currentQueueNo)) {
        badges.push("<span class=\"inline-flex items-center px-2 py-0.5 rounded-full bg-[#eef7ff] text-[10px] text-[#1f6fb2]\">Current</span>");
      }
      if (nextQueueNo !== null && queueNo === Number(nextQueueNo)) {
        badges.push("<span class=\"inline-flex items-center px-2 py-0.5 rounded-full bg-[#fdf4e7] text-[10px] text-[#b26a1f]\">Next</span>");
      }
    }
    const badgeHtml = badges.length ? `<div class=\"flex flex-wrap gap-2 mt-2\">${badges.join("")}</div>` : "";
    const statusLabel = statusLabels[appointment.status] || appointment.status;

    const left = document.createElement("div");
    left.innerHTML = `
      <div class="text-sm font-semibold text-[#111418]">#${appointment.queue_no}</div>
      <div class="text-xs text-[#617589]">${appointment.patient_name || appointment.booking_ref}</div>
      <div class="text-xs text-[#9ca3af]">Status ${statusLabel}</div>
      ${badgeHtml}
    `;

    const actions = document.createElement("div");
    actions.className = "flex flex-wrap gap-2";
    const viewButton = document.createElement("button");
    viewButton.type = "button";
    viewButton.className =
      "h-9 px-3 rounded-lg border border-[#dbe0e6] text-xs text-[#617589] hover:border-primary hover:text-primary";
    viewButton.textContent = "View";
    viewButton.addEventListener("click", () => loadQueuePatientDetail(appointment));
    actions.appendChild(viewButton);

    const canCall = ["booked", "checked_in"].includes(appointment.status);
    const callButton = document.createElement("button");
    callButton.type = "button";
    callButton.className = canCall
      ? "h-9 px-3 rounded-lg bg-primary text-white text-xs font-semibold"
      : "h-9 px-3 rounded-lg border border-[#dbe0e6] text-xs text-[#617589]";
    callButton.textContent = "Call";
    callButton.disabled = !canCall;
    callButton.addEventListener("click", () => updateAppointmentStatus(appointment.id, "called"));
    actions.appendChild(callButton);

    wrapper.appendChild(left);
    wrapper.appendChild(actions);
    queueList.appendChild(wrapper);
  });
}
function renderQueueDetailActions(appointment) {
  if (!queueDetailActions) return;
  queueDetailActions.innerHTML = "";
  if (!appointment) return;
  const allowed = new Set(statusTransitions[appointment.status] ?? []);
  actionStatuses.forEach((status) => {
    const button = document.createElement("button");
    button.type = "button";
    const isActive = appointment.status === status;
    const isAllowed = allowed.has(status);
    button.className = isActive
      ? "h-8 px-3 rounded-lg bg-primary text-white text-xs font-semibold"
      : "h-8 px-3 rounded-lg border border-[#dbe0e6] text-xs text-[#617589] hover:border-primary hover:text-primary";
    button.textContent = statusLabels[status] || status;
    button.disabled = isActive || !isAllowed;
    button.addEventListener("click", () => updateAppointmentStatus(appointment.id, status));
    queueDetailActions.appendChild(button);
  });
}
function resetQueueDetail() {
  state.selectedQueueAppointment = null;
  if (queueDetailMeta) queueDetailMeta.textContent = "\u8ACB\u5148\u8F09\u5165\u770B\u8A3A\u6E05\u55AE";
  if (queueDetailBasic) queueDetailBasic.innerHTML = "<p>\u5C1A\u7121\u8CC7\u6599</p>";
  if (queueDetailForms) queueDetailForms.innerHTML = "<p>\u5C1A\u7121\u8CC7\u6599</p>";
  if (queueDetailActions) queueDetailActions.innerHTML = "";
  if (queueDetailMessage) {
    queueDetailMessage.textContent = "";
    queueDetailMessage.className = "text-xs text-[#9ca3af]";
  }
}
async function loadQueuePatientDetail(appointment) {
  if (!appointment?.patient_id) {
    resetQueueDetail();
    return;
  }

  state.selectedQueueAppointment = appointment;

  renderQueueDetailActions(appointment);
  renderQueueList(state.queueAppointments);
  if (queueDetailMeta) {
    queueDetailMeta.textContent = `#${appointment.queue_no} · ${appointment.service_date_local}`;
  }
  if (queueDetailBasic) {
    queueDetailBasic.innerHTML = "<p>載入中...</p>";
  }
  if (queueDetailForms) {
    queueDetailForms.innerHTML = "<p>載入中...</p>";
  }

  try {
    const patient = await fetchJson(`${apiBase}/admin/patients/${appointment.patient_id}`);
    const data = patient.data || {};
    if (queueDetailBasic) {
      queueDetailBasic.innerHTML = `
        <div>姓名：${data.display_name || "-"}</div>
        <div>身分證：${data.national_id || "-"}</div>
        <div>生日：${data.dob || "-"}</div>
        <div>電話：${data.phone || "-"}</div>
        <div>Email：${data.email || "-"}</div>
        <div>狀態：${formatAppointmentStatus(appointment.status)}</div>
        <div>查詢碼：${appointment.booking_ref || "-"}</div>
      `;
    }

    await loadFormSchemas();
    const submissions = await fetchJson(`${apiBase}/admin/form-submissions?patient_id=${appointment.patient_id}`);
    renderFormsInto(queueDetailForms, submissions.data || []);
  } catch (error) {
    if (queueDetailMessage) {
      queueDetailMessage.textContent = "載入病人詳情失敗";
      queueDetailMessage.className = "text-xs text-red-600";
    }
  }
}

async function loadQueueStatus() {
  const providerId = providerSelect.value;
  const date = queueDate?.value;
  if (!providerId || !date) return;
  const params = new URLSearchParams({
    provider_id: providerId,
    service_date_local: date,
  });
  const result = await fetchJson(`${apiBase}/public/queue-status?${params.toString()}`);
  state.queueStatus = result.data || null;
  renderQueueSummary(state.queueStatus);
  if (state.queueAppointments?.length) {
    renderQueueList(state.queueAppointments);
  }
}

async function loadQueueAppointments() {
  const providerId = providerSelect.value;
  const date = queueDate?.value;
  if (!providerId || !date) return;
  const params = new URLSearchParams({
    provider_id: providerId,
    service_date_local: date,
  });
  const result = await fetchJson(`${apiBase}/admin/appointments?${params.toString()}`);
  const appointments = (result.data || []).sort((a, b) => a.queue_no - b.queue_no);
  state.queueAppointments = appointments;
  renderQueueList(appointments);

  if (state.selectedQueueAppointment?.id) {
    const selected = appointments.find((item) => item.id === state.selectedQueueAppointment.id);
    if (!selected) {
      resetQueueDetail();
    }
  }
}

async function refreshQueueDashboard() {
  if (!providerSelect.value) {
    showMessage(queueMessage, "請先選擇醫師", true);
    return;
  }
  if (queueDate && !queueDate.value) {
    queueDate.value = getTaipeiDateString();
  }
  try {
    await Promise.all([loadQueueStatus(), loadQueueAppointments()]);
  } catch (error) {
    showMessage(queueMessage, "載入叫號清單失敗", true);
  }
}

function setQueueAutoRefresh(enabled) {
  if (queueRefreshTimer) {
    window.clearInterval(queueRefreshTimer);
    queueRefreshTimer = null;
  }
  if (!enabled) return;
  queueRefreshTimer = window.setInterval(() => {
    refreshQueueDashboard().catch(() => {});
  }, queueRefreshIntervalMs);
}
async function updateAppointmentStatus(appointmentId, toStatus) {
  try {
    const notify = Boolean(queueNotifyCalled?.checked) && toStatus === "called";
    await fetchJson(`${apiBase}/admin/appointments/${appointmentId}/status`, {
      method: "POST",
      body: JSON.stringify({ to_status: toStatus, notify }),
    });
    showMessage(queueMessage, `已更新為 ${statusLabels[toStatus] || toStatus}`);
    await refreshQueueDashboard();
  } catch (error) {
    showMessage(queueMessage, "更新狀態失敗", true);
  }
}

function normalizeBookingRef(value) {
  return (value || "").replace(/\s+/g, "").toUpperCase();
}

function normalizeNationalId(value) {
  return (value || "").replace(/\s+/g, "").toUpperCase();
}

function renderRescheduleSummary(appointment) {
  if (!appointment) {
    rescheduleSummary.textContent = "尚未查詢";
    return;
  }
  rescheduleSummary.textContent = `#${appointment.booking_ref} · ${appointment.status}｜號碼 ${appointment.queue_no}`;
}

async function loadRescheduleSlots() {
  const clinicId = rescheduleClinicId.value;
  const providerId = rescheduleProviderId.value;
  const date = rescheduleDate.value;
  if (!clinicId || !providerId || !date) {
    return;
  }

  const params = new URLSearchParams({
    clinic_id: clinicId,
    provider_id: providerId,
    service_date_local: date,
  });
  const result = await fetchJson(`${apiBase}/public/slots?${params.toString()}`);
  const slots = result.data || [];

  rescheduleSlot.innerHTML = "";
  if (!slots.length) {
    rescheduleSlot.innerHTML = "<option value=\"\">無可預約時段</option>";
    return;
  }

  slots.forEach((slot) => {
    const timeLabel = slot.start_at_utc
      ? timeFormatter.format(new Date(slot.start_at_utc))
      : slot.start_time_local;
    const isFull = Number(slot.booked_count) >= Number(slot.capacity) || slot.status !== "open";
    const option = document.createElement("option");
    option.value = slot.slot_id;
    option.textContent = `${timeLabel} (${slot.booked_count}/${slot.capacity})`;
    option.disabled = isFull;
    rescheduleSlot.appendChild(option);
  });
}

async function loadBookingSlots() {
  const clinicId = clinicSelect.value;
  const providerId = providerSelect.value;
  const date = bookingDate.value;
  if (!clinicId || !providerId || !date) return;

  const params = new URLSearchParams({
    clinic_id: clinicId,
    provider_id: providerId,
    service_date_local: date,
  });
  const result = await fetchJson(`${apiBase}/public/slots?${params.toString()}`);
  const slots = result.data || [];

  bookingSlot.innerHTML = "";
  if (!slots.length) {
    bookingSlot.innerHTML = "<option value=\"\">無可預約時段</option>";
    return;
  }

  slots.forEach((slot) => {
    const timeLabel = slot.start_at_utc
      ? timeFormatter.format(new Date(slot.start_at_utc))
      : slot.start_time_local;
    const isFull = Number(slot.booked_count) >= Number(slot.capacity) || slot.status !== "open";
    const option = document.createElement("option");
    option.value = slot.slot_id;
    option.textContent = `${timeLabel} (${slot.booked_count}/${slot.capacity})`;
    option.disabled = isFull;
    bookingSlot.appendChild(option);
  });
}

function syncExceptionFields() {
  const isOverride = exceptionType.value === "override";
  exceptionOverrideFields.classList.toggle("hidden", !isOverride);
  exceptionCapacity.parentElement.classList.toggle("hidden", !isOverride);
}

function resetRuleForm() {
  ruleId.value = "";
  ruleSubmit.textContent = "新增規則";
  ruleCancelEdit.classList.add("hidden");
}

function resetExceptionForm() {
  exceptionId.value = "";
  exceptionSubmit.textContent = "新增例外";
  exceptionCancelEdit.classList.add("hidden");
}

function resetClinicForm() {
  clinicIdInput.value = "";
  clinicNameInput.value = "";
  clinicTimezoneInput.value = "Asia/Taipei";
  clinicPhoneInput.value = "";
  clinicAddressInput.value = "";
  clinicSubmit.textContent = "新增院所";
  clinicCancelEdit.classList.add("hidden");
}

function resetProviderForm() {
  providerIdInput.value = "";
  providerNameInput.value = "";
  providerTitleInput.value = "";
  providerSpecialtyInput.value = "";
  providerPhotoInput.value = "";
  providerBioInput.value = "";
  providerActiveInput.checked = true;
  providerSubmit.textContent = "新增醫師";
  providerCancelEdit.classList.add("hidden");
}

exceptionType.addEventListener("change", syncExceptionFields);

clinicRefresh?.addEventListener("click", async () => {
  try {
    await loadClinics();
    await loadProvidersAdmin();
    showMessage(clinicMessage, "已更新院所列表");
  } catch (error) {
    showMessage(clinicMessage, "載入院所失敗", true);
  }
});

clinicForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!clinicNameInput.value) {
    showMessage(clinicMessage, "請填寫院所名稱", true);
    return;
  }

  try {
    if (clinicIdInput.value) {
      await fetchJson(`${apiBase}/admin/clinics/${clinicIdInput.value}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: clinicNameInput.value,
          timezone: clinicTimezoneInput.value || "Asia/Taipei",
          phone: clinicPhoneInput.value || undefined,
          address: clinicAddressInput.value || undefined,
        }),
      });
      showMessage(clinicMessage, "已更新院所");
    } else {
      await fetchJson(`${apiBase}/admin/clinics`, {
        method: "POST",
        body: JSON.stringify({
          name: clinicNameInput.value,
          timezone: clinicTimezoneInput.value || "Asia/Taipei",
          phone: clinicPhoneInput.value || undefined,
          address: clinicAddressInput.value || undefined,
        }),
      });
      showMessage(clinicMessage, "已新增院所");
    }
    resetClinicForm();
    await loadClinics();
    await loadProvidersAdmin();
  } catch (error) {
    showMessage(clinicMessage, "院所儲存失敗", true);
  }
});

clinicCancelEdit?.addEventListener("click", () => {
  resetClinicForm();
});

providerRefresh?.addEventListener("click", async () => {
  try {
    await loadProvidersAdmin();
    showMessage(providerMessage, "已更新醫師列表");
  } catch (error) {
    showMessage(providerMessage, "載入醫師失敗", true);
  }
});

providerFormAdmin?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!providerClinicSelect.value) {
    showMessage(providerMessage, "請選擇院所", true);
    return;
  }
  if (!providerNameInput.value) {
    showMessage(providerMessage, "請填寫醫師姓名", true);
    return;
  }

  const payload = {
    clinic_id: providerClinicSelect.value,
    name: providerNameInput.value,
    title: providerTitleInput.value || undefined,
    specialty: providerSpecialtyInput.value || undefined,
    bio: providerBioInput.value || undefined,
    photo_url: providerPhotoInput.value || undefined,
    is_active: providerActiveInput.checked,
  };

  try {
    if (providerIdInput.value) {
      await fetchJson(`${apiBase}/admin/providers/${providerIdInput.value}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      showMessage(providerMessage, "已更新醫師");
    } else {
      await fetchJson(`${apiBase}/admin/providers`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showMessage(providerMessage, "已新增醫師");
    }
    resetProviderForm();
    await loadClinics();
    await loadProvidersAdmin();
    await loadProviders();
  } catch (error) {
    showMessage(providerMessage, "醫師儲存失敗", true);
  }
});

providerCancelEdit?.addEventListener("click", () => {
  resetProviderForm();
});

providerClinicSelect?.addEventListener("change", async () => {
  try {
    await loadProvidersAdmin();
  } catch (error) {
    showMessage(providerMessage, "載入醫師失敗", true);
  }
});

noticeClinic?.addEventListener("change", async () => {
  try {
    await loadClinicNotice();
  } catch (error) {
    showMessage(noticeMessage, "載入公告失敗", true);
  }
});

noticeForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!noticeClinic?.value) {
    showMessage(noticeMessage, "請選擇院所", true);
    return;
  }
  if (!noticeContent?.value) {
    showMessage(noticeMessage, "請填寫公告內容", true);
    return;
  }
  try {
    await fetchJson(`${apiBase}/admin/clinic-notice`, {
      method: "POST",
      body: JSON.stringify({
        clinic_id: noticeClinic.value,
        content: noticeContent.value,
      }),
    });
    showMessage(noticeMessage, "已更新看診公告");
  } catch (error) {
    showMessage(noticeMessage, "更新失敗", true);
  }
});

clinicSelect.addEventListener("change", async () => {
  if (templateClinic) templateClinic.value = clinicSelect.value;
  if (staffClinic) staffClinic.value = clinicSelect.value;
  if (patientClinic) patientClinic.value = clinicSelect.value;
  if (reportClinic) reportClinic.value = clinicSelect.value;
  if (csvClinic) csvClinic.value = clinicSelect.value;
  if (auditClinic) auditClinic.value = clinicSelect.value;
  clearPatientForm();
  await loadProviders();
  await loadTemplates();
  await loadStaffUsers();
  await loadPatients();
  await loadProvidersForSelect(reportProvider, reportClinic?.value || "");
  await loadProvidersForSelect(csvProvider, csvClinic?.value || "");
});
providerSelect.addEventListener("change", () => {
  updateProviderSummary();
  loadRulesAndExceptions();
  loadBookingSlots();
  refreshQueueDashboard();
});

reportClinic?.addEventListener("change", () => {
  loadProvidersForSelect(reportProvider, reportClinic.value);
});

csvClinic?.addEventListener("change", () => {
  loadProvidersForSelect(csvProvider, csvClinic.value);
});

seedButton.addEventListener("click", async () => {
  try {
    await fetchJson(`${apiBase}/dev/seed`, { method: "POST" });
    await loadClinics();
    await loadProviders();
  } catch (error) {
    showMessage(generateMessage, "產生測試資料失敗", true);
  }
});

notificationRefresh.addEventListener("click", async () => {
  try {
    await loadNotifications();
    showMessage(notificationMessage, "已更新通知佇列");
  } catch (error) {
    showMessage(notificationMessage, "載入通知失敗", true);
  }
});

notificationStatus?.addEventListener("change", async () => {
  await loadNotifications();
});

notificationProcess.addEventListener("click", async () => {
  try {
    const response = await fetchJson(`${apiBase}/admin/notifications/process`, {
      method: "POST",
      body: JSON.stringify({ limit: 20 }),
    });
    showMessage(notificationMessage, `已處理 ${response.data.processed} 筆通知`);
    await loadNotifications();
  } catch (error) {
    showMessage(notificationMessage, "處理通知失敗", true);
  }
});

templateRefresh?.addEventListener("click", async () => {
  try {
    await loadTemplates();
    showMessage(templateMessage, "已更新模板列表");
  } catch (error) {
    showMessage(templateMessage, "載入模板失敗", true);
  }
});

templateForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const clinicId = templateClinic?.value || clinicSelect.value;
  if (!clinicId) {
    showMessage(templateMessage, "請先選擇院所", true);
    return;
  }
  if (!templateName.value || !templateBody.value) {
    showMessage(templateMessage, "請填模板名稱與內容", true);
    return;
  }
  try {
    await fetchJson(`${apiBase}/admin/message-templates`, {
      method: "POST",
      body: JSON.stringify({
        clinic_id: clinicId,
        channel: templateChannel.value,
        name: templateName.value,
        subject: templateSubject.value || undefined,
        body: templateBody.value,
        locale: templateLocale?.value || undefined,
      }),
    });
    templateName.value = "";
    templateSubject.value = "";
    templateBody.value = "";
    if (templatePayload) templatePayload.value = "";
    if (templatePreviewOutput) templatePreviewOutput.textContent = "";
    showMessage(templateMessage, "已新增模板");
    await loadTemplates();
  } catch (error) {
    showMessage(templateMessage, "新增模板失敗", true);
  }
});

templatePreview?.addEventListener("click", async () => {
  try {
    const payloadText = templatePayload?.value || "{}";
    const payload = payloadText ? JSON.parse(payloadText) : {};
    const result = await fetchJson(`${apiBase}/admin/message-templates/preview`, {
      method: "POST",
      body: JSON.stringify({
        subject: templateSubject.value || undefined,
        body: templateBody.value || undefined,
        payload,
      }),
    });
    if (templatePreviewOutput) {
      const subject = result.data?.subject ? `Subject: ${result.data.subject}` : "Subject: (none)";
      const body = result.data?.body ? `Body: ${result.data.body}` : "Body: (empty)";
      templatePreviewOutput.textContent = `${subject}
${body}`;
    }
  } catch (error) {
    showMessage(templateMessage, "Preview failed", true);
  }
});


templateClinic?.addEventListener("change", async () => {
  try {
    await loadTemplates();
  } catch (error) {
    showMessage(templateMessage, "載入模板失敗", true);
  }
});

staffRefresh?.addEventListener("click", async () => {
  try {
    await loadStaffUsers();
    showMessage(staffMessage, "已更新人員列表");
  } catch (error) {
    showMessage(staffMessage, "載入人員失敗", true);
  }
});

staffForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const clinicId = staffClinic?.value || clinicSelect.value;
  if (!clinicId) {
    showMessage(staffMessage, "請先選擇院所", true);
    return;
  }
  if (!staffEmail.value) {
    showMessage(staffMessage, "請填 Email", true);
    return;
  }
  const roles = String(staffRoles.value || "")
    .split(/[,，\s]+/)
    .filter(Boolean);
  try {
    await fetchJson(`${apiBase}/admin/staff-users`, {
      method: "POST",
      body: JSON.stringify({
        clinic_id: clinicId,
        email: staffEmail.value,
        name: staffName.value || undefined,
        roles,
      }),
    });
    staffEmail.value = "";
    staffName.value = "";
    staffRoles.value = "";
    showMessage(staffMessage, "已新增人員");
    await loadStaffUsers();
  } catch (error) {
    showMessage(staffMessage, "新增人員失敗", true);
  }
});

staffClinic?.addEventListener("change", async () => {
  try {
    await loadStaffUsers();
  } catch (error) {
    showMessage(staffMessage, "載入人員失敗", true);
  }
});

patientAuthRefresh?.addEventListener("click", async () => {
  try {
    await loadPatientAuth();
    showMessage(patientAuthMessage, "已更新審核列表");
  } catch (error) {
    showMessage(patientAuthMessage, "載入失敗", true);
  }
});

patientRefresh?.addEventListener("click", async () => {
  await loadPatients();
});

patientClinic?.addEventListener("change", async () => {
  clearPatientForm();
  await loadPatients();
});

patientSearchForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadPatients();
});

patientEditForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!patientIdInput.value) {
    showMessage(patientMessage, "請先選擇病人", true);
    return;
  }

  try {
    await fetchJson(`${apiBase}/admin/patients/${patientIdInput.value}`, {
      method: "PATCH",
      body: JSON.stringify({
        display_name: patientNameInput.value,
        gender: patientGenderInput.value || null,
        phone: patientPhoneInput.value,
        email: patientEmailInput.value,
      }),
    });
    showMessage(patientMessage, "已更新病人資料");
    await loadPatients();
  } catch (error) {
    showMessage(patientMessage, "更新失敗", true);
  }
});

patientClear?.addEventListener("click", () => {
  clearPatientForm();
});

patientDelete?.addEventListener("click", async () => {
  if (!patientIdInput.value) {
    showMessage(patientMessage, "請先選擇病人", true);
    return;
  }
  if (!confirm("確定要刪除這位病人嗎？")) return;
  try {
    await fetchJson(`${apiBase}/admin/patients/${patientIdInput.value}`, {
      method: "DELETE",
    });
    showMessage(patientMessage, "已刪除病人");
    clearPatientForm();
    await loadPatients();
  } catch (error) {
    showMessage(patientMessage, "刪除失敗", true);
  }
});

patientUnlock?.addEventListener("click", async () => {
  if (!patientIdInput.value) {
    showMessage(patientMessage, "請先選擇病人", true);
    return;
  }
  try {
    await fetchJson(`${apiBase}/admin/patients/${patientIdInput.value}/unlock`, {
      method: "POST",
    });
    showMessage(patientMessage, "已解除鎖定");
    await loadPatients();
  } catch (error) {
    showMessage(patientMessage, "解除鎖定失敗", true);
  }
});

patientCreateForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const clinicId = patientClinic?.value || clinicSelect?.value;
  const nationalId = normalizeNationalId(patientCreateNationalId.value);
  if (!clinicId) {
    showMessage(patientMessage, "請先選擇院所", true);
    return;
  }
  if (!nationalId || !patientCreateDob.value) {
    showMessage(patientMessage, "請填身分證與生日", true);
    return;
  }
  if (!patientCreatePhone.value && !patientCreateEmail.value) {
    showMessage(patientMessage, "請填手機或 Email", true);
    return;
  }

  try {
    await fetchJson(`${apiBase}/admin/patients/quick-create`, {
      method: "POST",
      body: JSON.stringify({
        clinic_id: clinicId,
        national_id: nationalId,
        dob: patientCreateDob.value,
        display_name: patientCreateName.value || undefined,
        phone: patientCreatePhone.value || undefined,
        email: patientCreateEmail.value || undefined,
      }),
    });
    showMessage(patientMessage, "已新增病人");
    patientCreateNationalId.value = "";
    patientCreateDob.value = "";
    patientCreateName.value = "";
    patientCreatePhone.value = "";
    patientCreateEmail.value = "";
    await loadPatients();
  } catch (error) {
    showMessage(patientMessage, "新增失敗，請檢查欄位", true);
  }
});

patientApptRefresh?.addEventListener("click", async () => {
  await loadPatientAppointments({ reset: true });
});

patientApptFilter?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadPatientAppointments({ reset: true });
});

patientApptMore?.addEventListener("click", async () => {
  await loadPatientAppointments({ reset: false });
});

patientFormRefresh?.addEventListener("click", async () => {
  await loadPatientForms();
});

formDefinitionRefresh?.addEventListener("click", async () => {
  await loadFormDefinitions();
});

formDefinitionClear?.addEventListener("click", () => {
  resetFormDefinitionEditor();
});

formDefinitionForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!formDefinitionType?.value) {
    showMessage(formDefinitionMessage, "請選擇表單類型", true);
    return;
  }
  if (!formDefinitionSchema?.value) {
    showMessage(formDefinitionMessage, "請輸入 Schema JSON", true);
    return;
  }
  let schemaJson = null;
  try {
    schemaJson = JSON.stringify(JSON.parse(formDefinitionSchema.value));
  } catch {
    showMessage(formDefinitionMessage, "Schema JSON 格式錯誤", true);
    return;
  }
  try {
    const response = await fetchJson(`${apiBase}/admin/forms`, {
      method: "POST",
      body: JSON.stringify({
        type: formDefinitionType.value.trim(),
        schema_json: schemaJson,
        is_active: Boolean(formDefinitionActive?.checked),
      }),
    });
    showMessage(
      formDefinitionMessage,
      `已建立表單版本 v${response.data?.version ?? ""}`
    );
    await loadFormDefinitions();
  } catch (error) {
    showMessage(formDefinitionMessage, "新增表單失敗", true);
  }
});

formDefinitionList?.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const action = button.dataset.action;
  const id = button.dataset.id;
  if (!action || !id) return;
  if (action === "copy-form") {
    fillFormDefinitionEditor(state.formDefinitionsById[id]);
    return;
  }
  if (action === "activate-form") {
    try {
      await fetchJson(`${apiBase}/admin/forms/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: true }),
      });
      await loadFormDefinitions();
    } catch (error) {
      showMessage(formDefinitionMessage, "啟用表單失敗", true);
    }
  }
});

rescheduleLookupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const bookingRef = normalizeBookingRef(rescheduleBookingRef.value);
  if (!bookingRef) {
    showMessage(rescheduleMessage, "請輸入查詢碼", true);
    return;
  }

  try {
    const result = await fetchJson(`${apiBase}/admin/appointments?booking_ref=${bookingRef}`);
    const appointment = result.data?.[0];
    if (!appointment) {
      showMessage(rescheduleMessage, "查無資料", true);
      renderRescheduleSummary(null);
      return;
    }
    rescheduleAppointmentId.value = appointment.id;
    rescheduleProviderId.value = appointment.provider_id;
    rescheduleClinicId.value = appointment.clinic_id;
    renderRescheduleSummary(appointment);
    showMessage(rescheduleMessage, "已載入預約");
  } catch (error) {
    showMessage(rescheduleMessage, "查詢失敗", true);
  }
});

rescheduleDate.addEventListener("change", async () => {
  try {
    await loadRescheduleSlots();
  } catch (error) {
    showMessage(rescheduleMessage, "載入時段失敗", true);
  }
});

rescheduleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!rescheduleAppointmentId.value) {
    showMessage(rescheduleMessage, "請先查詢預約", true);
    return;
  }
  if (!rescheduleSlot.value) {
    showMessage(rescheduleMessage, "請選擇新時段", true);
    return;
  }

  try {
    const response = await fetchJson(`${apiBase}/admin/appointments/reschedule`, {
      method: "POST",
      body: JSON.stringify({
        appointment_id: rescheduleAppointmentId.value,
        new_slot_id: rescheduleSlot.value,
        notify: Boolean(rescheduleNotify.checked),
        reason: rescheduleReason.value || undefined,
      }),
    });
    showMessage(
      rescheduleMessage,
      `已改約，新的查詢碼 ${response.data.booking_ref} / 號碼 ${response.data.queue_no}`
    );
  } catch (error) {
    showMessage(rescheduleMessage, "改約失敗", true);
  }
});

bookingLookupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const nationalId = normalizeNationalId(bookingNationalId.value);
  if (!nationalId) {
    showMessage(bookingMessage, "請輸入身分證字號", true);
    return;
  }

  try {
    const response = await fetchJson(`${apiBase}/admin/patients/lookup`, {
      method: "POST",
      body: JSON.stringify({ national_id: nationalId }),
    });
    bookingPatientId.value = response.data.id;
    bookingPatientSummary.textContent = `${response.data.display_name || "病人"} / ${response.data.dob}`;
    showMessage(bookingMessage, "已找到病人");
  } catch (error) {
    bookingPatientId.value = "";
    bookingPatientSummary.textContent = "查無病人，可快速新增";
    showMessage(bookingMessage, "查無病人，可快速新增", true);
  }
});

bookingCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const clinicId = clinicSelect.value;
  const nationalId = normalizeNationalId(bookingNationalId.value);
  if (!clinicId) {
    showMessage(bookingMessage, "請先選擇院所", true);
    return;
  }
  if (!nationalId || !bookingDob.value) {
    showMessage(bookingMessage, "請填身分證與生日", true);
    return;
  }

  try {
    const response = await fetchJson(`${apiBase}/admin/patients/quick-create`, {
      method: "POST",
      body: JSON.stringify({
        clinic_id: clinicId,
        national_id: nationalId,
        dob: bookingDob.value,
        display_name: bookingName.value || undefined,
        phone: bookingPhone.value || undefined,
        email: bookingEmail.value || undefined,
      }),
    });
    bookingPatientId.value = response.data.patient_id;
    bookingPatientSummary.textContent = "已建立病人";
    showMessage(bookingMessage, "已建立病人");
  } catch (error) {
    showMessage(bookingMessage, "建立病人失敗，請檢查欄位", true);
  }
});

bookingDate.addEventListener("change", async () => {
  try {
    await loadBookingSlots();
  } catch (error) {
    showMessage(bookingMessage, "載入時段失敗", true);
  }
});

bookingFormAdmin.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!bookingPatientId.value) {
    showMessage(bookingMessage, "請先查詢或建立病人", true);
    return;
  }
  if (!bookingSlot.value) {
    showMessage(bookingMessage, "請選擇時段", true);
    return;
  }

  try {
    const response = await fetchJson(`${apiBase}/admin/appointments/book`, {
      method: "POST",
      body: JSON.stringify({
        patient_id: bookingPatientId.value,
        slot_id: bookingSlot.value,
        notify: Boolean(bookingNotify.checked),
        reason: bookingReason.value || undefined,
      }),
    });
    showMessage(
      bookingMessage,
      `已完成掛號，查詢碼 ${response.data.booking_ref} / 號碼 ${response.data.queue_no}`
    );
  } catch (error) {
    showMessage(bookingMessage, "掛號失敗", true);
  }
});

queueForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await refreshQueueDashboard();
});

queueSaveReserved?.addEventListener("click", async () => {
  const clinicId = clinicSelect?.value;
  if (!clinicId) {
    showMessage(queueMessage, "Select clinic first", true);
    return;
  }
  if (queueDate && !queueDate.value) {
    queueDate.value = getTaipeiDateString();
  }
  const date = queueDate?.value;
  if (!date) {
    showMessage(queueMessage, "Select date first", true);
    return;
  }

  const queueNos = parseQueueNumbersInput(queueReserved?.value || "");
  try {
    await fetchJson(`${apiBase}/admin/queue/reserved`, {
      method: "POST",
      body: JSON.stringify({
        clinic_id: clinicId,
        service_date_local: date,
        queue_nos: queueNos,
      }),
    });
    showMessage(queueMessage, "Reserved numbers updated");
    await refreshQueueDashboard();
  } catch (error) {
    showMessage(queueMessage, "Update reserved numbers failed", true);
  }
});
queueDetailRefresh?.addEventListener("click", async () => {
  if (state.selectedQueueAppointment) {
    await loadQueuePatientDetail(state.selectedQueueAppointment);
  } else {
    resetQueueDetail();
  }
});

queueNext?.addEventListener("click", async () => {
  if (!state.queueAppointments || state.queueAppointments.length === 0) {
    showMessage(queueMessage, "\u8acb\u5148\u8f09\u5165\u6e05\u55ae", true);
    return;
  }
  const next = getNextQueueAppointment();
  if (!next) {
    showMessage(queueMessage, "\u6c92\u6709\u53ef\u53eb\u865f\u7684\u9810\u7d04", true);
    return;
  }
  state.selectedQueueAppointment = next;
  await updateAppointmentStatus(next.id, "called");
});

queueQuickCall?.addEventListener("click", async () => {
  if (!state.queueAppointments || state.queueAppointments.length === 0) {
    showMessage(queueMessage, "Please load list first", true);
    return;
  }
  const targetNo = Number(queueCallInput?.value || "");
  if (!Number.isFinite(targetNo) || targetNo <= 0) {
    showMessage(queueMessage, "Enter queue number to call", true);
    return;
  }
  const target = state.queueAppointments.find((item) => Number(item.queue_no) === targetNo);
  if (!target) {
    showMessage(queueMessage, "Queue number not found", true);
    return;
  }
  state.selectedQueueAppointment = target;
  await updateAppointmentStatus(target.id, "called");
});


queueAutoRefresh?.addEventListener("change", () => {
  setQueueAutoRefresh(queueAutoRefresh.checked);
});
queueExport?.addEventListener("click", async () => {
  const clinicId = clinicSelect?.value;
  const providerId = providerSelect?.value;
  const date = queueDate?.value;
  if (!clinicId || !providerId || !date) {
    showMessage(queueMessage, "請先選擇院所與醫師並指定日期", true);
    return;
  }

  try {
    const params = new URLSearchParams({
      clinic_id: clinicId,
      provider_id: providerId,
      service_date_local: date,
    });
    const response = await fetch(`${apiBase}/admin/appointments/export?${params.toString()}`, {
      method: "GET",
    });
    if (!response.ok) {
      throw new Error("export_failed");
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `appointments_${date}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    showMessage(queueMessage, "匯出失敗", true);
  }
});

ruleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const providerId = providerSelect.value;
  if (!providerId) {
    showMessage(ruleMessage, "請先選擇醫師", true);
    return;
  }
  const payload = {
    provider_id: providerId,
    weekday: Number(ruleWeekday.value),
    start_time_local: ruleStart.value,
    end_time_local: ruleEnd.value,
    slot_minutes: Number(ruleSlot.value),
    capacity_per_slot: Number(ruleCapacity.value),
    effective_from: ruleFrom.value || undefined,
    effective_to: ruleTo.value || undefined,
  };

  try {
    if (ruleId.value) {
      await fetchJson(`${apiBase}/admin/schedule-rules/${ruleId.value}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      showMessage(ruleMessage, "已更新規則");
    } else {
      await fetchJson(`${apiBase}/admin/schedule-rules`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showMessage(ruleMessage, "已新增規則");
    }
    resetRuleForm();
    await loadRulesAndExceptions();
  } catch (error) {
    showMessage(ruleMessage, "新增失敗，請檢查欄位", true);
  }
});

exceptionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const providerId = providerSelect.value;
  if (!providerId) {
    showMessage(exceptionMessage, "請先選擇醫師", true);
    return;
  }

  const payload = {
    provider_id: providerId,
    service_date_local: exceptionDate.value,
    type: exceptionType.value,
    note: exceptionNote.value || undefined,
  };

  if (exceptionType.value === "override") {
    payload.override_start_time_local = exceptionStart.value;
    payload.override_end_time_local = exceptionEnd.value;
    payload.override_slot_minutes = Number(exceptionSlot.value);
    payload.override_capacity_per_slot = Number(exceptionCapacity.value);
  }

  try {
    if (exceptionId.value) {
      await fetchJson(`${apiBase}/admin/schedule-exceptions/${exceptionId.value}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      showMessage(exceptionMessage, "已更新例外");
    } else {
      await fetchJson(`${apiBase}/admin/schedule-exceptions`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showMessage(exceptionMessage, "已新增例外");
    }
    resetExceptionForm();
    await loadRulesAndExceptions();
  } catch (error) {
    showMessage(exceptionMessage, "新增失敗，請檢查欄位", true);
  }
});

generateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const providerId = providerSelect.value;
  if (!providerId) {
    showMessage(generateMessage, "請先選擇醫師", true);
    return;
  }

  try {
    const response = await fetchJson(`${apiBase}/admin/slots/generate`, {
      method: "POST",
      body: JSON.stringify({
        provider_id: providerId,
        from_date: generateFrom.value,
        to_date: generateTo.value || undefined,
        reset_existing: Boolean(generateReset?.checked),
        overwrite_empty: Boolean(generateOverwrite?.checked),
      }),
    });
    showMessage(generateMessage, `已產生 ${response.data.inserted} 筆時段`);
  } catch (error) {
    showMessage(generateMessage, "產生時段失敗", true);
  }
});

closeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const providerId = providerSelect.value;
  if (!providerId) {
    showMessage(closeMessage, "請先選擇醫師", true);
    return;
  }
  try {
    const response = await fetchJson(`${apiBase}/admin/slots/close`, {
      method: "POST",
      body: JSON.stringify({
        provider_id: providerId,
        service_date_local: closeDate.value,
        mode: closeMode.value,
        notify: Boolean(closeNotify.checked),
        reason: closeReason.value || undefined,
      }),
    });
    showMessage(
      closeMessage,
      `已關診 ${response.data.closed_slots}，並取消 ${response.data.cancelled_appointments}`
    );
  } catch (error) {
    showMessage(closeMessage, "關診失敗，請檢查欄位", true);
  }
});

ruleList.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "edit-rule") {
    ruleId.value = button.dataset.id;
    ruleWeekday.value = button.dataset.weekday;
    ruleStart.value = button.dataset.start;
    ruleEnd.value = button.dataset.end;
    ruleSlot.value = button.dataset.slot;
    ruleCapacity.value = button.dataset.capacity;
    ruleFrom.value = button.dataset.from;
    ruleTo.value = button.dataset.to;
    ruleSubmit.textContent = "更新規則";
    ruleCancelEdit.classList.remove("hidden");
    return;
  }
  if (action === "delete-rule") {
    try {
      await fetchJson(`${apiBase}/admin/schedule-rules/${button.dataset.id}`, { method: "DELETE" });
      showMessage(ruleMessage, "已刪除規則");
      await loadRulesAndExceptions();
    } catch (error) {
      showMessage(ruleMessage, "刪除失敗", true);
    }
  }
});

exceptionList.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "edit-exception") {
    exceptionId.value = button.dataset.id;
    exceptionDate.value = button.dataset.date;
    exceptionType.value = button.dataset.type;
    exceptionStart.value = button.dataset.start || "14:00";
    exceptionEnd.value = button.dataset.end || "17:00";
    exceptionSlot.value = button.dataset.slot || "10";
    exceptionCapacity.value = button.dataset.capacity || "4";
    exceptionNote.value = button.dataset.note || "";
    exceptionSubmit.textContent = "更新例外";
    exceptionCancelEdit.classList.remove("hidden");
    syncExceptionFields();
    return;
  }
  if (action === "delete-exception") {
    try {
      await fetchJson(`${apiBase}/admin/schedule-exceptions/${button.dataset.id}`, {
        method: "DELETE",
      });
      showMessage(exceptionMessage, "已刪除例外");
      await loadRulesAndExceptions();
    } catch (error) {
      showMessage(exceptionMessage, "刪除失敗", true);
    }
  }
});

ruleCancelEdit.addEventListener("click", () => {
  resetRuleForm();
});

exceptionCancelEdit.addEventListener("click", () => {
  resetExceptionForm();
  syncExceptionFields();
});

if (queueDate && !queueDate.value) {
  queueDate.value = getTaipeiDateString();
}

Promise.resolve()
  .then(loadAdminContext)
  .then(loadClinics)
  .then(loadClinicNotice)
  .then(loadProvidersAdmin)
  .then(loadProviders)
  .then(loadNotifications)
  .then(loadTemplates)
  .then(loadStaffUsers)
  .then(loadPatientAuth)
  .then(loadPatients)
  .then(loadFormDefinitions)
  .then(() => {

    if (queueAutoRefresh) {

      setQueueAutoRefresh(queueAutoRefresh.checked);

    }

  })

  .catch(() => {
    showMessage(generateMessage, "資料載入失敗", true);
  });

syncExceptionFields();



templateLocale?.addEventListener("change", async () => {
  try {
    await loadTemplates();
  } catch (error) {
    showMessage(templateMessage, "Load templates failed", true);
  }
});


reportRefresh?.addEventListener("click", async () => {
  try {
    await loadDailyReport();
  } catch (error) {
    if (reportMessage) reportMessage.textContent = "Load failed";
  }
});

csvExport?.addEventListener("click", async () => {
  try {
    await exportSlotsCsvAdmin();
  } catch (error) {
    if (csvMessage) csvMessage.textContent = "Export failed";
  }
});

csvImport?.addEventListener("click", async () => {
  try {
    await importSlotsCsvAdmin();
  } catch (error) {
    if (csvMessage) csvMessage.textContent = "Import failed";
  }
});

auditRefresh?.addEventListener("click", async () => {
  try {
    await loadAuditLogs();
  } catch (error) {
    if (auditMessage) auditMessage.textContent = "Load failed";
  }
});
