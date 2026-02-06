PRAGMA foreign_keys = ON;

-- ===== Tenant =====
CREATE TABLE org (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE clinic (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  name TEXT NOT NULL,
  timezone TEXT NOT NULL DEFAULT 'Asia/Taipei',
  phone TEXT,
  address TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_clinic_org ON clinic(org_id);

-- ===== Staff / RBAC =====
CREATE TABLE staff_user (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  clinic_id TEXT REFERENCES clinic(id),
  cf_subject TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(cf_subject)
);

CREATE TABLE role (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  name TEXT NOT NULL
);

CREATE TABLE staff_user_role (
  staff_user_id TEXT NOT NULL REFERENCES staff_user(id),
  role_id TEXT NOT NULL REFERENCES role(id),
  PRIMARY KEY (staff_user_id, role_id)
);

-- ===== Patient (org-shared) =====
CREATE TABLE patient (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  display_name TEXT,
  gender TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
);
CREATE INDEX idx_patient_org ON patient(org_id);

CREATE TABLE patient_identity (
  patient_id TEXT PRIMARY KEY REFERENCES patient(id),
  national_id TEXT NOT NULL,
  dob TEXT NOT NULL,
  verified_level INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(national_id)
);

CREATE TABLE patient_contact (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  patient_id TEXT NOT NULL REFERENCES patient(id),
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  is_primary INTEGER NOT NULL DEFAULT 0,
  is_verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE(org_id, type, value)
);
CREATE INDEX idx_patient_contact_patient ON patient_contact(patient_id);

CREATE TABLE patient_auth (
  id TEXT PRIMARY KEY,
  patient_id TEXT NOT NULL REFERENCES patient(id),
  provider TEXT NOT NULL,
  provider_sub TEXT NOT NULL,
  bound_status TEXT NOT NULL DEFAULT 'pending_review',
  created_at INTEGER NOT NULL,
  UNIQUE(provider, provider_sub)
);

CREATE TABLE patient_session (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  patient_id TEXT NOT NULL REFERENCES patient(id),
  provider TEXT NOT NULL,
  provider_sub TEXT NOT NULL,
  bound_status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE(token_hash)
);
CREATE INDEX idx_patient_session_patient ON patient_session(patient_id, expires_at);

CREATE TABLE email_verification (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_email_verification_email_purpose ON email_verification(email, purpose, created_at);

CREATE TABLE patient_restriction (
  patient_id TEXT PRIMARY KEY REFERENCES patient(id),
  no_show_count_recent INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  lock_reason TEXT,
  updated_at INTEGER NOT NULL
);

-- ===== Provider / Schedule / Slot =====
CREATE TABLE provider (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  clinic_id TEXT NOT NULL REFERENCES clinic(id),
  name TEXT NOT NULL,
  title TEXT,
  specialty TEXT,
  bio TEXT,
  photo_url TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_provider_clinic ON provider(clinic_id);

CREATE TABLE schedule_rule (
  id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES provider(id),
  weekday INTEGER NOT NULL,
  start_time_local TEXT NOT NULL,
  end_time_local TEXT NOT NULL,
  slot_minutes INTEGER NOT NULL,
  capacity_per_slot INTEGER NOT NULL,
  effective_from TEXT,
  effective_to TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_schedule_rule_provider ON schedule_rule(provider_id);

CREATE TABLE schedule_exception (
  id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES provider(id),
  service_date_local TEXT NOT NULL,
  type TEXT NOT NULL,
  override_start_time_local TEXT,
  override_end_time_local TEXT,
  override_slot_minutes INTEGER,
  override_capacity_per_slot INTEGER,
  note TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_schedule_exc_provider_date ON schedule_exception(provider_id, service_date_local);

CREATE TABLE slot (
  id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES provider(id),
  clinic_id TEXT NOT NULL REFERENCES clinic(id),
  service_date_local TEXT NOT NULL,
  start_at_utc INTEGER NOT NULL,
  end_at_utc INTEGER NOT NULL,
  capacity INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL,
  UNIQUE(provider_id, start_at_utc)
);
CREATE INDEX idx_slot_provider_date ON slot(provider_id, service_date_local);
CREATE INDEX idx_slot_clinic_date ON slot(clinic_id, service_date_local);

CREATE TABLE slot_inventory (
  slot_id TEXT PRIMARY KEY REFERENCES slot(id),
  capacity INTEGER NOT NULL,
  booked_count INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL DEFAULT 0,
  CHECK(booked_count <= capacity)
);

-- ===== Queue counter =====
CREATE TABLE queue_counter (
  provider_id TEXT NOT NULL REFERENCES provider(id),
  service_date_local TEXT NOT NULL,
  next_queue_no INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (provider_id, service_date_local)
);

-- ===== Reserved queue numbers =====
CREATE TABLE queue_reserved (
  id TEXT PRIMARY KEY,
  clinic_id TEXT NOT NULL REFERENCES clinic(id),
  service_date_local TEXT NOT NULL,
  queue_no INTEGER NOT NULL,
  note TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(clinic_id, service_date_local, queue_no)
);
CREATE INDEX idx_queue_reserved_clinic_date ON queue_reserved(clinic_id, service_date_local);

-- ===== Booking / Hold =====
CREATE TABLE appointment (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  clinic_id TEXT NOT NULL REFERENCES clinic(id),
  provider_id TEXT NOT NULL REFERENCES provider(id),
  slot_id TEXT NOT NULL REFERENCES slot(id),
  patient_id TEXT NOT NULL REFERENCES patient(id),
  service_date_local TEXT NOT NULL,
  queue_no INTEGER NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  booking_ref TEXT NOT NULL,
  note_internal TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  cancelled_at INTEGER,
  deleted_at INTEGER,
  UNIQUE(provider_id, service_date_local, queue_no)
);
CREATE INDEX idx_appt_provider_date ON appointment(provider_id, service_date_local);
CREATE INDEX idx_appt_status_updated ON appointment(status, updated_at);
CREATE INDEX idx_appt_patient_created ON appointment(patient_id, created_at);
CREATE INDEX idx_appt_patient_service_date ON appointment(patient_id, service_date_local, id);
CREATE INDEX idx_appt_slot ON appointment(slot_id);

CREATE TABLE appointment_status_history (
  id TEXT PRIMARY KEY,
  appointment_id TEXT NOT NULL REFERENCES appointment(id),
  from_status TEXT,
  to_status TEXT NOT NULL,
  changed_by_type TEXT NOT NULL,
  changed_by_id TEXT,
  changed_at INTEGER NOT NULL,
  meta TEXT
);
CREATE INDEX idx_appt_hist_appt ON appointment_status_history(appointment_id, changed_at);

CREATE TABLE appointment_hold (
  id TEXT PRIMARY KEY,
  slot_id TEXT NOT NULL REFERENCES slot(id),
  clinic_id TEXT NOT NULL REFERENCES clinic(id),
  provider_id TEXT NOT NULL REFERENCES provider(id),
  patient_provisional_key TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_hold_slot_exp ON appointment_hold(slot_id, expires_at);

CREATE TABLE appointment_checkin_token (
  id TEXT PRIMARY KEY,
  appointment_id TEXT NOT NULL REFERENCES appointment(id),
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX idx_checkin_appt ON appointment_checkin_token(appointment_id, expires_at);
CREATE INDEX idx_checkin_token_hash ON appointment_checkin_token(token_hash);

-- ===== Forms =====
CREATE TABLE form_definition (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  version INTEGER NOT NULL,
  schema_json TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(type, version)
);

CREATE TABLE form_submission (
  id TEXT PRIMARY KEY,
  patient_id TEXT NOT NULL REFERENCES patient(id),
  appointment_id TEXT REFERENCES appointment(id),
  form_definition_id TEXT NOT NULL REFERENCES form_definition(id),
  data_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_form_sub_patient ON form_submission(patient_id, updated_at);

-- ===== Notifications =====
CREATE TABLE message_template (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  clinic_id TEXT REFERENCES clinic(id),
  channel TEXT NOT NULL,
  name TEXT NOT NULL,
  subject TEXT,
  body TEXT NOT NULL,
  locale TEXT NOT NULL DEFAULT 'zh-TW',
  version INTEGER NOT NULL DEFAULT 1,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_template_lookup ON message_template(org_id, name, channel, locale, version);

CREATE TABLE notification_job (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  channel TEXT NOT NULL,
  patient_id TEXT NOT NULL REFERENCES patient(id),
  appointment_id TEXT REFERENCES appointment(id),
  template_id TEXT REFERENCES message_template(id),
  payload_json TEXT NOT NULL,
  scheduled_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_notify_sched ON notification_job(status, scheduled_at);

CREATE TABLE notification_delivery (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES notification_job(id),
  provider_message_id TEXT,
  attempt INTEGER NOT NULL DEFAULT 1,
  sent_at INTEGER,
  status TEXT NOT NULL,
  error TEXT
);

-- ===== Clinic notice =====
CREATE TABLE clinic_notice (
  clinic_id TEXT PRIMARY KEY REFERENCES clinic(id),
  content TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- ===== Audit =====
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES org(id),
  clinic_id TEXT REFERENCES clinic(id),
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  entity_table TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  before_json TEXT,
  after_json TEXT,
  request_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_audit_entity ON audit_log(entity_table, entity_id, created_at);

-- ===== Idempotency =====
CREATE TABLE idempotency_key (
  key TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  response_json TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_idempotency_scope ON idempotency_key(scope);

-- ===== Rate limit =====
CREATE TABLE rate_limit (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);
