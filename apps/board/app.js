const apiBase = document.body.dataset.apiBase || "/api/v1";
const useMock = document.body.dataset.mock === "true" || window.location.protocol === "file:";

const clinicSelect = document.getElementById("clinic-select");
const providerSelect = document.getElementById("provider-select");
const boardDate = document.getElementById("board-date");
const boardRefresh = document.getElementById("board-refresh");
const boardSummary = document.getElementById("board-summary");
const currentNumber = document.getElementById("current-number");
const nextNumber = document.getElementById("next-number");
const reservedList = document.getElementById("reserved-list");
const updatedAt = document.getElementById("updated-at");

const state = {
  clinics: [],
  providers: [],
  refreshTimer: null,
};

const mockData = {
  clinics: [
    { id: "cln_tp_main", name: "台北敦南院區 (總院)" },
    { id: "cln_tp_station", name: "台北站前院區" },
  ],
  providers: [
    { id: "prv_retina", clinic_id: "cln_tp_main", name: "王大明 醫師", title: "視網膜門診" },
    { id: "prv_glaucoma", clinic_id: "cln_tp_main", name: "林佳怡 醫師", title: "青光眼門診" },
  ],
};

function getTaipeiDateString() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Taipei",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

function formatTimestamp(ts) {
  if (!ts) return "--";
  return new Date(ts).toLocaleString("zh-TW", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

async function fetchJson(url) {
  if (!useMock) {
    const response = await fetch(url);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload?.error?.code || "request_failed");
    }
    return response.json();
  }

  const origin = window.location.origin && window.location.origin !== "null"
    ? window.location.origin
    : "http://mock.local";
  const requestUrl = new URL(url, origin);
  const path = requestUrl.pathname;

  if (path.endsWith("/public/clinics")) {
    return { data: mockData.clinics };
  }
  if (path.endsWith("/public/providers")) {
    const clinicId = requestUrl.searchParams.get("clinic_id");
    const providers = mockData.providers.filter((item) => item.clinic_id === clinicId);
    return { data: providers };
  }
  if (path.endsWith("/public/queue-status")) {
    const tick = Date.now();
    return {
      data: {
        current_queue_no: 12,
        next_queue_no: 13,
        reserved_queue_no: [4, 5],
        updated_at: tick,
      },
    };
  }

  throw new Error("not_found");
}

function renderClinics(clinics) {
  clinicSelect.innerHTML = "";
  clinics.forEach((clinic) => {
    const option = document.createElement("option");
    option.value = clinic.id;
    option.textContent = clinic.name;
    clinicSelect.appendChild(option);
  });
}

function renderProviders(providers) {
  providerSelect.innerHTML = "";
  if (!providers.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "尚無醫師";
    providerSelect.appendChild(option);
    return;
  }

  providers.forEach((provider) => {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = `${provider.name} ${provider.title ? `(${provider.title})` : ""}`.trim();
    providerSelect.appendChild(option);
  });
}

function renderStatus(status) {
  if (!status) return;
  currentNumber.textContent = status.current_queue_no ?? "--";
  nextNumber.textContent = status.next_queue_no ?? "--";
  reservedList.innerHTML = "";
  const reserved = status.reserved_queue_no || [];
  if (!reserved.length) {
    const pill = document.createElement("span");
    pill.className = "reserved-pill";
    pill.textContent = "無";
    reservedList.appendChild(pill);
  } else {
    reserved.forEach((queueNo) => {
      const pill = document.createElement("span");
      pill.className = "reserved-pill";
      pill.textContent = queueNo;
      reservedList.appendChild(pill);
    });
  }
  updatedAt.textContent = `更新時間：${formatTimestamp(status.updated_at)}`;
}

function updateSummary() {
  const clinic = state.clinics.find((item) => item.id === clinicSelect.value);
  const provider = state.providers.find((item) => item.id === providerSelect.value);
  if (!clinic || !provider) {
    boardSummary.textContent = "請選擇院所與醫師";
    return;
  }
  boardSummary.textContent = `${clinic.name}｜${provider.name}`;
}

async function loadProviders() {
  if (!clinicSelect.value) return;
  const response = await fetchJson(`${apiBase}/public/providers?clinic_id=${clinicSelect.value}`);
  state.providers = response.data || [];
  renderProviders(state.providers);
  updateSummary();
}

async function refreshStatus() {
  if (!providerSelect.value || !boardDate.value) return;
  const params = new URLSearchParams({
    provider_id: providerSelect.value,
    service_date_local: boardDate.value,
  });
  const response = await fetchJson(`${apiBase}/public/queue-status?${params.toString()}`);
  renderStatus(response.data);
}

async function init() {
  boardDate.value = getTaipeiDateString();
  const response = await fetchJson(`${apiBase}/public/clinics`);
  state.clinics = response.data || [];
  renderClinics(state.clinics);
  await loadProviders();
  updateSummary();
  await refreshStatus();
}

clinicSelect.addEventListener("change", async () => {
  await loadProviders();
  updateSummary();
  await refreshStatus();
});

providerSelect.addEventListener("change", async () => {
  updateSummary();
  await refreshStatus();
});

boardDate.addEventListener("change", refreshStatus);
boardRefresh.addEventListener("click", refreshStatus);

init().catch(() => {
  boardSummary.textContent = "資料載入失敗，請稍後再試";
});

state.refreshTimer = window.setInterval(() => {
  refreshStatus().catch(() => {});
}, 8000);
