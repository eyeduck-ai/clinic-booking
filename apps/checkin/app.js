const apiBase = document.body.dataset.apiBase || "/api/v1";
const form = document.getElementById("checkin-form");
const tokenInput = document.getElementById("checkin-token");
const submitButton = document.getElementById("checkin-submit");
const message = document.getElementById("checkin-message");
const detail = document.getElementById("checkin-detail");

function setMessage(text, isError = false) {
  if (!message) return;
  message.textContent = text;
  message.className = `message ${isError ? "error" : "success"}`.trim();
}

function setDetail(text) {
  if (!detail) return;
  detail.textContent = text || "";
}

async function submitCheckin(token) {
  if (!token) {
    setMessage("請輸入報到碼", true);
    return;
  }
  try {
    if (submitButton) submitButton.disabled = true;
    setMessage("");
    setDetail("");
    const response = await fetch(`${apiBase}/public/checkin`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const code = data?.error?.code || "checkin_failed";
      setMessage(`報到失敗：${code}`, true);
      return;
    }
    const status = data?.data?.status || "checked_in";
    const appointmentId = data?.data?.appointment_id || "";
    setMessage("報到完成", false);
    if (appointmentId) {
      setDetail(`Appointment: ${appointmentId} · Status: ${status}`);
    } else {
      setDetail(`Status: ${status}`);
    }
  } catch (error) {
    setMessage("報到失敗，請稍後再試", true);
  } finally {
    if (submitButton) submitButton.disabled = false;
  }
}

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  submitCheckin(tokenInput?.value?.trim());
});

const params = new URLSearchParams(window.location.search);
const tokenFromUrl = params.get("token");
if (tokenFromUrl && tokenInput) {
  tokenInput.value = tokenFromUrl;
  submitCheckin(tokenFromUrl);
}
