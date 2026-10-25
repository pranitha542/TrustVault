"use strict";

function csrfToken() {
    const cookie = document.cookie
        .split("; ")
        .find((item) => item.startsWith("trustvault_csrf="));
    return cookie ? decodeURIComponent(cookie.split("=").slice(1).join("=")) : "";
}

function showFeedback(message, kind = "success") {
    const feedback = document.querySelector("#feedback");
    if (!feedback) return;
    feedback.textContent = message;
    feedback.className = `alert alert-${kind}`;
    feedback.focus();
}

function reloadWithNotice(message) {
    window.sessionStorage.setItem("trustvault-notice", message);
    window.location.reload();
}

async function responseMessage(response) {
    try {
        const body = await response.json();
        if (typeof body.detail === "string") return body.detail;
    } catch {
        // Use the generic fallback for responses without a JSON body.
    }
    return "The request could not be completed. Please try again.";
}

async function sendRequest(url, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("X-CSRF-Token", csrfToken());
    return fetch(url, { ...options, headers, credentials: "same-origin" });
}

const loginForm = document.querySelector("#login-form");
const savedNotice = window.sessionStorage.getItem("trustvault-notice");
if (savedNotice) {
    window.sessionStorage.removeItem("trustvault-notice");
    showFeedback(savedNotice);
}

if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = new FormData(loginForm);
        try {
            const response = await fetch("/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "same-origin",
                body: JSON.stringify({
                    username_or_email: form.get("username_or_email"),
                    password: form.get("password"),
                }),
            });
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            window.location.assign("/dashboard");
        } catch {
            showFeedback("Unable to connect. Please try again.", "danger");
        }
    });
}

document.querySelectorAll("[data-logout]").forEach((button) => {
    button.addEventListener("click", async () => {
        try {
            const response = await sendRequest("/auth/logout", { method: "POST" });
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            window.location.assign("/login");
        } catch {
            showFeedback("Unable to log out. Please try again.", "danger");
        }
    });
});

document.querySelectorAll("[data-edit-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
        document
            .querySelector(`[data-edit-form="${CSS.escape(button.dataset.editToggle)}"]`)
            ?.classList.toggle("d-none");
    });
});

document.querySelectorAll("[data-share-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
        document
            .querySelector(`[data-share-panel="${CSS.escape(button.dataset.shareToggle)}"]`)
            ?.classList.toggle("d-none");
    });
});

document.querySelectorAll("[data-edit-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const values = new FormData(form);
        const payload = Object.fromEntries(values.entries());
        try {
            const response = await sendRequest(`/documents/${form.dataset.editForm}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            reloadWithNotice("Document details updated.");
        } catch {
            showFeedback("Unable to update document details.", "danger");
        }
    });
});

document.querySelectorAll("[data-delete-id]").forEach((button) => {
    button.addEventListener("click", async () => {
        if (!window.confirm("Move this document out of your active documents?")) return;
        try {
            const response = await sendRequest(`/documents/${button.dataset.deleteId}`, {
                method: "DELETE",
            });
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            reloadWithNotice("Document moved out of your active documents.");
        } catch {
            showFeedback("Unable to delete the document.", "danger");
        }
    });
});

document.querySelectorAll("[data-share-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const values = new FormData(form);
        try {
            const response = await sendRequest(
                `/documents/${form.dataset.shareForm}/permissions`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(Object.fromEntries(values.entries())),
                },
            );
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            reloadWithNotice("Document shared successfully.");
        } catch {
            showFeedback("Unable to share the document.", "danger");
        }
    });
});

document.querySelectorAll("[data-revoke-url]").forEach((button) => {
    button.addEventListener("click", async () => {
        if (!window.confirm("Revoke this user's access?")) return;
        try {
            const response = await sendRequest(button.dataset.revokeUrl, {
                method: "DELETE",
            });
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            reloadWithNotice("Access revoked.");
        } catch {
            showFeedback("Unable to revoke access.", "danger");
        }
    });
});

const uploadForm = document.querySelector("#upload-form");
if (uploadForm) {
    uploadForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const response = await sendRequest("/documents", {
                method: "POST",
                body: new FormData(uploadForm),
            });
            if (!response.ok) {
                showFeedback(await responseMessage(response), "danger");
                return;
            }
            reloadWithNotice("Document uploaded successfully.");
        } catch {
            showFeedback("Unable to upload the document.", "danger");
        }
    });
}
