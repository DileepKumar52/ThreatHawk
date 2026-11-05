/**
 * ThreatHawk Core Platform Scripts
 * Unified theming, accessible dropdowns, mobile navigation, accessible modals, and toast alerts.
 */

"use strict";

(function () {
    const THEME_KEY = "threathawk-theme";

    // --------------------------------------------------------------------------
    // 1. THEME ENGINE
    // --------------------------------------------------------------------------
    function getPreferredTheme() {
        try {
            const saved = localStorage.getItem(THEME_KEY);
            if (saved === "light" || saved === "dark") {
                return saved;
            }
        } catch (e) {
            console.warn("Storage access failed:", e);
        }
        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "dark"
            : "light";
    }

    function applyTheme(theme) {
        const isDark = theme === "dark";
        document.documentElement.setAttribute("data-theme", theme);
        document.documentElement.style.colorScheme = theme;
        document.body.classList.toggle("dark-mode", isDark);
        document.body.classList.toggle("light-mode", !isDark);

        // Update meta theme-color
        let metaTheme = document.querySelector('meta[name="theme-color"]');
        if (!metaTheme) {
            metaTheme = document.createElement("meta");
            metaTheme.name = "theme-color";
            document.head.appendChild(metaTheme);
        }
        metaTheme.setAttribute("content", isDark ? "#000000" : "#fafafa");

        // Update all theme toggle buttons
        document.querySelectorAll(".th-theme-btn, #themeToggle").forEach(btn => {
            btn.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
            btn.setAttribute("title", isDark ? "Switch to light theme" : "Switch to dark theme");
            const icon = btn.querySelector("i, svg");
            if (icon) {
                if (icon.tagName.toLowerCase() === "i") {
                    icon.className = isDark ? "fa-solid fa-sun" : "fa-solid fa-moon";
                }
            }
        });
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute("data-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        try {
            localStorage.setItem(THEME_KEY, next);
        } catch (e) {
            console.warn("Storage access failed:", e);
        }
        applyTheme(next);
    }

    // Apply immediately to prevent flash
    const initialTheme = getPreferredTheme();
    applyTheme(initialTheme);

    // Listen for system theme changes if user hasn't explicitly set preference
    if (window.matchMedia) {
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", e => {
            try {
                if (!localStorage.getItem(THEME_KEY)) {
                    applyTheme(e.matches ? "dark" : "light");
                }
            } catch (err) {}
        });
    }

    // --------------------------------------------------------------------------
    // 2. TOAST ENGINE
    // --------------------------------------------------------------------------
    let toastTimeout = null;

    function showToast(message, icon = "fa-check") {
        let toastEl = document.getElementById("toast");
        if (!toastEl) {
            toastEl = document.createElement("div");
            toastEl.id = "toast";
            toastEl.className = "th-toast";
            toastEl.setAttribute("role", "status");
            toastEl.setAttribute("aria-live", "polite");
            document.body.appendChild(toastEl);
        }

        toastEl.innerHTML = `<i class="fa-solid ${icon}" aria-hidden="true"></i> <span>${message}</span>`;
        toastEl.classList.add("active");

        clearTimeout(toastTimeout);
        toastTimeout = setTimeout(() => {
            toastEl.classList.remove("active");
        }, 2400);
    }

    async function copyToClipboard(text, successMessage = "Copied to clipboard") {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
            } else {
                const textArea = document.createElement("textarea");
                textArea.value = text;
                textArea.style.position = "fixed";
                textArea.style.left = "-9999px";
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand("copy");
                document.body.removeChild(textArea);
            }
            showToast(successMessage, "fa-check");
            return true;
        } catch (err) {
            console.error("Clipboard copy error:", err);
            showToast("Failed to copy", "fa-triangle-exclamation");
            return false;
        }
    }

    // --------------------------------------------------------------------------
    // 3. ACCESSIBLE MODALS / KNOWLEDGE POPUPS
    // --------------------------------------------------------------------------
    let previousActiveElement = null;

    function openModal(title, contentHtml) {
        let backdrop = document.getElementById("knowledgeOverlay");
        if (!backdrop) {
            backdrop = document.createElement("div");
            backdrop.id = "knowledgeOverlay";
            backdrop.className = "th-modal-backdrop";
            backdrop.setAttribute("role", "dialog");
            backdrop.setAttribute("aria-modal", "true");
            backdrop.setAttribute("aria-labelledby", "popupTitle");

            backdrop.innerHTML = `
                <div class="th-modal-card">
                    <div class="th-modal-header">
                        <h3 id="popupTitle" class="heading-md"></h3>
                        <button type="button" class="btn-icon-circular" id="popupClose" aria-label="Close dialog">
                            <i class="fa-solid fa-xmark" aria-hidden="true"></i>
                        </button>
                    </div>
                    <div id="popupContent" class="th-modal-body"></div>
                </div>
            `;
            document.body.appendChild(backdrop);

            backdrop.addEventListener("click", e => {
                if (e.target === backdrop) closeModal();
            });

            const closeBtn = backdrop.querySelector("#popupClose");
            if (closeBtn) closeBtn.addEventListener("click", closeModal);
        }

        const titleEl = backdrop.querySelector("#popupTitle");
        const bodyEl = backdrop.querySelector("#popupContent");
        if (titleEl) titleEl.innerHTML = title;
        if (bodyEl) bodyEl.innerHTML = contentHtml;

        previousActiveElement = document.activeElement;
        backdrop.classList.add("active");
        document.body.style.overflow = "hidden";

        const closeBtn = backdrop.querySelector("#popupClose");
        if (closeBtn) closeBtn.focus();
    }

    function closeModal() {
        const backdrop = document.getElementById("knowledgeOverlay");
        if (backdrop && backdrop.classList.contains("active")) {
            backdrop.classList.remove("active");
            document.body.style.overflow = "";
            if (previousActiveElement && typeof previousActiveElement.focus === "function") {
                previousActiveElement.focus();
            }
        }
    }

    // --------------------------------------------------------------------------
    // 4. DOM INITIALIZATION
    // --------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", () => {
        // Theme toggle button listeners
        document.querySelectorAll(".th-theme-btn, #themeToggle").forEach(btn => {
            btn.addEventListener("click", e => {
                e.preventDefault();
                toggleTheme();
            });
        });

        // Navigation Dropdown
        const dropdown = document.querySelector(".th-dropdown, .nav-dropdown");
        const dropdownToggle = document.querySelector(".th-dropdown-toggle, .dropdown-toggle");

        if (dropdown && dropdownToggle) {
            dropdownToggle.addEventListener("click", e => {
                e.stopPropagation();
                const isOpen = dropdown.classList.toggle("active");
                dropdownToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });

            document.addEventListener("click", e => {
                if (!dropdown.contains(e.target)) {
                    dropdown.classList.remove("active");
                    dropdownToggle.setAttribute("aria-expanded", "false");
                }
            });

            document.addEventListener("keydown", e => {
                if (e.key === "Escape") {
                    dropdown.classList.remove("active");
                    dropdownToggle.setAttribute("aria-expanded", "false");
                    closeModal();
                }
            });
        }

        // Mobile Drawer
        const mobileToggle = document.querySelector(".th-mobile-toggle");
        const mobileDrawer = document.querySelector(".th-mobile-drawer");
        if (mobileToggle && mobileDrawer) {
            mobileToggle.addEventListener("click", () => {
                const isOpen = mobileDrawer.classList.toggle("active");
                mobileToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });
        }

        // Generic Knowledge / Info Popups
        document.querySelectorAll(".info-button, [data-popup]").forEach(btn => {
            btn.addEventListener("click", () => {
                const popupKey = btn.dataset.popup;
                if (window.knowledgeData && window.knowledgeData[popupKey]) {
                    const data = window.knowledgeData[popupKey];
                    openModal(data.title, data.content);
                }
            });
        });
    });

    // Global ThreatHawk object
    window.ThreatHawk = {
        theme: {
            get: getPreferredTheme,
            apply: applyTheme,
            toggle: toggleTheme
        },
        toast: showToast,
        copyToClipboard: copyToClipboard,
        modal: {
            open: openModal,
            close: closeModal
        }
    };
})();

