/**
 * ThreatHawk Guides Support Scripts
 * Ensures navigation dropdowns and core platform functionality work seamlessly across all guide pages.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    // If core.js is loaded, dropdown & theme are handled globally.
    // Fallback dropdown handler:
    const dropdown = document.querySelector(".nav-dropdown, .th-dropdown");
    const toggle = document.querySelector(".dropdown-toggle, .th-dropdown-toggle");

    if (dropdown && toggle && !dropdown.dataset.initialized) {
        dropdown.dataset.initialized = "true";
        toggle.addEventListener("click", e => {
            e.stopPropagation();
            const isOpen = dropdown.classList.toggle("active");
            toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
        });

        document.addEventListener("click", e => {
            if (!dropdown.contains(e.target)) {
                dropdown.classList.remove("active");
                toggle.setAttribute("aria-expanded", "false");
            }
        });
    }
});
