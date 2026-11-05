/**
 * ThreatHawk Guides Support Scripts
 * Unified theming, dropdown navigation, and reading progress / TOC highlighting.
 */

"use strict";

(function () {
    const THEME_KEY = "threathawk-theme";

    // 1. THEME INITIALIZATION
    function getStoredTheme() {
        try {
            const saved = localStorage.getItem(THEME_KEY);
            if (saved === "light" || saved === "dark") return saved;
        } catch (e) {}
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

        let metaTheme = document.querySelector('meta[name="theme-color"]');
        if (!metaTheme) {
            metaTheme = document.createElement("meta");
            metaTheme.name = "theme-color";
            document.head.appendChild(metaTheme);
        }
        metaTheme.setAttribute("content", isDark ? "#000000" : "#fafafa");

        document.querySelectorAll(".th-theme-btn, #themeToggle").forEach(btn => {
            btn.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
            btn.setAttribute("title", isDark ? "Switch to light theme" : "Switch to dark theme");
            const icon = btn.querySelector("i, svg");
            if (icon && icon.tagName.toLowerCase() === "i") {
                icon.className = isDark ? "fa-solid fa-sun" : "fa-solid fa-moon";
            }
        });
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute("data-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        try {
            localStorage.setItem(THEME_KEY, next);
        } catch (e) {}
        applyTheme(next);
    }

    // Apply immediately to prevent flash
    applyTheme(getStoredTheme());

    document.addEventListener("DOMContentLoaded", () => {
        // Theme toggle listener
        document.querySelectorAll(".th-theme-btn, #themeToggle").forEach(btn => {
            btn.addEventListener("click", e => {
                e.preventDefault();
                toggleTheme();
            });
        });

        // 2. DROPDOWN NAVIGATION
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

            document.addEventListener("keydown", e => {
                if (e.key === "Escape") {
                    dropdown.classList.remove("active");
                    toggle.setAttribute("aria-expanded", "false");
                }
            });
        }

        // 3. TABLE OF CONTENTS ACTIVE HIGHLIGHTING (Observer)
        const tocLinks = document.querySelectorAll(".toc-card nav a");
        if (tocLinks.length > 0) {
            const sections = [];
            tocLinks.forEach(link => {
                const targetId = link.getAttribute("href")?.replace(/^#/, "");
                if (targetId) {
                    const el = document.getElementById(targetId);
                    if (el) sections.push({ link, el });
                }
            });

            if (sections.length > 0 && "IntersectionObserver" in window) {
                const observer = new IntersectionObserver(
                    entries => {
                        entries.forEach(entry => {
                            if (entry.isIntersecting) {
                                tocLinks.forEach(l => l.classList.remove("active"));
                                const match = sections.find(s => s.el === entry.target);
                                if (match) match.link.classList.add("active");
                            }
                        });
                    },
                    { rootMargin: "-80px 0px -60% 0px", threshold: 0 }
                );

                sections.forEach(s => observer.observe(s.el));
            }
        }
    });
})();
