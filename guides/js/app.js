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

        // 2. DROPDOWN NAVIGATION (Respects core.js if already initialized)
        const dropdown = document.querySelector(".nav-dropdown, .th-dropdown");
        const toggle = document.querySelector(".dropdown-toggle, .th-dropdown-toggle");
        const menu = dropdown ? dropdown.querySelector(".dropdown-menu, .th-dropdown-menu") : null;

        if (dropdown && toggle && !dropdown.dataset.thDropdownInitialized && !dropdown.dataset.initialized) {
            dropdown.dataset.thDropdownInitialized = "true";
            dropdown.dataset.initialized = "true";

            function openDropdown() {
                dropdown.classList.add("active");
                toggle.setAttribute("aria-expanded", "true");
            }

            function closeDropdown() {
                dropdown.classList.remove("active");
                toggle.setAttribute("aria-expanded", "false");
            }

            toggle.addEventListener("click", e => {
                e.preventDefault();
                e.stopPropagation();
                if (dropdown.classList.contains("active")) {
                    closeDropdown();
                } else {
                    openDropdown();
                }
            });

            // Keyboard navigation on toggle
            toggle.addEventListener("keydown", e => {
                if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
                    if (!dropdown.classList.contains("active")) {
                        e.preventDefault();
                        openDropdown();
                        const firstLink = menu ? menu.querySelector("a") : null;
                        if (firstLink) firstLink.focus();
                    }
                } else if (e.key === "ArrowUp") {
                    if (!dropdown.classList.contains("active")) {
                        e.preventDefault();
                        openDropdown();
                        const links = menu ? menu.querySelectorAll("a") : [];
                        if (links.length) links[links.length - 1].focus();
                    }
                }
            });

            // Keyboard navigation in menu
            if (menu) {
                const getLinks = () => Array.from(menu.querySelectorAll("a"));
                menu.addEventListener("keydown", e => {
                    const links = getLinks();
                    if (!links.length) return;
                    const currentIndex = links.indexOf(document.activeElement);

                    if (e.key === "ArrowDown") {
                        e.preventDefault();
                        const nextIndex = currentIndex >= 0 ? (currentIndex + 1) % links.length : 0;
                        links[nextIndex].focus();
                    } else if (e.key === "ArrowUp") {
                        e.preventDefault();
                        const prevIndex = currentIndex > 0 ? currentIndex - 1 : links.length - 1;
                        links[prevIndex].focus();
                    } else if (e.key === "Escape") {
                        e.preventDefault();
                        closeDropdown();
                        toggle.focus();
                    }
                });

                menu.querySelectorAll("a").forEach(link => {
                    link.addEventListener("click", () => {
                        closeDropdown();
                    });
                });
            }

            document.addEventListener("click", e => {
                if (!dropdown.contains(e.target)) {
                    closeDropdown();
                }
            });

            document.addEventListener("keydown", e => {
                if (e.key === "Escape" && dropdown.classList.contains("active")) {
                    closeDropdown();
                    toggle.focus();
                }
            });
        }

        // Mobile drawer support for guides
        const mobileToggle = document.querySelector(".th-mobile-toggle");
        const mobileDrawer = document.querySelector(".th-mobile-drawer");
        if (mobileToggle && mobileDrawer && !mobileToggle.dataset.thDrawerInitialized) {
            mobileToggle.dataset.thDrawerInitialized = "true";
            mobileToggle.addEventListener("click", e => {
                e.stopPropagation();
                const isOpen = mobileDrawer.classList.toggle("active");
                mobileToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });

            document.addEventListener("click", e => {
                if (!mobileDrawer.contains(e.target) && !mobileToggle.contains(e.target)) {
                    mobileDrawer.classList.remove("active");
                    mobileToggle.setAttribute("aria-expanded", "false");
                }
            });

            document.addEventListener("keydown", e => {
                if (e.key === "Escape" && mobileDrawer.classList.contains("active")) {
                    mobileDrawer.classList.remove("active");
                    mobileToggle.setAttribute("aria-expanded", "false");
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
