document.addEventListener("DOMContentLoaded", () => {
    const dropdown = document.querySelector(".nav-dropdown");
    const toggle = document.querySelector(".dropdown-toggle");
    const menu = document.querySelector(".dropdown-menu");

    if (!dropdown || !toggle || !menu) {
        return;
    }

    const closeDropdown = () => {
        dropdown.classList.remove("active");
        toggle.setAttribute("aria-expanded", "false");
    };

    const openDropdown = () => {
        dropdown.classList.add("active");
        toggle.setAttribute("aria-expanded", "true");
    };

    toggle.addEventListener("click", (event) => {
        event.stopPropagation();

        const isOpen = dropdown.classList.contains("active");

        if (isOpen) {
            closeDropdown();
        } else {
            openDropdown();
        }
    });

    menu.addEventListener("click", (event) => {
        event.stopPropagation();
    });

    document.addEventListener("click", (event) => {
        if (!dropdown.contains(event.target)) {
            closeDropdown();
        }
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeDropdown();
            toggle.focus();
        }
    });

    window.addEventListener("resize", () => {
        closeDropdown();
    });
});