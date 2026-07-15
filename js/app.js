"use strict";

/* ==========================
   Smooth Scroll
========================== */

document.querySelectorAll('a[href^="#"]').forEach(link => {

    link.addEventListener("click", function (e) {

        const target = document.querySelector(this.getAttribute("href"));

        if (!target) return;

        e.preventDefault();

        target.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    });

});


/* ==========================
   Sticky Navbar
========================== */

const navbar = document.querySelector(".navbar");

window.addEventListener("scroll", () => {

    if (window.scrollY > 40) {

        navbar.style.boxShadow =
            "0 12px 30px rgba(0,0,0,.35)";

        navbar.style.borderBottom =
            "1px solid rgba(255,255,255,.08)";

    }

    else {

        navbar.style.boxShadow = "none";

        navbar.style.borderBottom =
            "1px solid rgba(255,255,255,.07)";
    }

});


/* ==========================
   Active Navigation
========================== */

const sections = document.querySelectorAll("section");

const navLinks = document.querySelectorAll("nav a");

window.addEventListener("scroll", () => {

    let current = "";

    sections.forEach(section => {

        const sectionTop = section.offsetTop - 120;

        if (pageYOffset >= sectionTop) {

            current = section.getAttribute("id");

        }

    });

    navLinks.forEach(link => {

        link.classList.remove("active");

        if (link.getAttribute("href") === "#" + current) {

            link.classList.add("active");

        }

    });

});


/* ==========================
   Reveal Animation
========================== */

const revealElements =
    document.querySelectorAll(

        ".module-card, .capability-card, .architecture-box, .current, .future, .about"

    );

const observer = new IntersectionObserver(

    entries => {

        entries.forEach(entry => {

            if (entry.isIntersecting) {

                entry.target.classList.add("visible");

            }

        });

    },

    {
        threshold: .18
    }

);

revealElements.forEach(element => {

    element.classList.add("reveal");

    observer.observe(element);

});


/* ==========================
   Architecture Hover
========================== */

const architectureModules =
    document.querySelectorAll(".architecture-row div");

architectureModules.forEach(module => {

    module.addEventListener("mouseenter", () => {

        architectureModules.forEach(item =>
            item.classList.remove("active")
        );

        module.classList.add("active");

    });

});


/* ==========================
   Hero Buttons Hover
========================== */

document.querySelectorAll(

    ".primary-btn, .secondary-btn"

).forEach(button => {

    button.addEventListener("mouseenter", () => {

        button.style.transform =
            "translateY(-3px)";

    });

    button.addEventListener("mouseleave", () => {

        button.style.transform =
            "translateY(0px)";

    });

});


/* ==========================
   Module Card Animation
========================== */

document.querySelectorAll(

    ".module-card"

).forEach(card => {

    card.addEventListener("mousemove", e => {

        const rect = card.getBoundingClientRect();

        const x = e.clientX - rect.left;

        const y = e.clientY - rect.top;

        card.style.background =
            `radial-gradient(circle at ${x}px ${y}px,
            rgba(0,212,255,.08),
            rgba(13,22,37,.95) 45%)`;

    });

    card.addEventListener("mouseleave", () => {

        card.style.background = "";

    });

});


/* ==========================
   Footer Year
========================== */

const footer = document.querySelector("footer");

const year = new Date().getFullYear();

footer.insertAdjacentHTML(

    "beforeend",

    `<p style="margin-top:20px;width:100%;text-align:center;color:#66758a;font-size:13px;">
        © ${year} ThreatHawk. All rights reserved.
    </p>`

);

/* Make each module card clickable */

document.querySelectorAll(".module-card[data-href]")
    .forEach(card => {
        function openModule() {
            const target = card.dataset.href;

            if (target) {
                window.location.href = target;
            }
        }

        card.addEventListener("click", event => {
            /*
             * Let the existing Launch Module link work normally.
             */
            if (event.target.closest("a")) {
                return;
            }

            openModule();
        });

        card.addEventListener("keydown", event => {
            if (
                event.key === "Enter" ||
                event.key === " "
            ) {
                event.preventDefault();
                openModule();
            }
        });
    });