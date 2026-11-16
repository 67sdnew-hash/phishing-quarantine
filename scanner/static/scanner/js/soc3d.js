(() => {
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isTouchDevice = window.matchMedia("(pointer: coarse)").matches;

  // Mobile sidebar drawer toggle
  const menuBtn = document.getElementById("mobileMenuBtn");
  const sidebar = document.getElementById("appSidebar");
  const backdrop = document.getElementById("sidebarBackdrop");

  function setSidebarOpen(open) {
    if (!sidebar || !backdrop) return;
    sidebar.classList.toggle("open", open);
    backdrop.classList.toggle("open", open);
  }

  if (menuBtn && sidebar && backdrop) {
    menuBtn.addEventListener("click", () => {
      setSidebarOpen(!sidebar.classList.contains("open"));
    });
    backdrop.addEventListener("click", () => setSidebarOpen(false));
  }

  // Interactive 3D tilt + specular glare
  if (!prefersReducedMotion && !isTouchDevice) {
    const tiltTargets = document.querySelectorAll(".kpi-card, .preset-btn, [data-tilt]");
    tiltTargets.forEach((el) => {
      const maxTilt = parseFloat(el.dataset.tiltMax || "7");

      el.addEventListener("mousemove", (e) => {
        const rect = el.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const px = x / rect.width;
        const py = y / rect.height;

        const rotateY = (px - 0.5) * (maxTilt * 2);
        const rotateX = (0.5 - py) * (maxTilt * 2);

        el.style.setProperty("--mouse-x", `${(px * 100).toFixed(1)}%`);
        el.style.setProperty("--mouse-y", `${(py * 100).toFixed(1)}%`);
        el.style.transform = `perspective(900px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-4px) scale(1.012)`;
      });

      el.addEventListener("mouseleave", () => {
        el.style.transform = "";
      });
    });
  }

  // Smooth count-up animation for KPI metrics
  if (!prefersReducedMotion) {
    const counters = document.querySelectorAll(".kpi-value[data-count]");
    counters.forEach((el) => {
      const raw = el.dataset.count;
      const suffix = el.dataset.suffix || "";
      const target = parseFloat(raw);
      if (Number.isNaN(target)) return;

      const isFloat = raw.includes(".");
      const decimals = isFloat ? (raw.split(".")[1] || "").length : 0;
      const duration = 650;
      const start = performance.now();

      function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = target * eased;
        el.textContent = (isFloat ? current.toFixed(decimals) : Math.round(current)) + suffix;
        if (progress < 1) {
          requestAnimationFrame(tick);
        } else {
          el.textContent = raw + suffix;
        }
      }

      requestAnimationFrame(tick);
    });

    // Animate progress bars from 0 to target width
    const bars = document.querySelectorAll(".prob-fill, .risk-fill");
    bars.forEach((bar) => {
      const targetWidth = bar.style.width;
      if (!targetWidth) return;
      bar.style.width = "0%";
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          bar.style.width = targetWidth;
        });
      });
    });
  }

  // Animate 3D SVG gauge rings
  const gaugeRings = document.querySelectorAll(".gauge-ring-fill[data-gauge-pct]");
  gaugeRings.forEach((circle) => {
    const pct = Math.max(0, Math.min(100, parseFloat(circle.dataset.gaugePct || "0")));
    const circumference = 251.33;
    const offset = circumference - (pct / 100) * circumference;
    if (prefersReducedMotion) {
      circle.style.strokeDashoffset = String(offset);
    } else {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          circle.style.strokeDashoffset = String(offset);
        });
      });
    }
  });

  // Multi-Theme Engine (Obsidian Dark, Platinum Light, Matrix Cyberpunk, Cobalt Sentinel)
  const THEMES = {
    dark: { label: "Obsidian", icon: "🌙" },
    light: { label: "Platinum", icon: "☀️" },
    cyberpunk: { label: "Matrix", icon: "⚡" },
    midnight: { label: "Cobalt", icon: "🌊" }
  };

  const themeWrap = document.getElementById("themeDropdownWrap");
  const themeMenuBtn = document.getElementById("themeMenuBtn");
  const themeIconEl = document.getElementById("activeThemeIcon");
  const themeLabelEl = document.getElementById("activeThemeLabel");
  const themeItems = document.querySelectorAll("[data-theme-value]");

  function applyTheme(themeKey) {
    const meta = THEMES[themeKey] || THEMES.dark;
    const finalKey = THEMES[themeKey] ? themeKey : "dark";

    document.documentElement.setAttribute("data-theme", finalKey);
    try {
      localStorage.setItem("phishguard-theme", finalKey);
    } catch (_) {}

    if (themeIconEl) themeIconEl.textContent = meta.icon;
    if (themeLabelEl) themeLabelEl.textContent = meta.label;

    themeItems.forEach((btn) => {
      const isMatch = btn.getAttribute("data-theme-value") === finalKey;
      btn.classList.toggle("active", isMatch);
      btn.setAttribute("aria-selected", isMatch ? "true" : "false");
    });
  }

  // Initialize active theme
  const initialTheme = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(initialTheme);

  if (themeMenuBtn && themeWrap) {
    themeMenuBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const isOpen = themeWrap.classList.toggle("open");
      themeMenuBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });

    document.addEventListener("click", (e) => {
      if (!themeWrap.contains(e.target)) {
        themeWrap.classList.remove("open");
        themeMenuBtn.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && themeWrap.classList.contains("open")) {
        themeWrap.classList.remove("open");
        themeMenuBtn.setAttribute("aria-expanded", "false");
        themeMenuBtn.focus();
      }
    });
  }

  themeItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      const val = btn.getAttribute("data-theme-value");
      if (val) {
        applyTheme(val);
        if (themeWrap) themeWrap.classList.remove("open");
        if (themeMenuBtn) themeMenuBtn.setAttribute("aria-expanded", "false");
      }
    });
  });

  // "/" keyboard shortcut to focus search bar
  const searchInput = document.querySelector('.filter-bar input[name="q"]');
  if (searchInput) {
    document.addEventListener("keydown", (e) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
      const tag = (document.activeElement && document.activeElement.tagName) || "";
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    });
  }

  // 3D File Dropzone feedback
  document.querySelectorAll(".dropzone-3d").forEach((zone) => {
    const input = zone.querySelector('input[type="file"]');
    const labelEl = zone.querySelector(".dropzone-filename");
    if (!input) return;

    const updateName = () => {
      if (labelEl && input.files && input.files.length > 0) {
        labelEl.textContent = `Selected: ${input.files[0].name}`;
      }
    };

    input.addEventListener("change", updateName);
    zone.addEventListener("dragover", (e) => {
      e.preventDefault();
      zone.classList.add("dragover");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
    zone.addEventListener("drop", () => {
      zone.classList.remove("dragover");
      setTimeout(updateName, 0);
    });
  });

  // Dismissible flash alerts
  document.querySelectorAll(".flash-close").forEach((btn) => {
    btn.addEventListener("click", () => {
      const flash = btn.closest(".flash");
      if (flash) flash.remove();
    });
  });

  // Highlight diagonal cells in confusion matrix
  document.querySelectorAll("table[data-cm-table] tbody tr").forEach((row, rIdx) => {
    const cells = row.querySelectorAll("td[data-cm-cell]");
    if (cells[rIdx]) cells[rIdx].classList.add("cm-diag");
  });
})();
