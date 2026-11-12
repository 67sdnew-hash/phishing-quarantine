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
})();
