/**
 * dashboard.js — CyberSentinel Interactive Controller
 * =====================================================
 * Handles SPA navigation, Chart.js visualizations, API fetches,
 * table pagination, and client/server filtering across all 5 pages.
 */

document.addEventListener("DOMContentLoaded", () => {
  // ─── Global State & Chart Cache ───────────────────────────────────────────
  const charts = {};
  const state = {
    activePage: "page-overview",
    incidents: { page: 1, perPage: 15, totalPages: 1, search: "", threat: "all", severity: "all" },
    vulns: { page: 1, perPage: 15, totalPages: 1, search: "", severity: "all", exploited: "all" },
    sectorsData: [],
  };

  // ─── Chart.js Global Dark Theme Styling ────────────────────────────────────
  if (typeof Chart !== "undefined") {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    Chart.defaults.font.size = 12;
    Chart.defaults.plugins.tooltip.backgroundColor = "rgba(13, 21, 39, 0.95)";
    Chart.defaults.plugins.tooltip.borderColor = "#1e2f54";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.titleColor = "#00d2ff";
    Chart.defaults.plugins.tooltip.bodyColor = "#f8fafc";
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 6;
  }

  // ─── Navigation & Page Switching ──────────────────────────────────────────
  const navItems = document.querySelectorAll(".nav-item");
  const pageViews = document.querySelectorAll(".page-view");
  const pageTitle = document.getElementById("current-page-title");
  const pageSubtitle = document.getElementById("current-page-subtitle");

  const pageMeta = {
    "page-overview": {
      title: "National Cyber Threat Overview",
      subtitle: "Executive Risk Metrics & Historical Intelligence (2021–2024)",
    },
    "page-sectors": {
      title: "Critical Infrastructure Analysis",
      subtitle: "Sector-wise Risk Rankings & Contributing Quantitative Factors",
    },
    "page-threats": {
      title: "Threat Vector Intelligence",
      subtitle: "Attack Vector Distributions, Trend Trajectories & Incident Logs",
    },
    "page-vulnerabilities": {
      title: "Vulnerability Intelligence & Exploitation Feed",
      subtitle: "NIST NVD CVE Standards & CISA Known Exploited Vulnerabilities (KEV)",
    },
    "page-risk-analysis": {
      title: "Quantitative Risk Model & Architecture",
      subtitle: "Mathematical Formulation, Severity vs. Frequency & Model Governance",
    },
  };

  function switchPage(targetPageId) {
    state.activePage = targetPageId;

    navItems.forEach((item) => {
      if (item.dataset.page === targetPageId) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    pageViews.forEach((view) => {
      if (view.id === targetPageId) {
        view.classList.add("active");
      } else {
        view.classList.remove("active");
      }
    });

    if (pageMeta[targetPageId]) {
      pageTitle.textContent = pageMeta[targetPageId].title;
      pageSubtitle.textContent = pageMeta[targetPageId].subtitle;
    }

    // Trigger page-specific data load
    loadPageData(targetPageId);
  }

  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      switchPage(item.dataset.page);
    });
  });

  // ─── Helper Functions ──────────────────────────────────────────────────────
  function destroyChart(key) {
    if (charts[key]) {
      charts[key].destroy();
      delete charts[key];
    }
  }

  function getSeverityBadge(sev) {
    const s = String(sev || "Unknown").toLowerCase();
    if (s === "critical") return `<span class="badge badge-critical">Critical</span>`;
    if (s === "high") return `<span class="badge badge-high">High</span>`;
    if (s === "medium") return `<span class="badge badge-medium">Medium</span>`;
    if (s === "low") return `<span class="badge badge-low">Low</span>`;
    return `<span class="badge badge-public">${sev}</span>`;
  }

  function getRiskCategoryBadge(cat) {
    const c = String(cat || "").toLowerCase();
    if (c.includes("critical")) return `<span class="badge badge-critical">Critical Risk</span>`;
    if (c.includes("high")) return `<span class="badge badge-high">High Risk</span>`;
    if (c.includes("moderate")) return `<span class="badge badge-medium">Moderate Risk</span>`;
    return `<span class="badge badge-low">Low Risk</span>`;
  }

  // ─── PAGE 1: NATIONAL OVERVIEW ─────────────────────────────────────────────
  async function loadOverview() {
    try {
      const res = await fetch("/api/overview");
      const data = await res.json();
      if (data.status !== "success") return;

      // KPIs
      document.getElementById("kpi-ncri-val").textContent = data.ncri.score.toFixed(2);
      document.getElementById("kpi-ncri-badge").textContent = data.ncri.label;
      document.getElementById("kpi-ncri-period").textContent = data.ncri.period;
      document.getElementById("kpi-total-incidents").textContent = Number(data.ncri.total_incidents).toLocaleString();
      document.getElementById("kpi-total-cves").textContent = Number(data.vuln_metrics.total_cves).toLocaleString();
      document.getElementById("kpi-crit-vulns").textContent = `${Number(data.vuln_metrics.critical_count).toLocaleString()} Critical`;
      document.getElementById("kpi-high-vulns").textContent = `${Number(data.vuln_metrics.high_count).toLocaleString()} High`;
      document.getElementById("kpi-kev-exploited").textContent = Number(data.vuln_metrics.kev_exploited_count).toLocaleString();

      // Key Findings
      const findingsList = document.getElementById("overview-findings-list");
      findingsList.innerHTML = data.findings.map((f) => `<li>${f}</li>`).join("");

      // Chart 1: Monthly Incident Trends
      destroyChart("monthlyTrends");
      const trendLabels = data.monthly_trends.map((t) => t.month_label);
      const trendCounts = data.monthly_trends.map((t) => t.incident_count);

      const ctxTrend = document.getElementById("chart-monthly-trends").getContext("2d");
      const gradient = ctxTrend.createLinearGradient(0, 0, 0, 260);
      gradient.addColorStop(0, "rgba(0, 210, 255, 0.35)");
      gradient.addColorStop(1, "rgba(0, 210, 255, 0.0)");

      charts.monthlyTrends = new Chart(ctxTrend, {
        type: "line",
        data: {
          labels: trendLabels,
          datasets: [
            {
              label: "Recorded Incidents",
              data: trendCounts,
              borderColor: "#00d2ff",
              borderWidth: 2,
              backgroundColor: gradient,
              fill: true,
              tension: 0.35,
              pointBackgroundColor: "#00d2ff",
              pointRadius: 2,
              pointHoverRadius: 5,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "rgba(30, 47, 84, 0.4)" }, ticks: { maxTicksLimit: 12 } },
            y: { grid: { color: "rgba(30, 47, 84, 0.4)" }, beginAtZero: true },
          },
        },
      });

      // Chart 2: Threat Distribution
      destroyChart("threatDist");
      const threatLabels = data.threat_distribution.map((t) => t.threat_type);
      const threatCounts = data.threat_distribution.map((t) => t.incident_count);

      const ctxThreat = document.getElementById("chart-threat-distribution").getContext("2d");
      charts.threatDist = new Chart(ctxThreat, {
        type: "doughnut",
        data: {
          labels: threatLabels,
          datasets: [
            {
              data: threatCounts,
              backgroundColor: ["#38bdf8", "#3b82f6", "#ef4444", "#f97316", "#a855f7"],
              borderColor: "#111d35",
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "right", labels: { boxWidth: 12, padding: 12 } },
          },
          cutout: "68%",
        },
      });

      // Chart 3: Sector Overview Bar Chart
      destroyChart("sectorOverview");
      const sortedSectors = [...data.sector_overview].sort((a, b) => b.acrs_score - a.acrs_score);
      const sLabels = sortedSectors.map((s) => s.sector_name);
      const sScores = sortedSectors.map((s) => s.acrs_score);

      const ctxSector = document.getElementById("chart-sector-overview").getContext("2d");
      charts.sectorOverview = new Chart(ctxSector, {
        type: "bar",
        data: {
          labels: sLabels,
          datasets: [
            {
              label: "ACRS Score",
              data: sScores,
              backgroundColor: sScores.map((sc) => (sc >= 50 ? "#f97316" : sc >= 25 ? "#eab308" : "#10b981")),
              borderRadius: 4,
            },
          ],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "rgba(30, 47, 84, 0.4)" }, max: 100, beginAtZero: true },
            y: { grid: { display: false } },
          },
        },
      });

      // Recent Notable Incidents Table
      const tbody = document.getElementById("overview-recent-incidents-tbody");
      if (data.recent_records && data.recent_records.length > 0) {
        tbody.innerHTML = data.recent_records
          .map(
            (r) => `
          <tr>
            <td><code style="color: var(--accent-cyan);">${r.incident_id}</code></td>
            <td>${r.incident_date}</td>
            <td><strong>${r.threat_type}</strong></td>
            <td>${r.target_sector}</td>
            <td>${getSeverityBadge(r.severity)}</td>
            <td>${r.target_state || "National"}</td>
          </tr>
        `
          )
          .join("");
      } else {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No incidents available in database.</td></tr>`;
      }
    } catch (err) {
      console.error("Failed to load overview data:", err);
    }
  }

  // ─── PAGE 2: CRITICAL INFRASTRUCTURE ───────────────────────────────────────
  async function loadSectors() {
    try {
      const res = await fetch("/api/sectors");
      const data = await res.json();
      if (data.status !== "success") return;

      state.sectorsData = data.sectors;
      renderSectorsTable(data.sectors);

      // Chart 1: Sector Comparison Bar
      destroyChart("sectorComparison");
      const ctxComp = document.getElementById("chart-sector-comparison").getContext("2d");
      charts.sectorComparison = new Chart(ctxComp, {
        type: "bar",
        data: {
          labels: data.sectors.map((s) => s.sector_name),
          datasets: [
            {
              label: "ACRS Composite Score",
              data: data.sectors.map((s) => s.acrs_score),
              backgroundColor: "#38bdf8",
              borderRadius: 4,
            },
            {
              label: "NIFS (Frequency Score)",
              data: data.sectors.map((s) => s.nifs_score),
              backgroundColor: "rgba(59, 130, 246, 0.4)",
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { grid: { display: false } },
            y: { grid: { color: "rgba(30, 47, 84, 0.4)" }, max: 100, beginAtZero: true },
          },
        },
      });

      // Chart 2: Contributing Factors Stacked Bar
      destroyChart("sectorFactors");
      const ctxFactors = document.getElementById("chart-sector-factors").getContext("2d");
      charts.sectorFactors = new Chart(ctxFactors, {
        type: "bar",
        data: {
          labels: data.sectors.map((s) => s.sector_name),
          datasets: [
            {
              label: "Frequency Pts (max 40)",
              data: data.sectors.map((s) => s.freq_points_contrib),
              backgroundColor: "#38bdf8",
            },
            {
              label: "Severity Pts (max 35)",
              data: data.sectors.map((s) => s.sev_points_contrib),
              backgroundColor: "#f97316",
            },
            {
              label: "Criticality Pts (max 25)",
              data: data.sectors.map((s) => s.crit_points_contrib),
              backgroundColor: "#a855f7",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { stacked: true, grid: { display: false } },
            y: { stacked: true, grid: { color: "rgba(30, 47, 84, 0.4)" }, max: 100, beginAtZero: true },
          },
        },
      });
    } catch (err) {
      console.error("Failed to load sectors:", err);
    }
  }

  function renderSectorsTable(sectors) {
    const tbody = document.getElementById("tbody-sectors");
    if (!sectors || sectors.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No matching sectors found.</td></tr>`;
      return;
    }

    tbody.innerHTML = sectors
      .map(
        (s) => `
      <tr>
        <td><strong>#${s.rank}</strong></td>
        <td><strong>${s.sector_name}</strong></td>
        <td><span style="font-size: 1rem; font-weight: 700; color: var(--accent-cyan);">${Number(s.acrs_score).toFixed(2)}</span></td>
        <td>${getRiskCategoryBadge(s.risk_category)}</td>
        <td>${Number(s.incident_count).toLocaleString()}</td>
        <td>${s.nifs_score}</td>
        <td>${s.wss_score}</td>
        <td><code>${s.scw}</code></td>
        <td style="font-size: 0.76rem; color: var(--text-secondary); max-width: 280px;">${s.criticality_assumption || "—"}</td>
      </tr>
    `
      )
      .join("");
  }

  // Filter Sectors in memory
  const filterCat = document.getElementById("filter-sector-category");
  const searchSec = document.getElementById("search-sector-input");

  function applySectorFilter() {
    const cat = filterCat.value;
    const term = searchSec.value.toLowerCase().trim();

    const filtered = state.sectorsData.filter((s) => {
      const matchCat = cat === "all" || s.risk_category === cat;
      const matchTerm = !term || s.sector_name.toLowerCase().includes(term);
      return matchCat && matchTerm;
    });
    renderSectorsTable(filtered);
  }

  filterCat.addEventListener("change", applySectorFilter);
  searchSec.addEventListener("input", applySectorFilter);

  // ─── PAGE 3: THREAT INTELLIGENCE ───────────────────────────────────────────
  async function loadThreats() {
    try {
      const res = await fetch("/api/threats");
      const data = await res.json();
      if (data.status !== "success") return;

      // Chart 1: Threat Vectors Bar
      destroyChart("threatBars");
      const ctxTBars = document.getElementById("chart-threat-bars").getContext("2d");
      charts.threatBars = new Chart(ctxTBars, {
        type: "bar",
        data: {
          labels: data.threat_distribution.map((t) => t.threat_type),
          datasets: [
            {
              label: "Incident Volume",
              data: data.threat_distribution.map((t) => t.incident_count),
              backgroundColor: ["#38bdf8", "#3b82f6", "#ef4444", "#f97316", "#a855f7"],
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false } },
            y: { grid: { color: "rgba(30, 47, 84, 0.4)" }, beginAtZero: true },
          },
        },
      });

      // Chart 2: Severity Distribution Donut
      destroyChart("incidentSeverity");
      const ctxSev = document.getElementById("chart-incident-severity").getContext("2d");
      charts.incidentSeverity = new Chart(ctxSev, {
        type: "pie",
        data: {
          labels: data.severity_distribution.map((s) => s.severity),
          datasets: [
            {
              data: data.severity_distribution.map((s) => s.incident_count),
              backgroundColor: ["#ef4444", "#f97316", "#eab308", "#10b981"],
              borderColor: "#111d35",
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "right" } },
        },
      });

      // Load Incidents Table
      loadIncidentsTable();
    } catch (err) {
      console.error("Failed to load threats:", err);
    }
  }

  async function loadIncidentsTable() {
    const tbody = document.getElementById("tbody-incidents");
    const countLabel = document.getElementById("incident-record-count-label");
    const curPageSpan = document.getElementById("incidents-current-page");
    const totalPagesSpan = document.getElementById("incidents-total-pages");
    const btnPrev = document.getElementById("btn-incidents-prev");
    const btnNext = document.getElementById("btn-incidents-next");

    tbody.innerHTML = `<tr><td colspan="8" class="loading-spinner"><div class="spinner"></div>Loading records...</td></tr>`;

    try {
      const q = new URLSearchParams({
        page: state.incidents.page,
        per_page: state.incidents.perPage,
        search: state.incidents.search,
        threat_type: state.incidents.threat,
        severity: state.incidents.severity,
      });

      const res = await fetch(`/api/incidents/list?${q.toString()}`);
      const data = await res.json();
      if (data.status !== "success") return;

      state.incidents.totalPages = data.total_pages;
      curPageSpan.textContent = data.page;
      totalPagesSpan.textContent = data.total_pages;
      countLabel.textContent = `Showing ${(data.page - 1) * state.incidents.perPage + 1}–${Math.min(
        data.page * state.incidents.perPage,
        data.total_records
      )} of ${data.total_records.toLocaleString()} incidents`;

      btnPrev.disabled = data.page <= 1;
      btnNext.disabled = data.page >= data.total_pages;

      if (!data.records || data.records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No incidents match the selected filters.</td></tr>`;
        return;
      }

      tbody.innerHTML = data.records
        .map(
          (r) => `
        <tr>
          <td><code style="color: var(--accent-cyan); font-weight: 600;">${r.incident_id}</code></td>
          <td>${r.incident_date}</td>
          <td><strong>${r.threat_type}</strong></td>
          <td>${r.target_sector}</td>
          <td>${getSeverityBadge(r.severity)}</td>
          <td>${r.target_state}</td>
          <td><span class="badge badge-synthetic">SYNTHETIC</span></td>
          <td style="font-size: 0.76rem; color: var(--text-secondary); max-width: 250px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${r.description || ''}">${r.description || "—"}</td>
        </tr>
      `
        )
        .join("");
    } catch (err) {
      console.error("Failed to load incidents table:", err);
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">Error loading incidents.</td></tr>`;
    }
  }

  // Incidents Filter & Pagination Listeners
  const filterIncThreat = document.getElementById("filter-incident-threat");
  const filterIncSev = document.getElementById("filter-incident-severity");
  const searchInc = document.getElementById("search-incidents-input");

  filterIncThreat.addEventListener("change", () => {
    state.incidents.threat = filterIncThreat.value;
    state.incidents.page = 1;
    loadIncidentsTable();
  });

  filterIncSev.addEventListener("change", () => {
    state.incidents.severity = filterIncSev.value;
    state.incidents.page = 1;
    loadIncidentsTable();
  });

  let debounceTimer;
  searchInc.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      state.incidents.search = searchInc.value;
      state.incidents.page = 1;
      loadIncidentsTable();
    }, 300);
  });

  document.getElementById("btn-incidents-prev").addEventListener("click", () => {
    if (state.incidents.page > 1) {
      state.incidents.page--;
      loadIncidentsTable();
    }
  });

  document.getElementById("btn-incidents-next").addEventListener("click", () => {
    if (state.incidents.page < state.incidents.totalPages) {
      state.incidents.page++;
      loadIncidentsTable();
    }
  });

  // ─── PAGE 4: VULNERABILITY INTELLIGENCE ─────────────────────────────────────
  async function loadVulnerabilities() {
    try {
      const res = await fetch("/api/vulnerabilities");
      const data = await res.json();
      if (data.status !== "success") return;

      // Extract stats
      let totalCves = 7861,
        meanCvss = 7.52,
        kevCount = 1756,
        rwCount = 361;
      data.statistics.forEach((s) => {
        if (s.metric === "total_cve_records") totalCves = s.value;
        if (s.metric === "mean_cvss_score") meanCvss = s.value;
      });
      data.kev_summary.forEach((k) => {
        if (k.metric === "total_known_exploited_vulnerabilities") kevCount = k.value;
        if (k.metric === "ransomware_campaign_use_known") rwCount = k.value;
      });

      document.getElementById("kpi-vuln-total").textContent = Number(totalCves).toLocaleString();
      document.getElementById("kpi-vuln-mean").textContent = Number(meanCvss).toFixed(2);
      document.getElementById("kpi-vuln-kev").textContent = Number(kevCount).toLocaleString();
      document.getElementById("kpi-vuln-ransomware").textContent = Number(rwCount).toLocaleString();

      // Chart 1: CVSS Severity Donut
      destroyChart("vulnSeverity");
      const ctxVS = document.getElementById("chart-vuln-severity").getContext("2d");
      charts.vulnSeverity = new Chart(ctxVS, {
        type: "doughnut",
        data: {
          labels: data.severity_summary.map((s) => `${s.cvss_severity} (${s.percentage}%)`),
          datasets: [
            {
              data: data.severity_summary.map((s) => s.vulnerability_count),
              backgroundColor: ["#ef4444", "#f97316", "#eab308", "#10b981"],
              borderColor: "#111d35",
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "right" } },
          cutout: "60%",
        },
      });

      // Chart 2: CVSS Score Histogram
      destroyChart("vulnScores");
      const ctxVScore = document.getElementById("chart-vuln-scores").getContext("2d");
      charts.vulnScores = new Chart(ctxVScore, {
        type: "bar",
        data: {
          labels: data.score_distribution.map((d) => d.score_range),
          datasets: [
            {
              label: "Vulnerabilities Count",
              data: data.score_distribution.map((d) => d.cve_count),
              backgroundColor: "#38bdf8",
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false } },
            y: { grid: { color: "rgba(30, 47, 84, 0.4)" }, beginAtZero: true },
          },
        },
      });

      // Load Vulnerabilities Table
      loadVulnsTable();
    } catch (err) {
      console.error("Failed to load vulnerabilities:", err);
    }
  }

  async function loadVulnsTable() {
    const tbody = document.getElementById("tbody-vulns");
    const curPage = document.getElementById("vuln-current-page");
    const totalPages = document.getElementById("vuln-total-pages");
    const totalCount = document.getElementById("vuln-total-count");
    const btnPrev = document.getElementById("btn-vuln-prev");
    const btnNext = document.getElementById("btn-vuln-next");

    tbody.innerHTML = `<tr><td colspan="8" class="loading-spinner"><div class="spinner"></div>Loading CVE catalog...</td></tr>`;

    try {
      const q = new URLSearchParams({
        page: state.vulns.page,
        per_page: state.vulns.perPage,
        search: state.vulns.search,
        severity: state.vulns.severity,
        exploited: state.vulns.exploited,
      });

      const res = await fetch(`/api/vulnerabilities/list?${q.toString()}`);
      const data = await res.json();
      if (data.status !== "success") return;

      state.vulns.totalPages = data.total_pages;
      curPage.textContent = data.page;
      totalPages.textContent = data.total_pages;
      totalCount.textContent = Number(data.total_records).toLocaleString();

      btnPrev.disabled = data.page <= 1;
      btnNext.disabled = data.page >= data.total_pages;

      if (!data.records || data.records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No CVEs match the selected criteria.</td></tr>`;
        return;
      }

      tbody.innerHTML = data.records
        .map((v) => {
          let kevBadge = `<span class="badge badge-public">Standard NVD</span>`;
          if (v.is_known_exploited) {
            if (v.known_ransomware_use === "Known") {
              kevBadge = `<span class="badge badge-ransomware">KEV + Ransomware</span>`;
            } else {
              kevBadge = `<span class="badge badge-kev">KEV Listed</span>`;
            }
          }

          const cvssColor = v.cvss_base_score >= 9.0 ? "#ef4444" : v.cvss_base_score >= 7.0 ? "#f97316" : "#eab308";

          return `
          <tr>
            <td><code style="color: var(--accent-cyan); font-weight: 700;">${v.cve_id}</code></td>
            <td>${v.published_date}</td>
            <td><span style="font-weight: 700; color: ${cvssColor};">${Number(v.cvss_base_score).toFixed(1)}</span></td>
            <td>${getSeverityBadge(v.cvss_severity)}</td>
            <td><strong>${v.vendor}</strong></td>
            <td>${v.product}</td>
            <td>${kevBadge}</td>
            <td style="font-size: 0.76rem; color: var(--text-secondary); max-width: 280px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${v.description || ''}">${v.description || "—"}</td>
          </tr>
        `;
        })
        .join("");
    } catch (err) {
      console.error("Failed to load CVE catalog:", err);
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">Error loading CVE records.</td></tr>`;
    }
  }

  // Vulnerabilities Filter & Pagination Listeners
  const filterVSeverity = document.getElementById("filter-vuln-severity");
  const filterVExploited = document.getElementById("filter-vuln-exploited");
  const searchV = document.getElementById("search-vuln-input");

  filterVSeverity.addEventListener("change", () => {
    state.vulns.severity = filterVSeverity.value;
    state.vulns.page = 1;
    loadVulnsTable();
  });

  filterVExploited.addEventListener("change", () => {
    state.vulns.exploited = filterVExploited.value;
    state.vulns.page = 1;
    loadVulnsTable();
  });

  let vulnSearchDebounce;
  searchV.addEventListener("input", () => {
    clearTimeout(vulnSearchDebounce);
    vulnSearchDebounce = setTimeout(() => {
      state.vulns.search = searchV.value;
      state.vulns.page = 1;
      loadVulnsTable();
    }, 300);
  });

  document.getElementById("btn-vuln-prev").addEventListener("click", () => {
    if (state.vulns.page > 1) {
      state.vulns.page--;
      loadVulnsTable();
    }
  });

  document.getElementById("btn-vuln-next").addEventListener("click", () => {
    if (state.vulns.page < state.vulns.totalPages) {
      state.vulns.page++;
      loadVulnsTable();
    }
  });

  // ─── PAGE 5: RISK ANALYSIS ─────────────────────────────────────────────────
  async function loadRiskAnalysis() {
    try {
      const res = await fetch("/api/risk-analysis");
      const data = await res.json();
      if (data.status !== "success") return;

      // Chart 1: Scatter Severity vs Frequency
      destroyChart("riskScatter");
      const scatterPoints = data.sectors.map((s) => ({
        x: s.nifs_score,
        y: s.wss_score,
        sector: s.sector_name,
        acrs: s.acrs_score,
      }));

      const ctxScatter = document.getElementById("chart-risk-scatter").getContext("2d");
      charts.riskScatter = new Chart(ctxScatter, {
        type: "scatter",
        data: {
          datasets: [
            {
              label: "Sectors (NIFS vs WSS)",
              data: scatterPoints,
              backgroundColor: "#00d2ff",
              borderColor: "#38bdf8",
              borderWidth: 2,
              pointRadius: 7,
              pointHoverRadius: 10,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const pt = ctx.raw;
                  return `${pt.sector}: Freq ${pt.x} pts, Sev ${pt.y} pts (ACRS: ${pt.acrs})`;
                },
              },
            },
          },
          scales: {
            x: {
              title: { display: true, text: "Incident Frequency Score (NIFS, max 100)", color: "#94a3b8" },
              grid: { color: "rgba(30, 47, 84, 0.4)" },
              beginAtZero: true,
              max: 105,
            },
            y: {
              title: { display: true, text: "Weighted Severity Score (WSS, max 100)", color: "#94a3b8" },
              grid: { color: "rgba(30, 47, 84, 0.4)" },
              beginAtZero: true,
              max: 60,
            },
          },
        },
      });

      // Chart 2: Threat Category Risk Scores
      destroyChart("threatRisk");
      const ctxTR = document.getElementById("chart-threat-risk").getContext("2d");
      charts.threatRisk = new Chart(ctxTR, {
        type: "bar",
        data: {
          labels: data.threats.map((t) => t.threat_type),
          datasets: [
            {
              label: "Threat Risk Score",
              data: data.threats.map((t) => t.threat_risk_score),
              backgroundColor: ["#ef4444", "#f97316", "#eab308", "#38bdf8", "#a855f7"],
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false } },
            y: { grid: { color: "rgba(30, 47, 84, 0.4)" }, max: 100, beginAtZero: true },
          },
        },
      });

      // Key Insights Cards
      const container = document.getElementById("risk-insights-container");
      container.innerHTML = data.insights
        .map(
          (ins) => `
        <div class="insight-card">
          <h5>${ins.title}</h5>
          <p>${ins.text}</p>
        </div>
      `
        )
        .join("");
    } catch (err) {
      console.error("Failed to load risk analysis:", err);
    }
  }

  // ─── Page Dispatcher ───────────────────────────────────────────────────────
  function loadPageData(pageId) {
    if (pageId === "page-overview") loadOverview();
    else if (pageId === "page-sectors") loadSectors();
    else if (pageId === "page-threats") loadThreats();
    else if (pageId === "page-vulnerabilities") loadVulnerabilities();
    else if (pageId === "page-risk-analysis") loadRiskAnalysis();
  }

  // ─── Header Refresh Action ────────────────────────────────────────────────
  const btnRefresh = document.getElementById("btn-refresh-data");
  btnRefresh.addEventListener("click", async () => {
    btnRefresh.classList.add("spinning");
    try {
      const res = await fetch("/api/refresh", { method: "POST" });
      const data = await res.json();
      console.log("Data refreshed:", data);
      loadPageData(state.activePage);
      fetchSystemStatus();
    } catch (err) {
      console.error("Refresh failed:", err);
    } finally {
      setTimeout(() => {
        btnRefresh.classList.remove("spinning");
      }, 600);
    }
  });

  // ─── System Status Poller ──────────────────────────────────────────────────
  async function fetchSystemStatus() {
    try {
      const res = await fetch("/api/system-status");
      const data = await res.json();
      if (data.status === "online") {
        const incCount = data.database.counts.INCIDENTS || 2434;
        document.getElementById("sidebar-db-status").textContent = `Database Online (${incCount.toLocaleString()} Incidents)`;
      }
    } catch (err) {
      document.getElementById("sidebar-db-status").textContent = "Database Offline";
    }
  }

  // ─── Initial Page Load ─────────────────────────────────────────────────────
  fetchSystemStatus();
  loadOverview();
});
