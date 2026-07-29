document.addEventListener("DOMContentLoaded", () => {
    const targetInput = document.getElementById("target-input");
    const modeSelect = document.getElementById("mode-select");
    const cveToggle = document.getElementById("cve-toggle");
    const startBtn = document.getElementById("start-scan-btn");

    const progressContainer = document.getElementById("progress-container");
    const progressFill = document.getElementById("progress-fill");
    const progressText = document.getElementById("progress-text");
    const progressPct = document.getElementById("progress-pct");

    const metricsSection = document.getElementById("metrics-section");
    const mHosts = document.getElementById("m-hosts");
    const mPorts = document.getElementById("m-ports");
    const mVulns = document.getElementById("m-vulns");

    const resultsDisplay = document.getElementById("results-display");
    const terminalFeed = document.getElementById("terminal-feed");
    const reportDownloadPills = document.getElementById("report-download-pills");
    const reportArchiveList = document.getElementById("report-archive-list");

    let pollInterval = null;

    startBtn.addEventListener("click", async () => {
        const target = targetInput.value.trim();
        if (!target) {
            alert("Please enter a valid target IP or host range.");
            return;
        }

        startBtn.disabled = true;
        progressContainer.style.display = "block";
        progressFill.style.width = "5%";
        progressPct.innerText = "5%";
        progressText.innerText = "Initiating scan engine...";

        try {
            const res = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target: target,
                    scan_mode: modeSelect.value,
                    lookup_cves: cveToggle.checked
                })
            });
            const data = await res.json();
            if (data.status === "error") {
                alert(data.message);
                startBtn.disabled = false;
                return;
            }

            // Start status polling
            pollInterval = setInterval(checkStatus, 1000);
        } catch (err) {
            alert("Failed to connect to backend engine.");
            startBtn.disabled = false;
        }
    });

    async function checkStatus() {
        try {
            const res = await fetch("/api/status");
            const state = await res.json();

            // Update progress
            progressFill.style.width = `${state.progress}%`;
            progressPct.innerText = `${Math.round(state.progress)}%`;

            // Update terminal logs
            if (state.logs && state.logs.length) {
                terminalFeed.innerHTML = state.logs.map(l => `<div class="log-line">${l}</div>`).join("");
                terminalFeed.scrollTop = terminalFeed.scrollHeight;
                progressText.innerText = state.logs[state.logs.length - 1];
            }

            if (state.status === "Complete" || state.status === "Error") {
                clearInterval(pollInterval);
                startBtn.disabled = false;
                if (state.results) {
                    renderResults(state.results);
                }
                loadReportArchive();
            }
        } catch (err) {
            console.error("Polling error:", err);
        }
    }

    function renderResults(results) {
        metricsSection.style.display = "grid";
        mHosts.innerText = results.hosts_discovered_count || 0;

        let totalPorts = 0;
        let totalRisks = 0;
        let htmlContent = "";

        const discoveries = results.network_discoveries || {};
        for (const [hostIp, hostInfo] of Object.entries(discoveries)) {
            const findings = hostInfo.findings || [];
            totalPorts += hostInfo.open_ports_detected || 0;

            htmlContent += `
                <div style="margin-bottom: 20px; background: rgba(15, 23, 42, 0.6); padding: 16px; border-radius: 12px; border: 1px solid var(--border-card);">
                    <h4 style="color: var(--accent-cyan); margin-bottom: 10px;">🖥️ Host: ${hostIp} (${hostInfo.open_ports_detected} Open Ports)</h4>
            `;

            if (!findings.length) {
                htmlContent += `<p style="color: var(--text-secondary); font-size: 0.85rem;">Zero open targeted ports detected on this host.</p>`;
            } else {
                htmlContent += `
                    <table>
                        <thead>
                            <tr>
                                <th>Port / Proto</th>
                                <th>Service</th>
                                <th>Banner Metadata</th>
                                <th>Security Analysis & CVE</th>
                            </tr>
                        </thead>
                        <tbody>
                `;

                for (const f of findings) {
                    const vuln = f.vulnerability;
                    let vulnHtml = `<span style="color: var(--accent-green); font-weight: 600;">✔ Clean</span>`;
                    if (vuln) {
                        totalRisks++;
                        const cvePill = vuln.cve_id ? `<span style="background: rgba(192, 132, 252, 0.2); color: #d8b4fe; padding: 2px 6px; border-radius: 4px; font-family: monospace;">${vuln.cve_id}</span> ` : '';
                        vulnHtml = `
                            <span style="color: var(--accent-red); font-weight: 600;">⚠️ ${vuln.severity || 'Risk'}</span>
                            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 2px;">
                                ${cvePill}<strong>${vuln.title}</strong>
                            </div>
                        `;
                    }

                    htmlContent += `
                        <tr>
                            <td><strong>${f.port}</strong> <span style="font-size: 0.75rem; background: #334155; padding: 2px 6px; border-radius: 4px;">${f.protocol || 'TCP'}</span></td>
                            <td>${f.service || 'Unknown'}</td>
                            <td style="font-family: monospace; font-size: 0.8rem; color: var(--text-secondary);">${f.banner || 'None'}</td>
                            <td>${vulnHtml}</td>
                        </tr>
                    `;
                }

                htmlContent += `</tbody></table>`;
            }

            htmlContent += `</div>`;
        }

        mPorts.innerText = totalPorts;
        mVulns.innerText = totalRisks;
        resultsDisplay.innerHTML = htmlContent || `<p>No host findings.</p>`;

        // Add download buttons
        if (results.reports) {
            reportDownloadPills.innerHTML = `
                <a href="/api/reports/download/${results.reports.html_report}" target="_blank" class="btn-primary" style="padding: 6px 12px; font-size: 0.8rem;">📄 HTML Report</a>
                <a href="/api/reports/download/${results.reports.json_report}" target="_blank" class="btn-primary" style="padding: 6px 12px; font-size: 0.8rem; background: #475569;">📊 JSON Data</a>
            `;
        }
    }

    async function loadReportArchive() {
        try {
            const res = await fetch("/api/reports");
            const reports = await res.json();
            if (reports.length) {
                reportArchiveList.innerHTML = reports.map(r => `
                    <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border-card); font-size: 0.8rem;">
                        <span>${r.filename} (${r.size_kb} KB)</span>
                        <a href="/api/reports/download/${r.filename}" target="_blank" style="color: var(--accent-cyan); text-decoration: none;">Download</a>
                    </div>
                `).join("");
            }
        } catch (err) {
            console.error("Failed to load archive:", err);
        }
    }

    loadReportArchive();
});
