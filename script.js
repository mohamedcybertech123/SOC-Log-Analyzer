// ==========================================
// SOC LOG ANALYZER - DASHBOARD
// ==========================================


// ==========================================
// LOAD SAMPLE LOG FILE
// ==========================================

fetch("sample_logs.txt")

    .then(response => {

        if (!response.ok) {
            throw new Error("Could not load the log file.");
        }

        return response.text();

    })

    .then(data => {

        analyzeLogs(data);

    })

    .catch(error => {

        console.error("Error loading logs:", error);

    });


// ==========================================
// ANALYZE LOGS
// ==========================================

function analyzeLogs(logData) {

    // Split the log file into individual events
    const logs = logData
        .split("\n")
        .map(log => log.trim())
        .filter(log => log !== "");


    // ======================================
    // COUNTERS
    // ======================================

    let totalEvents = 0;
    let successfulLogins = 0;
    let failedLogins = 0;

    let criticalAlerts = 0;
    let highAlerts = 0;
    let mediumAlerts = 0;
    let lowAlerts = 0;


    // ======================================
    // STORAGE
    // ======================================

    // Total failed attempts from each IP
    const failedByIP = {};

    // Account targeted by each IP
    const targetAccounts = {};

    // Consecutive failed attempts
    const currentFailures = {};

    // Successful logins after repeated failures
    const suspiciousSuccesses = [];


    // ======================================
    // ANALYZE EACH SECURITY EVENT
    // ======================================

    logs.forEach(log => {

        totalEvents++;

        const parts = log.split(/\s+/);


        // Find username
        const usernamePart = parts.find(part =>
            part.startsWith("user=")
        );


        // Find IP address
        const ipPart = parts.find(part =>
            part.startsWith("ip=")
        );


        // Skip malformed logs
        if (!usernamePart || !ipPart) {

            console.warn(
                "Invalid log format:",
                log
            );

            return;

        }


        const username =
            usernamePart.replace("user=", "");

        const ipAddress =
            ipPart.replace("ip=", "");


        // ==================================
        // FAILED LOGIN
        // ==================================

        if (log.includes("LOGIN_FAILED")) {

            failedLogins++;


            // Count total failed attempts by IP
            if (failedByIP[ipAddress]) {

                failedByIP[ipAddress]++;

            } else {

                failedByIP[ipAddress] = 1;

            }


            // Remember targeted account
            targetAccounts[ipAddress] =
                username;


            // Count consecutive failures
            if (currentFailures[ipAddress]) {

                currentFailures[ipAddress]++;

            } else {

                currentFailures[ipAddress] = 1;

            }

        }


        // ==================================
        // SUCCESSFUL LOGIN
        // ==================================

        else if (log.includes("LOGIN_SUCCESS")) {

            successfulLogins++;


            const previousFailures =
                currentFailures[ipAddress] || 0;


            // Detect possible account compromise
            if (previousFailures >= 5) {

                suspiciousSuccesses.push({

                    ip: ipAddress,

                    user: username,

                    failures: previousFailures

                });

            }


            // Reset consecutive failures
            // after successful login
            currentFailures[ipAddress] = 0;

        }

    });


    // ======================================
    // DETERMINE FAILED LOGIN ALERT SEVERITY
    // ======================================

    Object.entries(failedByIP).forEach(
        ([ip, attempts]) => {


            // HIGH
            if (attempts >= 10) {

                highAlerts++;

            }


            // MEDIUM
            else if (attempts >= 5) {

                mediumAlerts++;

            }


            // LOW
            else if (attempts > 0) {

                lowAlerts++;

            }

        }
    );


    // ======================================
    // CRITICAL ALERTS
    // ======================================

    criticalAlerts =
        suspiciousSuccesses.length;


    // ======================================
    // TOTAL SECURITY ALERTS
    // ======================================

    const totalAlerts =

        criticalAlerts +
        highAlerts +
        mediumAlerts +
        lowAlerts;


    // ======================================
    // UPDATE DASHBOARD STATISTICS
    // ======================================

    document
        .getElementById("totalEvents")
        .textContent = totalEvents;


    document
        .getElementById("failedLogins")
        .textContent = failedLogins;


    document
        .getElementById("totalAlerts")
        .textContent = totalAlerts;


    document
        .getElementById("criticalAlerts")
        .textContent = criticalAlerts;


    // ======================================
    // GENERATE SECURITY ALERTS
    // ======================================

    const alertsContainer =
        document.getElementById(
            "alertsContainer"
        );


    // Remove loading message
    alertsContainer.innerHTML = "";


    // ======================================
    // CRITICAL ALERT CARDS
    // ======================================

    suspiciousSuccesses.forEach(event => {

        createAlert(

            "critical",

            "CRITICAL",

            "Successful Login After Multiple Failures",

            "A successful authentication occurred after repeated failed login attempts. This may indicate a compromised account.",

            event.ip,

            event.user,

            event.failures

        );

    });


    // ======================================
    // FAILED LOGIN ALERT CARDS
    // ======================================

    Object.entries(failedByIP).forEach(
        ([ip, attempts]) => {

            const account =
                targetAccounts[ip];


            // HIGH ALERT
            if (attempts >= 10) {

                createAlert(

                    "high",

                    "HIGH",

                    "Possible Brute Force Attack",

                    "Multiple failed authentication attempts were detected from the same source IP address.",

                    ip,

                    account,

                    attempts

                );

            }


            // MEDIUM ALERT
            else if (attempts >= 5) {

                createAlert(

                    "medium",

                    "MEDIUM",

                    "Repeated Failed Login Attempts",

                    "Repeated authentication failures were detected from this source IP address.",

                    ip,

                    account,

                    attempts

                );

            }


            // LOW ALERT
            else if (attempts > 0) {

                createAlert(

                    "low",

                    "LOW",

                    "Failed Login Activity",

                    "Failed authentication activity was detected from this source IP address.",

                    ip,

                    account,

                    attempts

                );

            }

        }
    );


    // ======================================
    // NO ALERTS MESSAGE
    // ======================================

    if (totalAlerts === 0) {

        alertsContainer.innerHTML = `

            <div class="no-alerts">

                <h3>
                    No Security Alerts
                </h3>

                <p>
                    No suspicious authentication
                    activity was detected.
                </p>

            </div>

        `;

    }


    // ======================================
    // CONSOLE RESULTS
    // ======================================

    console.log(
        "=============================="
    );

    console.log(
        "SOC LOG ANALYSIS RESULTS"
    );

    console.log(
        "=============================="
    );


    console.log(
        "Total Events:",
        totalEvents
    );


    console.log(
        "Successful Logins:",
        successfulLogins
    );


    console.log(
        "Failed Logins:",
        failedLogins
    );


    console.log(
        "Failed Logins By IP:",
        failedByIP
    );


    console.log(
        "Target Accounts:",
        targetAccounts
    );


    console.log(
        "Suspicious Successful Logins:",
        suspiciousSuccesses
    );


    console.log(
        "Critical Alerts:",
        criticalAlerts
    );


    console.log(
        "High Alerts:",
        highAlerts
    );


    console.log(
        "Medium Alerts:",
        mediumAlerts
    );


    console.log(
        "Low Alerts:",
        lowAlerts
    );


    console.log(
        "Total Alerts:",
        totalAlerts
    );

}


// ==========================================
// CREATE SECURITY ALERT
// ==========================================

function createAlert(

    severityClass,

    severity,

    title,

    description,

    ip,

    account,

    attempts

) {

    const alertsContainer =
        document.getElementById(
            "alertsContainer"
        );


    // Create alert element
    const alert =
        document.createElement("div");


    // Add CSS classes
    alert.classList.add(
        "alert",
        severityClass
    );


    // Create alert content
    alert.innerHTML = `

        <div>

            <span class="severity">
                ${severity}
            </span>


            <h3>
                ${title}
            </h3>


            <p>
                ${description}
            </p>

        </div>


        <div class="alert-details">

            <span>
                IP: ${ip}
            </span>


            <span>
                Account: ${account}
            </span>


            <span>
                Attempts: ${attempts}
            </span>

        </div>

    `;


    // Add alert to dashboard
    alertsContainer.appendChild(alert);

}