let attackersChart;
let severityChart;
let typeChart;
let timelineChart;
let lastAlertId = 0;


// =========================
// LOAD STATISTICS
// =========================
async function loadStats() {

    const response = await fetch("/api/stats");
    const data = await response.json();

    document.getElementById("total").textContent = data.total;
    document.getElementById("critical").textContent = data.critical;
    document.getElementById("high").textContent = data.high;
    document.getElementById("medium").textContent = data.medium;
    document.getElementById("low").textContent = data.low;

    updateSeverityChart(data);
}


// =========================
// LOAD EVENTS
// =========================
async function loadEvents() {

    const filter = document.getElementById("filter").value;
    const search = document.getElementById("search").value;

    const response = await fetch(
        "/api/events?severity=" +
        encodeURIComponent(filter) +
        "&search=" +
        encodeURIComponent(search)
    );

    const events = await response.json();
    loadAttackers();


    // Check new security alert
    if (events.length > 0) {

        const newestEvent = events[0];

        if (lastAlertId === 0) {

            lastAlertId = newestEvent.id;

        } else if (newestEvent.id > lastAlertId) {

            lastAlertId = newestEvent.id;

            if (
                newestEvent.severity === "CRITICAL" ||
                newestEvent.severity === "HIGH"
            ) {
                showAlert(newestEvent);
            }
        }
    }


    // Display events
    const table = document.getElementById("events");

    table.innerHTML = "";


    events.forEach(function(event) {

        const acknowledged =
            event.status === "ACKNOWLEDGED";

        const statusClass =
            acknowledged ? "acknowledged" : "open";

        const statusText =
            event.status || "OPEN";


        let actionButton;


        if (acknowledged) {

            actionButton =
                '<button disabled>ACKNOWLEDGED</button>';

        } else {

            actionButton =
                '<button onclick="acknowledgeEvent(' +
                event.id +
                ')">ACKNOWLEDGE</button>';
        }


        table.innerHTML +=

            "<tr>" +

            "<td>" +
            event.id +
            "</td>" +

            "<td>" +
            event.timestamp +
            "</td>" +

            "<td>" +
            event.event_type +
            "</td>" +

            '<td><span class="severity ' +
            event.severity.toLowerCase() +
            '">' +
            event.severity +
            "</span></td>" +

            "<td>" +
            event.source_ip +
            "</td>" +

            "<td>" +
            event.port +
            "</td>" +

            "<td>" +
            event.message +
            "</td>" +

            '<td><span class="status-badge ' +
            statusClass +
            '">' +
            statusText +
            "</span></td>" +

            "<td>" +

            actionButton +

            '<button class="delete-btn" onclick="deleteEvent(' +
            event.id +
            ')">Delete</button>' +

            "</td>" +

            "</tr>";
    });


    updateTypeChart(events);

    updateTimelineChart(events);
}


// =========================
// SECURITY ALERT
// =========================
function showAlert(event) {

    const alertBox =
        document.createElement("div");

    alertBox.className =
        "security-alert";


    alertBox.innerHTML =

        "<strong>SECURITY ALERT</strong>" +

        "<br><br>" +

        "Severity: " +
        event.severity +

        "<br>" +

        "Event: " +
        event.event_type +

        "<br>" +

        "Source: " +
        event.source_ip +

        "<br>" +

        "Port: " +
        event.port;


    document.body.appendChild(alertBox);


    setTimeout(function() {

        alertBox.remove();

    }, 5000);
}


// =========================
// ACKNOWLEDGE EVENT
// =========================
async function acknowledgeEvent(id) {

    await fetch(
        "/api/events/" +
        id +
        "/acknowledge",
        {
            method: "PUT"
        }
    );


    await loadStats();

    await loadEvents();
}


// =========================
// DELETE EVENT
// =========================
async function deleteEvent(id) {

    await fetch(
        "/api/events/" +
        id,
        {
            method: "DELETE"
        }
    );


    await loadStats();

    await loadEvents();
}


// =========================
// CLEAR ALL EVENTS
// =========================
async function clearEvents() {

    if (!confirm("Clear all security logs?")) {
        return;
    }


    await fetch(
        "/api/clear",
        {
            method: "DELETE"
        }
    );


    lastAlertId = 0;


    await loadStats();

    await loadEvents();
}


// =========================
// SEVERITY CHART
// =========================
function updateSeverityChart(data) {

    const ctx =
        document.getElementById("severityChart");


    if (severityChart) {
        severityChart.destroy();
    }


    severityChart = new Chart(ctx, {

        type: "doughnut",

        data: {

            labels: [
                "Critical",
                "High",
                "Medium",
                "Low"
            ],

            datasets: [
                {
                    data: [
                        data.critical,
                        data.high,
                        data.medium,
                        data.low
                    ]
                }
            ]
        }
    });
}


// =========================
// DETECTION TYPE CHART
// =========================
function updateTypeChart(events) {

    const counts = {};


    events.forEach(function(event) {

        if (counts[event.event_type]) {

            counts[event.event_type]++;

        } else {

            counts[event.event_type] = 1;
        }
    });


    const ctx =
        document.getElementById("typeChart");


    if (!ctx) {
        return;
    }


    if (typeChart) {
        typeChart.destroy();
    }


    typeChart = new Chart(ctx, {

        type: "bar",

        data: {

            labels:
                Object.keys(counts),

            datasets: [

                {
                    label:
                        "Detected Events",

                    data:
                        Object.values(counts)
                }
            ]
        }
    });
}


// =========================
// ATTACK TIMELINE
// =========================
function updateTimelineChart(events) {

    const counts = {};


    events.forEach(function(event) {

        const time =
            event.timestamp.substring(11, 16);


        if (counts[time]) {

            counts[time]++;

        } else {

            counts[time] = 1;
        }
    });


    const ctx =
        document.getElementById("timelineChart");


    if (!ctx) {
        return;
    }


    if (timelineChart) {
        timelineChart.destroy();
    }


    timelineChart = new Chart(ctx, {

        type: "line",

        data: {

            labels:
                Object.keys(counts),

            datasets: [

                {
                    label:
                        "Security Events",

                    data:
                        Object.values(counts),

                    tension: 0.3,

                    fill: false
                }
            ]
        },

        options: {

            responsive: true,

            maintainAspectRatio: false
        }
    });
}


// =========================
// START DASHBOARD
// =========================
loadStats();

loadEvents();


// =========================
// AUTO REFRESH
// =========================
setInterval(function() {

    loadStats();

    loadEvents();

}, 5000);
async function loadAttackers() {

    const response = await fetch("/api/attackers");

    const data = await response.json();

    const ctx =
        document.getElementById("attackersChart");

    if (!ctx) {
        return;
    }

    if (attackersChart) {
        attackersChart.destroy();
    }

    attackersChart = new Chart(ctx, {

        type: "bar",

        data: {

            labels: data.map(
                item => item.source_ip
            ),

            datasets: [
                {
                    label: "Security Events",

                    data: data.map(
                        item => item.attacks
                    )
                }
            ]
        },

        options: {
            responsive: true
        }
    });
}