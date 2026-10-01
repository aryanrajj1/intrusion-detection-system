let severityChart;
let typeChart;


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


async function loadEvents() {

    const filter = document.getElementById("filter").value;
    const search = document.getElementById("search").value;

    const response = await fetch(
        `/api/events?severity=${encodeURIComponent(filter)}&search=${encodeURIComponent(search)}`
    );

    const events = await response.json();

    const table = document.getElementById("events");

    table.innerHTML = "";

    events.forEach(event => {

        table.innerHTML += `
            <tr>

                <td>${event.id}</td>

                <td>${event.timestamp}</td>

                <td>${event.event_type}</td>

                <td>
                    <span class="severity ${event.severity.toLowerCase()}">
                        ${event.severity}
                    </span>
                </td>

                <td>${event.source_ip}</td>

                <td>${event.port}</td>

                <td>${event.message}</td>

                <td>
                    <button onclick="deleteEvent(${event.id})">
                        Delete
                    </button>
                </td>

            </tr>
        `;
    });

    updateTypeChart(events);
}


async function deleteEvent(id) {

    await fetch(
        `/api/events/${id}`,
        {
            method: "DELETE"
        }
    );

    loadStats();
    loadEvents();
}


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

    loadStats();
    loadEvents();
}


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

            datasets: [{
                data: [
                    data.critical,
                    data.high,
                    data.medium,
                    data.low
                ]
            }]

        }

    });
}


function updateTypeChart(events) {

    const counts = {};

    events.forEach(event => {

        counts[event.event_type] =
            (counts[event.event_type] || 0) + 1;

    });


    const ctx =
        document.getElementById("typeChart");

    if (typeChart) {
        typeChart.destroy();
    }


    typeChart = new Chart(ctx, {

        type: "bar",

        data: {

            labels: Object.keys(counts),

            datasets: [{

                label: "Detected Events",

                data: Object.values(counts)

            }]

        }

    });
}


loadStats();
loadEvents();


setInterval(() => {

    loadStats();
    loadEvents();

}, 5000);