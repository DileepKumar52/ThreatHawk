const logFile = document.getElementById("logFile");
const uploadBtn = document.getElementById("uploadBtn");
const totalEvents = document.getElementById("totalEvents");
const eventTable = document.getElementById("eventTable");

uploadBtn.addEventListener("click", function () {
    const file = logFile.files[0];

    if (!file) {
        alert("Please select a log file first.");
        return;
    }

    const reader = new FileReader();

    reader.onload = function (event) {
        const content = event.target.result;

        const logLines = content
            .split("\n")
            .map(line => line.trim())
            .filter(line => line.length > 0);

        totalEvents.textContent = logLines.length;
        eventTable.innerHTML = "";

        logLines.forEach(line => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>-</td>
                <td>Info</td>
                <td>${line}</td>
                <td>-</td>
            `;

            eventTable.appendChild(row);
        });
    };

    reader.readAsText(file);
});