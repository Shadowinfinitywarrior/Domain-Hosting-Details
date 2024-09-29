document.getElementById("lookup-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const domain = this.domain.value;
    const resultsDiv = document.getElementById("results");

    resultsDiv.innerHTML = "Loading...";

    const response = await fetch("/lookup", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
            "domain": domain
        })
    });

    if (response.ok) {
        const data = await response.json();
        resultsDiv.innerHTML = `
            <h2>Results for ${domain}</h2>
            <p><strong>WHOIS Info:</strong> ${data.domain_info}</p>
            <p><strong>IP Address:</strong> ${data.ip}</p>
            <p><strong>Nameservers:</strong> ${data.nameservers.join(", ")}</p>
            <p><strong>IP Info:</strong> ${JSON.stringify(data.ip_info, null, 2)}</p>
        `;
    } else {
        resultsDiv.innerHTML = "Error: Domain not found or invalid.";
    }
});