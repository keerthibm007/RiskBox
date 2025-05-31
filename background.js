chrome.runtime.onInstalled.addListener(() => {
  console.log("Email Security Extension installed");
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanEmails") {
    fetch("http://localhost:5000/scan_emails", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: "me" }),
    })
      .then((response) => response.json())
      .then((data) => {
        sendResponse({ summaries: data });
      })
      .catch((error) => {
        console.error("Error scanning emails:", error);
        sendResponse({ error: "Failed to scan emails" });
      });
    return true;
  }
});