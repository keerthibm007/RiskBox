console.log("Content script loaded on Gmail");

document.addEventListener("DOMContentLoaded", () => {
  chrome.runtime.sendMessage({ action: "scanEmails" }, (response) => {
    if (response.error) {
      console.error(response.error);
      return;
    }
    console.log("Email summaries:", response.summaries);
  });
});