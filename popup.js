chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "myBackgroundAlarm") {
    console.log("Background task running at:", new Date().toLocaleTimeString());
    send();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const ScanBtn = document.getElementById("scanBtn");
  if (ScanBtn) {
    ScanBtn.addEventListener("click", async () => {
      console.log("clicked");
      // Find the active browser tab
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });

      if (tab?.id) {
        console.log("id");
        // Send a message to the content script running inside that tab
        chrome.tabs.sendMessage(tab.id, { action: "SCAN" }, (response) => {
          console.log(response);
          if (chrome.runtime.lastError) {
            alert("Cannot scan this page. Try refreshing.");
            return;
          }
          if (response) {
            document.getElementById("results").style.display = "block";
            document.getElementById("headersCount").textContent =
              response.headers;
            document.getElementById("linksCount").textContent = response.links;
          }
        });
      }
    });
  }
});
