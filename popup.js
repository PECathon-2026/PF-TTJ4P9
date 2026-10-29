document.getElementById("actionBtn").addEventListener("click", async () => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // Send a message to the content script running on the active tab
  chrome.tabs.sendMessage(tab.id, { action: "highlight" });
});
