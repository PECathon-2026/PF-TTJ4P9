chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "highlight") {
    document.body.style.backgroundColor = "lightyellow";
    alert("Page background modified by extension!");
  }
});
