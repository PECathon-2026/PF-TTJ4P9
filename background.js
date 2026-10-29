chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension successfully installed.");

  // chrome.alarms.create("myBackgroundAlarm", {
  //   periodInMinutes: 1,
  // });
});
chrome.tabs.onUpdated.addListener(async (tabId, tab) => {
  console.log("heelo world");
  return chrome.tabs.sendMessage(tabId, { type: "SCAN" });
});
