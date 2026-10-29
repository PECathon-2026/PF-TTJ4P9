// content.js - Observe DOM changes on the page

// function handlePageChange() {
//   console.log("Page content updated! Running detection code...");
//   // Place your text detection or privacy scan logic here
// }

// // 1. Create an observer instance linked to your callback function
// const observer = new MutationObserver(async (mutationsList) => {
//   for (const mutation of mutationsList) {
//     if (mutation.type === "childList" || mutation.type === "characterData") {
//       handlePageChange();
//       await send({ type: "SCAN" });
//       break; // Trigger once per batch of updates
//     }
//   }
// });

// // 2. Start observing the entire document body for changes
// observer.observe(document.body, {
//   childList: true, // Listen for added/removed DOM nodes
//   subtree: true, // Listen to all descendant nodes, not just direct children
//   characterData: true, // Listen for text content changes inside nodes
// });
import { scanDom, toReport, summarize } from "../detectors/index.js";

(() => {
  if (!window.__privacyLensLoaded) {
    window.__privacyLensLoaded = true;

    const style = document.createElement("style");
    style.textContent = `
    ::highlight(privacylens){background:rgba(225,29,72,.35);}
    [data-pl-flag]{outline:2px solid #e11d48 !important;outline-offset:2px;}`;
    document.documentElement.appendChild(style);

    function clearHighlights() {
      CSS.highlights?.delete("privacylens");
      document
        .querySelectorAll("[data-pl-flag]")
        .forEach((e) => e.removeAttribute("data-pl-flag"));
    }

    function highlight(findings) {
      clearHighlights();
      const ranges = [];
      for (const f of findings) {
        if (f.kind === "text") {
          const r = new Range();
          r.setStart(f.node, f.start);
          r.setEnd(f.node, f.end);
          ranges.push(r);
        } else if (f.element) {
          f.element.setAttribute("data-pl-flag", f.type);
        }
      }
      if (ranges.length && CSS.highlights)
        CSS.highlights.set("privacylens", new Highlight(...ranges));
    }

    chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
      console.log("hello world lol");
      if (msg.type === "PING") {
        sendResponse({ ok: true, title: document.title });
      } else if (msg.type === "SCAN") {
        const { findings, ms } = scanDom(document, msg.opts || {});
        highlight(findings);
        sendResponse({
          ms,
          summary: summarize(findings),
          items: toReport(findings),
        });
      } else if (msg.type === "CLEAR") {
        clearHighlights();
        sendResponse({ ok: true });
      }
      return true;
    });
  }
})();
