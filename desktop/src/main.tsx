import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./style.css";

// The browser preview's way of seeing the dark palette; see style.css.
if (new URLSearchParams(window.location.search).get("dark") === "1") {
  document.documentElement.classList.add("dark");
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
