import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import { loadProviderConfig, postCallbackToOpener } from "./lib/auth";
import { closeConsentPopup } from "./lib/consentWindow";
import "./styles.css";

// **Before React, and this ordering is the whole point.**
//
// Silent renewal loads this same page inside a hidden iframe — it is the redirect URI,
// so there is nowhere else for the provider to send it. Mounting the application there
// would boot a second copy of everything inside an invisible frame, including a second
// silent renewal, which loads a third. One line, and it is the difference between a
// renewal and a fork bomb.
// The second window this app is loaded into and must not mount inside. A consent popup
// coming back from a provider posts its outcome to the opener and closes; mounting here
// would boot a silent sign-in inside a popup that is about to disappear, fail it, and
// flash a sign-in screen on the way out. Same reasoning as the line below it, found the
// same way — by watching what actually happened.
if (!closeConsentPopup() && !postCallbackToOpener()) {
  // The provider's whereabouts, before anything can need them: `boot()` fires from the
  // first render, and a silent sign-in against an unresolved provider would fail as
  // "not configured" on a page that simply had not finished reading its config.
  // `loadProviderConfig` never throws — a page with no provider still mounts, and the
  // sign-in screen says what is missing.
  void loadProviderConfig().finally(() => {
    createRoot(document.getElementById("root")!).render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
  });
}
