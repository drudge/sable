(() => {
  const passkeysSupported = window.isSecureContext && typeof window.PublicKeyCredential !== "undefined";
  document.documentElement.toggleAttribute("data-passkeys-supported", passkeysSupported);
  const decode = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
  const encode = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const creationOptions = (options) => ({
    ...options, challenge: decode(options.challenge), user: {...options.user, id: decode(options.user.id)},
    excludeCredentials: (options.excludeCredentials || []).map((key) => ({...key, id: decode(key.id)})),
  });
  const requestOptions = (options) => ({
    ...options, challenge: decode(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((key) => ({...key, id: decode(key.id)})),
  });
  const serialize = (credential) => {
    const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
    for (const name of ["attestationObject", "authenticatorData", "signature", "userHandle"]) {
      if (credential.response[name]) response[name] = encode(credential.response[name]);
    }
    if (credential.response.getTransports) response.transports = credential.response.getTransports();
    return {id: credential.id, rawId: encode(credential.rawId), type: credential.type, response,
      clientExtensionResults: credential.getClientExtensionResults(), authenticatorAttachment: credential.authenticatorAttachment};
  };
  const post = async (url, csrf, body = {}) => {
    const response = await fetch(url, {method: "POST", credentials: "same-origin", headers: {
      "Content-Type": "application/json", "X-CSRF-Token": csrf || "", "X-Sable-Passkey": "1",
    }, body: JSON.stringify(body)});
    const result = await response.json().catch(() => ({error: "Unable to complete this request. Reload and try again."}));
    if (!response.ok) throw new Error(result.error || "Passkey request failed.");
    return result;
  };
  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-passkey-action]");
    if (!button) return;
    const root = button.closest("[data-passkeys]");
    const status = root.querySelector("[data-passkey-status]");
    const action = button.dataset.passkeyAction;
    if ((action === "login" || action === "register") && !passkeysSupported) {
      status.textContent = "Passkeys require HTTPS (or localhost) and a browser that supports passkeys.";
      return;
    }
    status.textContent = "";
    try {
      if (action === "remove" && !await window.sableConfirmAction(
        "You will no longer be able to use this passkey to sign in.",
        {title: "Remove passkey?", action: "Remove passkey"},
      )) return;
      if (action === "disable-password" && !await window.sableConfirmAction(
        "Make sure your passkey is saved and available on another device if needed.",
        {title: "Disable password sign-in?", action: "Disable password sign-in"},
      )) return;
      if (action === "enable-password" && !await window.sableConfirmAction(
        "You will be able to sign in with your existing password again.",
        {title: "Enable password sign-in?", action: "Enable password sign-in", tone: "neutral"},
      )) return;
      button.disabled = true;
      const csrf = root.dataset.csrfToken;
      let result;
      if (action === "register") {
        const name = root.querySelector("[data-passkey-name]").value.trim();
        if (!name) throw new Error("Enter a name for this passkey.");
        const options = await post(`/ui/profile/passkeys/begin?name=${encodeURIComponent(name)}`, csrf);
        const credential = await navigator.credentials.create({publicKey: creationOptions(options.publicKey)});
        result = await post("/ui/profile/passkeys/finish", csrf, serialize(credential));
      } else if (action === "login") {
        const options = await post("/auth/passkey/login/begin", csrf);
        const credential = await navigator.credentials.get({publicKey: requestOptions(options.publicKey)});
        result = await post(`/auth/passkey/login/finish?return_to=${encodeURIComponent(root.dataset.returnTo || "/")}`, csrf, serialize(credential));
      } else if (action === "remove") {
        result = await post(`/ui/profile/passkeys/remove?id=${encodeURIComponent(button.dataset.passkeyId)}`, csrf);
      } else if (action === "enable-password") {
        result = await post("/ui/profile/password/enable", csrf);
      } else if (action === "disable-password") {
        result = await post("/ui/profile/password/disable", csrf);
      }
      if (result?.redirect) window.location.assign(result.redirect);
    } catch (error) {
      status.textContent = error.name === "NotAllowedError" ? "Passkey request was canceled or timed out. You can try again." : error.message;
    } finally {
      button.disabled = false;
    }
  });
})();
