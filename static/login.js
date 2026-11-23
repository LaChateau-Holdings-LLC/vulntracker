fetch("/api/auth").then((response) => response.json()).then((settings) => {
  document.getElementById("login-link").textContent = "Sign in with " + settings.provider;
}).catch(() => {});
