const form = document.getElementById("login-form"),
  error = document.getElementById("login-error");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = form.querySelector("button");
  submit.disabled = true;
  error.textContent = "";
  try {
    const session = await (
      await fetch("/auth/session", { cache: "no-store" })
    ).json();
    const values = new FormData(form);
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: values.get("username"),
        password: values.get("password"),
        csrf: session.csrf,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Sign-in failed");
    location.assign("/");
  } catch (failure) {
    error.textContent = failure.message;
  } finally {
    submit.disabled = false;
  }
});
