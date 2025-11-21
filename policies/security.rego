package main

# Policy 1 — Disallow root user
deny[msg] {
  input.Config.User == "root"
  msg = "Running container as root is not allowed."
}

# Policy 2 — Disallow latest tag
deny[msg] {
  endswith(input.Image, ":latest")
  msg = "Avoid using the latest tag for images."
}
