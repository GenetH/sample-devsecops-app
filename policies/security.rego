package security

# -------------------------------
# RULE 1: Disallow root user
# -------------------------------
deny[msg] {
  some i
  input[i].Instruction == "USER"
  input[i].Value == "root"
  msg := "❌ Root user is not allowed in Docker images"
}

# Deny if no USER is specified at all (default = root)
deny[msg] {
  not user_defined
  msg := "❌ Dockerfile missing USER instruction; default user is root"
}

user_defined {
  some i
  input[i].Instruction == "USER"
}

# -------------------------------
# RULE 2: Disallow usage of :latest tag
# -------------------------------
deny[msg] {
  some i
  input[i].Instruction == "FROM"
  contains(input[i].Value, ":latest")
  msg := "❌ Do not use :latest tag in FROM instruction"
}

# Deny missing version tag
deny[msg] {
  some i
  input[i].Instruction == "FROM"
  not contains(input[i].Value, ":")
  msg := "❌ FROM must use explicit version tags (e.g., node:18)"
}
