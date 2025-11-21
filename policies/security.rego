package main

# ------------------------------------------------------------
# RULE 1 — Disallow FROM using :latest (your working version)
# ------------------------------------------------------------
deny contains msg if {
    input[i].Cmd == "from"
    val := split(input[i].Value[_], ":")
    contains(lower(val[_]), "latest")
    msg := sprintf("Line %d: Do not use 'latest' tag for base images. Pin to a specific version.", [i])
}

# ------------------------------------------------------------
# RULE 2 — Disallow USER root (root user not allowed)
# ------------------------------------------------------------
deny contains msg if {
    input[i].Cmd == "user"
    usr := lower(input[i].Value[_])
    contains(usr, "root")
    msg := sprintf("Line %d: Do not run container as root user.", [i])
}

# ------------------------------------------------------------
# RULE 3 — Require USER instruction (if missing → default root)
# ------------------------------------------------------------
deny contains msg if {
    not user_instruction_present
    msg := "Dockerfile missing USER instruction — defaults to root user which is insecure."
}

user_instruction_present if {
    some i
    input[i].Cmd == "user"
}

# ------------------------------------------------------------
# RULE 4 — Warn about ADD usage (soft warning, not blocking)
# ------------------------------------------------------------
warn contains msg if {
    input[i].Cmd == "add"
    msg := sprintf("Line %d: Avoid using ADD — prefer COPY unless necessary.", [i])
}
