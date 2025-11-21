package main

deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value[0] // Get the image name and tag
    contains(lower(val), ":latest") // Check if the tag is 'latest'
    msg = sprintf("Do not use 'latest' tag for base images: %s", [val])
}