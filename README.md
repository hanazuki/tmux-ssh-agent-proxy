# tmux-ssh-agent-proxy

A proxy server for SSH agent protocol that forwards signing requests from the applications under a tmux server to the SSH agent for the active tmux client. Useful when you have multiple SSH sessions from different devices that simultaneously connect to a single workstation and share a long-running tmux session there.
