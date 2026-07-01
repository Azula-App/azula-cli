# playground

This is a throwaway shell running inside a Docker container, reachable from the
azula app over iroh — no SSH, no open ports, end-to-end encrypted.

Things to try:

    ls -al
    tree
    cat notes.txt
    curl -s https://azula.app/health
    git --version
    top   (q to quit)

Everything here is ephemeral — restart the container for a clean slate.
