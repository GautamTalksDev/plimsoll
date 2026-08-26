# Copying this scaffold

This directory is a complete starter for the public repo `GautamTalksDev/plimsoll-log`.

```bash
# From the plimsoll checkout:
cp -a scaffold/plimsoll-log/. /path/to/plimsoll-log/
cd /path/to/plimsoll-log
# Replace keys/log-public.pem (see keys/README.md)
# Set Actions secret LOG_SIGNING_KEY
# Pin PLIMSOLL_RELEASE in .github/workflows/append.yml after the first release
# that includes plimsoll-append and plimsoll-static
git init
git add .
git commit -s -m "initial empty plimsoll log"
git remote add origin git@github.com:GautamTalksDev/plimsoll-log.git
git push -u origin main
```

Do not copy this folder into the main plimsoll git history as the live log; it is a template only.
