#!/usr/bin/env bash
# One-command demo of bridgesmith against live public APIs (no credentials).
# Run: pnpm demo   (or: bash scripts/demo.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

B=$'\033[1m'; D=$'\033[2m'; G=$'\033[38;5;215m'; C=$'\033[38;5;79m'; R=$'\033[0m'
step(){ printf "\n${G}▎ %s${R}\n\n" "$1"; sleep 1.1; }
run(){ local disp="$1"; shift; [ "$1" = "--" ] && shift; printf "${D}\$ ${R}${B}%s${R}\n" "$disp"; sleep 0.8; "$@"; sleep 1.4; }

[ -d dist ] || { printf "${D}building…${R}\n"; pnpm build; }
rm -rf connectors/chesscom connectors/devpost connectors/imessage

printf "${C}${B}bridgesmith${R} — an agent builds its own integrations, and certifies them before it trusts them.\n"
sleep 1.6

step "1 · forge a connector for Chess.com from its own API"
run "bridgesmith forge chesscom --derive <10 players> --holdout <8 players> --host chess.com" -- \
  node dist/cli/index.js forge chesscom \
  --derive "https://api.chess.com/pub/player/magnuscarlsen,https://api.chess.com/pub/player/hikaru,https://api.chess.com/pub/player/fabianocaruana,https://api.chess.com/pub/player/gothamchess,https://api.chess.com/pub/player/anishgiri,https://api.chess.com/pub/player/danielnaroditsky,https://api.chess.com/pub/player/vishyanand,https://api.chess.com/pub/player/wesley_so,https://api.chess.com/pub/player/lachesisq,https://api.chess.com/pub/player/levonaronian" \
  --holdout "https://api.chess.com/pub/player/chessbrah,https://api.chess.com/pub/player/gmwso,https://api.chess.com/pub/player/nihalsarin2004,https://api.chess.com/pub/player/firouzja2003,https://api.chess.com/pub/player/lyonbeast,https://api.chess.com/pub/player/rpragchess,https://api.chess.com/pub/player/polish_fighter3000,https://api.chess.com/pub/player/chesswarrior7197" \
  --host chess.com --min-required 8

step "2 · the signed birth certificate it just minted"
run "bridgesmith inspect chesscom" -- bash -c "node dist/cli/index.js inspect chesscom | python3 -c 'import sys,json;d=json.load(sys.stdin);c=d[\"certificate\"];print(json.dumps({\"app\":c[\"app\"],\"tier\":c[\"tier\"],\"specHash\":c[\"specHash\"][:16]+\"…\",\"certifiedOps\":c[\"certifiedOps\"],\"mutationStats\":c[\"mutationStats\"],\"signature\":c[\"signature\"][:32]+\"…  (ed25519)\"}, indent=2))'"

step "3 · call it on a player it never saw during certification"
run "bridgesmith call chesscom get_pub_player_player_id --param player_id=levyrozman" -- \
  bash -c "node dist/cli/index.js call chesscom get_pub_player_player_id --param player_id=levyrozman | python3 -c 'import sys,json;d=json.load(sys.stdin)[\"data\"];print(json.dumps({\"username\":d[\"username\"],\"name\":d.get(\"name\"),\"followers\":d[\"followers\"],\"status\":d[\"status\"]},indent=2))'"

step "4 · forge a second app — Devpost — the same way"
run "bridgesmith forge devpost --derive <pages 1-6> --holdout <pages 7-10> --host devpost.com" -- \
  node dist/cli/index.js forge devpost \
  --derive "https://devpost.com/api/hackathons?page=1,https://devpost.com/api/hackathons?page=2,https://devpost.com/api/hackathons?page=3,https://devpost.com/api/hackathons?page=4,https://devpost.com/api/hackathons?page=5,https://devpost.com/api/hackathons?page=6" \
  --holdout "https://devpost.com/api/hackathons?page=7,https://devpost.com/api/hackathons?page=8,https://devpost.com/api/hackathons?page=9,https://devpost.com/api/hackathons?page=10" \
  --host devpost.com --min-required 4

step "5 · one connector, two surfaces — serve it as a REST API and call it"
node dist/cli/index.js serve devpost --port 8799 >/dev/null 2>&1 & SRV=$!
sleep 1.8
run "curl localhost:8799/manifest" -- bash -c "curl -s localhost:8799/manifest | python3 -m json.tool"
run "curl -X POST localhost:8799/op/get_api_hackathons -d '{\"page\":\"12\"}'" -- \
  bash -c "curl -s -X POST localhost:8799/op/get_api_hackathons -H 'content-type: application/json' -d '{\"page\":\"12\"}' | python3 -c 'import sys,json;r=json.load(sys.stdin);d=r.get(\"data\",{}).get(\"hackathons\",[]);[print(\"  •\", h[\"title\"]) for h in d[:5]] if d else print(\"  \",r)'"
kill $SRV 2>/dev/null || true

step "6 · give an app with NO network API a connector — iMessage, from its local database"
run "bridgesmith forge imessage --tier local-store" -- pnpm exec tsx scripts/imessage-demo.ts

step "7 · the registry — three connectors, two access tiers, each with a signed certificate"
run "bridgesmith list" -- node dist/cli/index.js list

step "8 · runtime: when an app drifts, it re-certifies and hot-swaps — or refuses"
run "bridgesmith heal-demo" -- pnpm exec tsx scripts/selfheal-proof.ts

printf "\n${C}${B}Certification is the gate. It never serves what it can't prove.${R}\n"
printf "${D}github.com/lgoyal6/bridgesmith${R}\n\n"
sleep 1.2
