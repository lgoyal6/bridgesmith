#!/usr/bin/env bash
# One-command demo of bridgesmith against live public APIs (no credentials).
# Run: pnpm demo   (or: bash scripts/demo.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

B=$'\033[1m'; D=$'\033[2m'; G=$'\033[38;5;215m'; C=$'\033[38;5;79m'; R=$'\033[0m'
step(){ printf "\n${G}▎ %s${R}\n\n" "$1"; sleep 1; }
# run "<clean display>" -- <real command...>
run(){ local disp="$1"; shift; [ "$1" = "--" ] && shift; printf "${D}\$ ${R}${B}%s${R}\n" "$disp"; sleep 0.7; "$@"; sleep 1.2; }

[ -d dist ] || { printf "${D}building…${R}\n"; pnpm -s build; }

printf "${C}${B}bridgesmith${R} — an agent builds its own integrations, and certifies them before it trusts them.\n"
sleep 1.4

step "1 · forge a connector for Chess.com from its own API"
run "bridgesmith forge chesscom --derive <10 players> --holdout <8 players> --host chess.com" -- \
  node dist/cli/index.js forge chesscom \
  --derive "https://api.chess.com/pub/player/magnuscarlsen,https://api.chess.com/pub/player/hikaru,https://api.chess.com/pub/player/fabianocaruana,https://api.chess.com/pub/player/gothamchess,https://api.chess.com/pub/player/anishgiri,https://api.chess.com/pub/player/danielnaroditsky,https://api.chess.com/pub/player/vishyanand,https://api.chess.com/pub/player/wesley_so,https://api.chess.com/pub/player/lachesisq,https://api.chess.com/pub/player/levonaronian" \
  --holdout "https://api.chess.com/pub/player/chessbrah,https://api.chess.com/pub/player/gmwso,https://api.chess.com/pub/player/nihalsarin2004,https://api.chess.com/pub/player/firouzja2003,https://api.chess.com/pub/player/lyonbeast,https://api.chess.com/pub/player/rpragchess,https://api.chess.com/pub/player/polish_fighter3000,https://api.chess.com/pub/player/chesswarrior7197" \
  --host chess.com --min-required 8

step "2 · call it on a player it never saw during certification"
run "bridgesmith call chesscom get_pub_player_player_id --param player_id=levyrozman" -- \
  node dist/cli/index.js call chesscom get_pub_player_player_id --param player_id=levyrozman

step "3 · forge a second connector — Devpost — the same way"
run "bridgesmith forge devpost --derive <pages 1-6> --holdout <pages 7-10> --host devpost.com" -- \
  node dist/cli/index.js forge devpost \
  --derive "https://devpost.com/api/hackathons?page=1,https://devpost.com/api/hackathons?page=2,https://devpost.com/api/hackathons?page=3,https://devpost.com/api/hackathons?page=4,https://devpost.com/api/hackathons?page=5,https://devpost.com/api/hackathons?page=6" \
  --holdout "https://devpost.com/api/hackathons?page=7,https://devpost.com/api/hackathons?page=8,https://devpost.com/api/hackathons?page=9,https://devpost.com/api/hackathons?page=10" \
  --host devpost.com --min-required 4

step "4 · the registry — every mounted connector carries a signed certificate"
run "bridgesmith list" -- node dist/cli/index.js list

step "5 · runtime: when an app drifts, it re-certifies and hot-swaps — or refuses"
run "bridgesmith heal-demo" -- pnpm -s tsx scripts/selfheal-proof.ts

printf "\n${C}${B}Certification is the gate. It never serves what it can't prove.${R}\n"
printf "${D}github.com/lgoyal6/bridgesmith${R}\n\n"
sleep 1
