#!/bin/sh

set -a
[ -f .env ] && . .env
set +a

TARGET=${1:-help}

CURRENT_WORKING_DIR=$(pwd)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_CMD=${COMPOSE_CMD:-"docker compose"}

# Screen session names
MAIN_SCREEN=main-docker-$BLOCKCHAIN
WORKER1_SCREEN=poller-$BLOCKCHAIN
WORKER2_SCREEN=peer-$BLOCKCHAIN
WORKER3_SCREEN=export-$BLOCKCHAIN

target_help() {
    echo "Usage: $0 {init|clear|help}"
    echo
    echo "Targets:"
    echo "  init    Start docker stack and workers in separate screen sessions."
    echo "  clear   Kill all screen sessions and stop docker containers."
    echo "  help    Show this help message."
}

target_init() {
    echo "Starting Docker stack in screen: $MAIN_SCREEN"
    cd "$SCRIPT_DIR" || exit 1

    # main stack (docker-compose up)
    screen -dmS "$MAIN_SCREEN" \
        bash -lc "cd '$SCRIPT_DIR' && $COMPOSE_CMD up --build"

    echo "Starting poller in screen: $WORKER1_SCREEN"
    screen -dmS "$WORKER1_SCREEN" \
        bash -lc "sleep 60 && cd '$SCRIPT_DIR' && $COMPOSE_CMD run --rm app python -m workers.poller"

    echo "Starting peer scanner in screen: $WORKER2_SCREEN"
    screen -dmS "$WORKER2_SCREEN" \
        bash -lc "sleep 10 && cd '$SCRIPT_DIR' && $COMPOSE_CMD run --rm app python -m workers.peer_scanner"

    echo "Starting exporter in screen: $WORKER3_SCREEN"
    screen -dmS "$WORKER3_SCREEN" \
        bash -lc "sleep 60 && cd '$SCRIPT_DIR' && $COMPOSE_CMD run --rm app python -m workers.export_scanned_csv"

    echo
    echo "Screen sessions created:"
    echo "  $MAIN_SCREEN"
    echo "  $WORKER1_SCREEN"
    echo "  $WORKER2_SCREEN"
    echo "  $WORKER3_SCREEN"
    echo
    echo "Attach with:  screen -r $MAIN_SCREEN   (or worker-* names)"
}

target_clear() {
    echo "Stopping docker stack..."
    cd "$SCRIPT_DIR" || exit 1
    $COMPOSE_CMD down || true

    echo "Killing all screen sessions..."
    for session in "$MAIN_SCREEN" "$WORKER1_SCREEN" "$WORKER2_SCREEN" "$WORKER3_SCREEN"; do
        screen -S "$session" -X quit 2>/dev/null || true
    done

    echo "Done."
}

case "$TARGET" in
    init)
        target_init
        ;;
    clear)
        target_clear
        ;;
    help)
        target_help
        ;;
    *)
        target_help
        exit 1
        ;;
esac