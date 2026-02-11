# Connector-Based Passive Data Gathering Setup

This setup assumes an Ubuntu-based operating system.  
The experiment requires  
(i) a working Docker installation, and  
(ii) the `screen` tool for managing multiple concurrent workflows.  

Docker may be installed by following the official guide at:  
https://docs.docker.com/engine/install/ubuntu/

---

## Installing Required Dependencies

The connector implementation requires only minimal system-level tooling.

**Install system package:**

```bash
sudo apt install screen
```

---

## Repository Setup

Clone the repository and enter the project directory:

```bash
git clone https://github.com/DogukanBaysal/Bitcoin-Fork-Connector
cd Bitcoin-Fork-Connector
```

The entry point for executing the connector is the script `prepare-experiment.sh`,  
which initializes multiple `screen` sessions responsible for different components  
of the workflow.

---

## Running the Experiment

- Initialize the experiment environment, create screen sessions, and start the connector system:

```bash
bash prepare-experiment.sh init
```

Each workflow runs inside its own dedicated GNU Screen session.  
Available screen sessions can be listed with:

```bash
screen -ls
```

To attach to a specific workflow, use:

```bash
screen -r <screen-name>
```

---

## Example: Screen Sessions for the Connector

When the experiment is initialized, the following screen sessions are created automatically.  
Each session corresponds to a specific workflow component:

- **`main-docker-<blockchain_name>`**: starts the Docker-based system, including the PostgreSQL database and all supporting containers.
- **`poller-<blockchain_name>`**:  
  runs the port checking component that checks whether discovered peer IPs are reachable.
- **`peer-<blockchain_name>`**:  
  runs the peer scanner component, which handshakes with active peers and retrieves peer lists.
- **`export-scanned-<blockchain_name>`**:  
  periodically exports scanned IP information to a CSV file in a human-readable format.
- **`export-checked-<blockchain_name>`**:  
  periodically exports checked IP information (snapshot of discovered unique IPs) to a CSV file in a human-readable format.

---

## Environment Variables

The connector experiment is configured through two `.env` files.  
The parameters are described below.

First, a `.env` file must be located in the root directory of the project and contain a single parameter `BLOCKCHAIN`.  
This variable specifies which blockchain is being analyzed and allows differentiating between multiple experiments running on the same machine.

Second, a separate `.env` file is used for configuring the experiment parameters and is located inside the `app` directory.

---

### Network Settings

- **`MAGIC`** — Magic bytes of the blockchain being monitored.
- **`PORT`** — Port number used by nodes for P2P communication.

---

### Poller Configuration

- **`POLL_MAX_WORKERS`** — Maximum number of worker threads running in parallel.
- **`POLL_BATCH_SIZE`** — Number of IPs assigned to each worker per batch.
- **`POLL_MAX_FETCH`** — Maximum number of IPs fetched from the database per cycle.
- **`POLL_CONNECT_TIMEOUT`** — Timeout (seconds) for marking an IP:port pair as inactive.
- **`POLL_STALE_AFTER_HOURS`** — Cache expiration window; IPs older than this must be rechecked.
- **`POLL_STATE_FILE`** — File storing the last processed database ID.
- **`POLL_INTERVAL_SECONDS`** — Time interval between poller cycles.

---

### Checked IP Exporter Configuration

- **`EXPORT_CHECKED_FILE`** — Output CSV file containing exported checked IPs.
- **`EXPORT_CHECKED_INTERVAL_SECONDS`** — Time interval between exporter cycles.

---

### Scanned IP Exporter Configuration

- **`EXPORT_FILE`** — Output CSV file containing exported scanned IPs.
- **`EXPORT_STATE_FILE`** — File storing the last exported scan ID.
- **`EXPORT_INTERVAL_SECONDS`** — Time interval between exporter cycles.
- **`EXPORT_FETCH_LIMIT`** — Maximum number of records exported per cycle.

---

### Peer Scanner Configuration

- **`SCAN_IPS_FILE`** — File containing seed IPs in `ip:port` format.
- **`ACTIVE_IPS_CSV`** — Output CSV file storing active IPs each cycle.
- **`SCAN_INTERVAL_SECONDS`** — Time interval between scanning cycles.
- **`SCAN_CHECKED_ACTIVE_LIMIT`** — Number of IPs cycled each round.
- **`SCAN_MAX_WORKERS`** — Maximum number of scanner threads.
- **`SCAN_BATCH_SIZE`** — Number of IPs each worker thread handles.
- **`SCAN_INSERT_CHUNK_SIZE`** — Size of batch inserts into the database.
- **`MAX_AGE_HOURS`** — Minimum number of hours between repeated handshakes to the same IP address.

---

## Example `.env` Configuration

Example configuration files for monitoring Bitcoin are shown below.

### Root `.env`

```env
BLOCKCHAIN=bitcoin
```

### `app/.env`

```env
MAGIC=0xf9beb4d9
PORT=8333

POLL_BATCH_SIZE=200
POLL_MAX_FETCH=10000
POLL_MAX_WORKERS=25
POLL_CONNECT_TIMEOUT=2.0
POLL_STALE_AFTER_HOURS=2
POLL_STATE_FILE=state/last_ip_list_id.txt
POLL_INTERVAL_SECONDS=5

EXPORT_FILE=exports/scanned_ips.csv
EXPORT_STATE_FILE=state/last_scanned_export_id.txt
EXPORT_INTERVAL_SECONDS=10
EXPORT_FETCH_LIMIT=1000000

EXPORT_CHECKED_FILE=exports/checked_ips.csv
EXPORT_CHECKED_INTERVAL_SECONDS=21600

SCAN_IPS_FILE=targets/peers.txt
ACTIVE_IPS_CSV=exports/active_checked_ips.csv
SCAN_INTERVAL_SECONDS=600
SCAN_CHECKED_ACTIVE_LIMIT=10000
SCAN_MAX_WORKERS=10
SCAN_BATCH_SIZE=50
SCAN_INSERT_CHUNK_SIZE=1000
MAX_AGE_HOURS=24
```
