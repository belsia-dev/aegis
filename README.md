```
   _____                .___        
  /  _  \   ____   ____ |   | ______
 /  /_\  \_/ __ \ / ___\|   |/  ___/
/    |    \  ___// /_/  >   |\___ \ 
\____|__  /\___  >___  /|___/____  >
        \/     \/_____/          \/ 
```
# Aegis : Advanced Firewall, designed to ban multiple hosts that is causing problems.
--

Aegis is a modern version of a fail2ban in which contains much more patterns and the diefference is that aegis has real time monitor ( web gui) and fail2ban doesn't. Aegis normally scans logs like /var/log/auth.log and bans ips that exceed the maximum threat score.

# HOW It works

Aegis basically scans logs that are pre setted in the config and ban the suspicious ips. It normally uses a score system in which as the attack is going on, the more the threat score it gets. If it goes over 100, it bans ip With "IPTABLES". 
--
# HOW TO INSTALL

## Requirements

- Linux server
- Python 3.10 or newer
- `python3-venv`
- `iptables` or `nftables`
- Root access for firewall control and system log monitoring

## 1. Prepare the Project

```bash
cd /path/to/aegis
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 2. Create Directories

```bash
sudo mkdir -p /etc/aegis
sudo mkdir -p /var/log/aegis
```

## 3. Copy the Config

```bash
sudo cp config.example.yaml /etc/aegis/config.yaml
```

Open `/etc/aegis/config.yaml` and change at least these values before production use:

- `api.username`
- `api.password`
- `whitelist.ips`
- `response.firewall_backend`
- `response.privilege_mode`

## 4. Run in Dry-Run Mode First

```bash
source venv/bin/activate
python main.py --config /etc/aegis/config.yaml --dry-run
```

The web UI starts on `http://127.0.0.1:8731` unless you change the API host or port in the config.

## 5. Run Normally

```bash
source venv/bin/activate
python main.py --config /etc/aegis/config.yaml
```

## 6. Install as a Systemd Service

```bash
sudo mkdir -p /opt/aegis
sudo cp -R . /opt/aegis
cd /opt/aegis
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
sudo cp config.example.yaml /etc/aegis/config.yaml
sudo cp aegis.service /etc/systemd/system/aegis.service
sudo systemctl daemon-reload
sudo systemctl enable --now aegis
sudo systemctl status aegis
```

## 7. Optional Shell Guard

To load the shell wrapper for interactive sessions:

```bash
sudo cp scripts/aegis_guard.sh /etc/profile.d/aegis_guard.sh
sudo chmod 644 /etc/profile.d/aegis_guard.sh
```

## Notes

- Run the service as `root` if you want direct firewall access with the default configuration.
- If you change `response.privilege_mode` to `sudo`, make sure the runtime user has non-interactive sudo permission for the required firewall commands.
- Default dashboard credentials come from `/etc/aegis/config.yaml`.

Protect Your Server Well!