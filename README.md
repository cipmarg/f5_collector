# F5 jump collector

Local Python collector that:
- opens one persistent SSH session to a Linux jump host
- reuses that session to SSH to F5 devices one by one
- captures raw command output locally
- parses the output with TextFSM locally
- writes parsed data to CSV and optionally to a SQL database

## Files
- `main.py` - collector
- `inventory.yaml` - example inventory
- `requirements.txt` - Python dependencies
- `templates/` - put your TextFSM templates here
- `out/` - CSV and raw outputs land here

## Expected TextFSM templates
Copy these into `templates/`:
- `textfsm_template_list_ltm_virtual.textfsm`
- `textfsm_template_list_sys_crypto_key.textfsm`
- `textfsm_template_list_sys_file_ssl-cert_all-properties.textfsm`
- `textfsm_template_show_cm_failover-status.textfsm`
- `textfsm_template_show_ltm_node.textfsm`
- `textfsm_template_show_ltm_virtual_raw_field-fmt.textfsm`
- `textfsm_template_show_sys_provision_asm.textfsm`
- `textfsm_template_show_sys_version.textfsm`

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python3 main.py --inventory inventory.yaml --templates-dir templates --out-dir out
```

## Optional DB load
Set a DB URL and the script will also append to SQL tables.

Example PostgreSQL:
```bash
export DB_URL='postgresql+psycopg2://user:pass@127.0.0.1:5432/f5model'
python3 main.py --inventory inventory.yaml --templates-dir templates --out-dir out
```

## Notes
- The script disables shell history in the remote shell session where possible.
- The F5 password is prompted locally and exported only inside the jump-host shell session.
- The jump-host SSH password is also prompted locally unless `JUMP_SSH_PASS` is already set.
- Downstream device first-contact host keys are handled with `ssh-keyscan` and `StrictHostKeyChecking=accept-new`.
- Raw stdout/stderr is saved under `out/raw/<run_id>/` for troubleshooting.

## Cron example
This runs locally and logs to a file.
```bash
0 * * * * /path/to/venv/bin/python /path/to/f5_jump_collector/main.py --inventory /path/to/f5_jump_collector/inventory.yaml --templates-dir /path/to/f5_jump_collector/templates --out-dir /path/to/f5_jump_collector/out >> /path/to/f5_jump_collector/collector.log 2>&1
```

For cron, it is usually better to set `JUMP_SSH_PASS` and `F5_SSH_PASS` from a protected wrapper script rather than rely on interactive prompts.
