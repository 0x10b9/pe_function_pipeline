## Function 0x1400011d0
- Fixture ground truth (evaluation only): `persist_run_key`, designed as **suspicious**
- CFG: 11 basic blocks, 55 instructions, 225 bytes
- Step 2 (random_init_gcn_standin, trained=False): rank 922 / 949, importance -0.000018, NOT in top-5
- Step 3 - import calls and recovered arguments:
  - `RegOpenKeyExA` @ 0x140001216 (advapi32.dll): hKey='HKEY_CURRENT_USER', lpSubKey='Software\\Microsoft\\Windows\\CurrentVersion\\Run', ulOptions='0', samDesired='2', phkResult='&local(rbp-0x10)'
  - `lstrlenA` @ 0x140001242 (kernel32.dll): lpString='C:\\Users\\Public\\updater.exe'
  - `RegSetValueExA` @ 0x14000126c (advapi32.dll): hKey='<unknown>', lpValueName='SystemUpdater', Reserved='0', dwType='1', lpData='C:\\Users\\Public\\updater.exe', cbData='<unknown>'
  - `RegCloseKey` @ 0x140001279 (advapi32.dll): (no args recovered)
- Step 4 - verdict: **suspicious**  (categories: persistence)
  - [suspicious] persistence.autorun_registry via `RegOpenKeyEx` @ 0x140001216: touches an autorun registry key (lpSubKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
  - [suspicious] persistence.autorun_registry via `RegSetValueEx` @ 0x14000126c: autorun target in a user-writable directory (lpData = 'C:\\Users\\Public\\updater.exe')

## Metrics (k=5)
- precision@k of model top-k vs verifier `suspicious`: 0.00 (hits 0 of 3 positives)
- baseline random-k precision: 0.0037; largest-k precision: 0.00
- fidelity: logit drop 0.000763 when top-k removed vs 0.000000 for random-k (std 0.000029)


- verifier sanity on fixture: 5/5 correct; `suspicious` outside fixture: 0