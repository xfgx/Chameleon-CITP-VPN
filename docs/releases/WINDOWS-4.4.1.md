# Chameleon VPN 4.4.1 beta — Windows x64

Fixes after 4.4.0 field diagnostics (CITP `vpn.firewall` ChameleonFree-IPv6 E_INVALIDARG; KS `vpn.ks.handshake` sent=73 replies=0).

- Firewall: IPv6 block rule uses `::/1,8000::/1` (range fallback); DNS guard tries range form then CIDR list; per-rule COM ordering (ports before addresses), `New-NetFirewallRule` final fallback. Stage/HRESULT reporting unchanged.
- KS: node agent allocated slot 10, which ks-hub (11..250) silently skipped. Fixed in ks-admin source (slots from 11); the affected key was moved to slot 19 on the RU node without restarting other sessions.
- AUTO protocol (default): broker tries KS then CITP (last successful first); stops on activation or Wintun integrity errors. Existing CITP/KS FULL cores are reused unchanged.
- UI: fixed 900x620 non-resizable window without scrolling (Viewbox scales down on small screens), close hides to tray (tray menu Open/Connect/Exit), single instance.
- App manifest `requireAdministrator`; one-time consent lists system changes; app starts BFE, MpsSvc and ChameleonBroker and checks wintun.dll. Broker manifest stays asInvoker (service runs as LocalSystem).
- Not Authenticode-signed. Linux cross-build + source tests only; no native Windows acceptance claimed.
