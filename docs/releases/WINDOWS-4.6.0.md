# Chameleon VPN 4.6.0 beta — Windows x64

- New: «Российские сайты напрямую» (tab «Протокол», on by default, can be switched off while disconnected).
  Russian networks bypass the VPN and are reached from the user's own address; everything else, including
  foreign services, stays in the tunnel. Design and limitations: docs/RU-DIRECT.md.
  - Broker installs ~3.1k RU IPv4 prefixes (internal/rudirect, shared with Android 4.6.0) through the physical
    uplink via iphlpapi (CreateIpForwardEntry2, metric 6), more specific than the 0/1+128/1 capture; removed on
    disconnect, stale rows from a crashed broker are purged on the next connect.
  - DNS for Russian domains (.ru/.su/.рф/… + curated Yandex/VK/Sber/… domains) is resolved by Yandex DoH
    (77.88.8.8, direct); all other DNS stays on the in-tunnel resolver. Failures fall back to the tunnel.
  - IPC: optional `ru_direct` boolean in the connect request (absent = on). UI and broker ship together.
- Not Authenticode-signed; trust root is the HTTPS site + manifest SHA-256. Native Windows acceptance pending.
