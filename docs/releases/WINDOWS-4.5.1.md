# Chameleon VPN 4.5.1 beta — Windows x64

- Animated, responsive interface (same motion language as Android 4.5.4):
  - buttons: hover glow, press «sink» with a spring release, ripple from the pointer (from the centre for
    Space/Enter), smooth fade when a button becomes unavailable; captions cross-fade
    («Подключить VPN» → «Пожалуйста, подождите…» → «Отключить VPN»);
  - sections slide in from the direction of travel and their cards rise one after another; the selected-section
    marker in the sidebar slides to the new item; card borders light up under the pointer; start-up intro;
  - power mark: spinning arc while connecting/reconnecting, breathing rings while protected, colours flow between
    states, a short pop on connect and a shake on error;
  - status, diagnostics, protocol and update texts change with a short cross-fade; the connection progress line
    slides open; the download progress bar glides; repeated notices blink so a repeated click is visible.
- Responsiveness: «Подключить VPN» shows «Устанавливаем соединение» at once while the Windows service check runs;
  the button is locked during that check (no second check on a double click); a connect/disconnect is no longer
  dropped when it coincides with the 3-second status refresh.
- Follows «Show animations in Windows» (SystemParameters.ClientAreaAnimation): with animations off every change is
  instant. Endless animations run only while the window is visible and not minimized, at 30 fps, and not under
  software rendering.
- Broker, VPN core, KS/CITP, firewall, updater and activation vault are unchanged from 4.5.0.
- Not Authenticode-signed; trust root is the HTTPS site + manifest SHA-256. Native Windows acceptance pending.
