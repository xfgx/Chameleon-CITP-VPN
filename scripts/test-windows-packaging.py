#!/usr/bin/env python3
"""Offline source regression checks. Native Windows acceptance is separate."""
from pathlib import Path
import unittest
root=Path(__file__).resolve().parents[1]
class PackagingTests(unittest.TestCase):
 def test_no_shell_service_registration(self):
  s=(root/'packaging/windows/chameleon.nsi').read_text()
  self.assertNotIn('sc.exe',s.replace('; A native x64 helper avoids sc.exe WOW64 redirection and nested binPath quotes.',''))
  for action in ('stop','install','start','remove'):self.assertIn('-action '+action,s)
 def test_notice_layout(self):
  s=(root/'packaging/windows/chameleon.nsi').read_text()
  self.assertIn('SetOutPath "$INSTDIR\\licenses"',s)
  self.assertIn('SetOutPath "$INSTDIR\\docs"',s)
  self.assertIn('SetOutPath "$INSTDIR\\tools"',s)
  self.assertIn('DisplayIcon',s)
 def test_native_scm_and_ownership(self):
  s=(root/'cmd/vpn-service-setup/main_windows.go').read_text()
  for token in ('m.CreateService(', 'syscall.EscapeArg(exe)', 'unrelated ChameleonBroker', 'windows.SetSecurityInfo', 'filepath.EvalSymlinks', 'func wait('):self.assertIn(token,s)
 def test_app_icon_and_nonadmin_manifest(self):
  import struct
  data=(root/'packaging/windows/assets/chameleon.ico').read_bytes()
  self.assertEqual(struct.unpack_from('<HHH',data),(0,1,7))
  self.assertIn('level="asInvoker"',(root/'packaging/windows/assets/chameleon.manifest').read_text())
  self.assertIn('SmallIcon: windows.Handle(smallIcon)',(root/'cmd/chamd/gui_windows.go').read_text())
if __name__=='__main__':unittest.main()
