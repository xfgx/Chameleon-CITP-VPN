#!/usr/bin/env python3
from pathlib import Path
import unittest
root=Path(__file__).resolve().parents[1]
class IPCTests(unittest.TestCase):
 def test_read_before_identity_before_action(self):
  s=(root/'cmd/chamd/broker_windows.go').read_text();s=s[s.index('func handleBroker'):s.index('type productService')]
  self.assertLess(s.index('c.Receive(&request)'),s.index('c.ClientSID()'))
  self.assertLess(s.index('c.ClientSID()'),s.index('switch request.Command'))
 def test_no_premature_identity_on_accept(self):
  s=(root/'internal/winipc/pipe_windows.go').read_text();s=s[s.index('func Listen'):s.index('type serviceStatus')]
  self.assertNotIn('clientSID(',s)
 def test_local_pipe_and_server_verification_remain(self):
  s=(root/'internal/winipc/pipe_windows.go').read_text()
  for key in ['status.PID != pipePID','status.State != 4','PROCESS_QUERY_LIMITED_INFORMATION','trustedServer(handle)','SECURITY_IDENTIFICATION','0x00000008']:
   self.assertIn(key,s)
 def test_service_ready_before_running(self):
  s=(root/'cmd/chamd/broker_windows.go').read_text();s=s[s.index('func (productService) Execute'):]
  self.assertLess(s.index('case <-ready:'),s.index('State: svc.Running'))
if __name__=='__main__':unittest.main()
