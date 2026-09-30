#!/usr/bin/env python3
"""Separate private-chat issuer. No shared alert-bot polling, no logging tokens/QR URLs."""
import base64,hashlib,hmac,io,json,logging,os,pathlib,secrets,sqlite3,time,urllib.error,urllib.parse,urllib.request
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import qrcode
log=logging.getLogger('activation-issuer');logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
def credential(name):
 p=pathlib.Path(os.environ.get('CREDENTIALS_DIRECTORY','/etc/chameleon/activation'))/name
 b=p.read_bytes().strip()
 if not b:raise RuntimeError('Missing issuer credential')
 return b
class Bot:
 def __init__(self):
  self.token=credential('telegram_token').decode();self.key=load_pem_private_key(credential('issuer_key'),None)
  if not isinstance(self.key,Ed25519PrivateKey):raise RuntimeError('Ed25519 issuer required')
  self.salt=credential('privacy_salt');self.kid=os.environ['ACTIVATION_KID'];self.origin=os.environ['PUBLIC_ORIGIN'].rstrip('/')
  if not self.origin.startswith('https://') or urllib.parse.urlsplit(self.origin).path:raise RuntimeError('HTTPS origin required')
  data=pathlib.Path(os.environ.get('STATE_DIRECTORY','/var/lib/chameleon-issuer'));data.mkdir(parents=True,exist_ok=True);self.db=sqlite3.connect(data/'issuer.sqlite3')
  self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, token TEXT NOT NULL, expires INTEGER NOT NULL, last_sent INTEGER NOT NULL)');self.db.execute('CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value INTEGER NOT NULL)');self.db.commit()
 def api(self,method,body,timeout=45):
  url='https://api.telegram.org/bot'+self.token+'/'+method
  req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
  try:
   with urllib.request.urlopen(req,timeout=timeout) as r:result=json.load(r)
  except urllib.error.HTTPError as e:raise RuntimeError('Telegram HTTP '+str(e.code)) from None
  except Exception:raise RuntimeError('Telegram network unavailable') from None
  if not result.get('ok'):raise RuntimeError('Telegram API rejected request')
  return result.get('result')
 def photo(self,chat,png,caption):
  boundary='issuer-'+secrets.token_hex(16);parts=[]
  for n,v in [('chat_id',str(chat)),('caption',caption)]:parts.append(('--'+boundary+'\r\nContent-Disposition: form-data; name="'+n+'"\r\n\r\n'+v+'\r\n').encode())
  parts.append(('--'+boundary+'\r\nContent-Disposition: form-data; name="photo"; filename="activation.png"\r\nContent-Type: image/png\r\n\r\n').encode()+png+b'\r\n');parts.append(('--'+boundary+'--\r\n').encode())
  req=urllib.request.Request('https://api.telegram.org/bot'+self.token+'/sendPhoto',data=b''.join(parts),headers={'Content-Type':'multipart/form-data; boundary='+boundary},method='POST')
  try:
   with urllib.request.urlopen(req,timeout=30) as r:result=json.load(r)
   if not result.get('ok'):raise RuntimeError()
  except Exception:raise RuntimeError('QR delivery failed') from None
 def issue(self,sender):
  uid=hmac.new(self.salt,str(sender).encode(),hashlib.sha256).hexdigest()[:32];now=int(time.time());row=self.db.execute('SELECT token,expires,last_sent FROM users WHERE user_id=?',(uid,)).fetchone()
  if row and now-row[2]<30:return None
  if row and row[1]>now+24*3600:token,expires=row[:2]
  else:
   expires=now+30*24*3600;claims={'version':1,'aud':'chameleon-free-vpn','kid':self.kid,'user_id':uid,'plan':'free','issued_at':now,'expires_at':expires,'device_limit':2,'nonce':secrets.token_hex(16)};payload=json.dumps(claims,separators=(',',':')).encode();token=base64.urlsafe_b64encode(payload).decode().rstrip('=')+'.'+base64.urlsafe_b64encode(self.key.sign(payload)).decode().rstrip('=')
  self.db.execute('INSERT INTO users(user_id,token,expires,last_sent) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token,expires=excluded.expires,last_sent=excluded.last_sent',(uid,token,expires,now));self.db.commit();return token,expires
 def send_activation(self,chat,sender):
  result=self.issue(sender)
  if not result:return
  token,expires=result;url=self.origin+'/vpn/activate#token='+token
  qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=6,border=4);qr.add_data(url);qr.make(fit=True);buf=io.BytesIO();qr.make_image(fill_color='black',back_color='white').save(buf,format='PNG')
  self.photo(chat,buf.getvalue(),'Ваш персональный QR Chameleon. Бесплатный доступ: 2 устройства, 30 дней. Не пересылайте QR другим людям. Сначала установите приложение с сайта, затем откройте ссылку ниже.')
  self.api('sendMessage',{'chat_id':chat,'text':'Активация вашего устройства','reply_markup':{'inline_keyboard':[[{'text':'Открыть Chameleon','url':url}],[{'text':'Скачать Android / Windows','url':self.origin+'/vpn/'}]]}})
 def run(self):
  me=self.api('getMe',{},timeout=15);webhook=self.api('getWebhookInfo',{},timeout=15)
  if webhook.get('url'):raise RuntimeError('A webhook is already configured; refusing to steal updates')
  expected=os.environ.get('TELEGRAM_USERNAME','').lstrip('@')
  if expected.lower()=='citpvpndpibot' or me.get('username','').lower()=='citpvpndpibot':raise RuntimeError('The existing alert bot must not be used as an issuer')
  if not expected or me.get('username','').lower()!=expected.lower():raise RuntimeError('Bot identity mismatch or username not configured')
  runtime=pathlib.Path(os.environ.get('RUNTIME_DIRECTORY','/run/chameleon-issuer'))
  ready=runtime/'ready';tmp=runtime/'ready.tmp'
  tmp.write_text(json.dumps({'pid':os.getpid(),'ready_at':int(time.time())})+'\n')
  tmp.chmod(0o600);tmp.replace(ready)
  log.info('Separate activation issuer ready')
  row=self.db.execute('SELECT value FROM meta WHERE name=?',('offset',)).fetchone();offset=row[0] if row else 0
  while True:
   try:
    updates=self.api('getUpdates',{'timeout':25,'offset':offset,'allowed_updates':['message']},timeout=35)
    for u in updates:
     m=u.get('message',{});chat=m.get('chat',{});sender=m.get('from',{});text=m.get('text','').split(' ',1)[0].split('@',1)[0]
     if chat.get('type')=='private' and chat.get('id')==sender.get('id') and not sender.get('is_bot') and text in ['/start','/activate','/qr']:
      try:self.send_activation(chat['id'],sender['id'])
      except Exception:log.warning('Activation delivery failed; no credential content logged')
     offset=int(u['update_id'])+1;self.db.execute('INSERT INTO meta VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value',('offset',offset));self.db.commit()
   except Exception:log.warning('Telegram polling unavailable; retrying');time.sleep(10)
if __name__=='__main__':
 os.umask(0o077)
 try:Bot().run()
 except Exception:log.error('Issuer not started: check local private configuration and bot identity');raise SystemExit(1)
