#!/usr/bin/env python3
"""Verify real linked PE resources, not just source icon references."""
import pathlib,struct,sys
b=pathlib.Path(sys.argv[1]).read_bytes()
pe=struct.unpack_from('<I',b,60)[0]
machine,ns=struct.unpack_from('<HH',b,pe+4)
assert machine==0x8664,'Expected x64 PE'
sz=struct.unpack_from('<H',b,pe+20)[0];opt=pe+24
assert struct.unpack_from('<H',b,opt)[0]==0x20b,'Expected PE32+'
rva=struct.unpack_from('<I',b,opt+128)[0]
sections=[]
for i in range(ns):
 o=opt+sz+40*i;vs,va,rawsz,raw=struct.unpack_from('<IIII',b,o+8)
 sections.append((va,va+max(vs,rawsz),raw))
def off(rva):
 for a,z,r in sections:
  if a<=rva<z:return r+rva-a
 raise ValueError('Invalid resource RVA')
base=off(rva)
def directory(rel):
 a=base+rel;n,m=struct.unpack_from('<HH',b,a+12)
 return dict(struct.unpack_from('<II',b,a+16+8*i) for i in range(n+m))
def data(typ,rid):
 group=directory(directory(0)[typ]&0x7fffffff)
 lang=directory(group[rid]&0x7fffffff)
 entry=next(iter(lang.values()));a=base+entry
 addr,size=struct.unpack_from('<II',b,a);a=off(addr);return b[a:a+size]
root=directory(0)
assert {3,14,24}<=root.keys(),'Missing ICON/GROUP_ICON/MANIFEST'
group=data(14,next(iter(directory(root[14]&0x7fffffff))))
assert struct.unpack_from('<HHH',group)==(0,1,7),'Expected seven icon sizes'
manifest=data(24,1)
assert b'level="requireAdministrator"' in manifest,'GUI must always run elevated (since 4.4.1)'
assert b'PerMonitorV2' in manifest
print('PASS: native WPF apphost x64, seven-size icon, requireAdministrator, PerMonitorV2')
