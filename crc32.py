#!/usr/bin/env python3
import zlib
import os.path
import sys
from typing import TextIO
def exitusage(code: int=1, out: TextIO=sys.stderr):
  out.write("Usage: "+_prog()+" [OPTION...] <FILE...>\n")
  out.write("Print CRC32 checksums.\n")
  out.write("When FILE is -, read standard input.\n")
  out.write("Options:\n")
  out.write("      --help        display this help and exit\n")
  exit(code)
def main() -> None:
  args = sys.argv[1:]
  while len(args) > 0 and args[0].startswith("-") and args[0] != "-":
    opt = args.pop(0)
    if opt == "--":
      break
    elif opt == "--help":
      exitusage(code=0, out=sys.stdout)
    else:
      sys.stderr.write(_prog()+": invalid option '"+opt+"'\n")
      sys.stderr.write("\n")
      exitusage()
  if len(args) == 0:
    exitusage()
  ret = 0
  for fn in args:
    try:
      crc = CRC32()
      with (open(fn, "rb") if fn != "-" else sys.stdin.buffer) as f:
        while True:
          chunk = f.read(131072)
          if len(chunk) > 0:
            crc.update(chunk)
          else:
            break
      print(crc.lhex()+"  "+fn)
    except OSError as exc:
      ret = 1
      sys.stderr.write(_prog()+": "+fn+": "+(exc.strerror or str(exc))+"\n")
  exit(ret)
class CRC32:
  def __init__(self, data: bytes = b""):
    self._crc = zlib.crc32(data)
  def update(self, data: bytes) -> None:
    self._crc = zlib.crc32(data, self._crc)
  def lhex(self) -> str:
      # lhex = lowercase hex
    return _lhex32(self._crc)
  def uhex(self) -> str:
      # uhex = uppercase hex
    return _uhex32(self._crc)
  def uint(self) -> int:
      # uint = unsigned int
    return _uint32(self._crc)
  def sint(self) -> int:
      # sint = signed int
    return _sint32(self._crc)
def _lhex32(x: int) -> str:
  return ("%08x" % _uint32(x)).lower()
def _uhex32(x: int) -> str:
  return ("%08x" % _uint32(x)).upper()
def _uint32(x: int) -> int:
  if x >= 0 and x < 0x100000000:
    return x
  elif x >= -0x80000000 and x < 0:
    return 0x100000000 + x
  else:
    raise Exception("argument out of range: "+str(x))
def _sint32(x: int) -> int:
  if x >= -0x80000000 and x < 0x80000000:
    return x
  elif x >= 0x80000000 and x < 0x100000000:
    return x - 0x100000000
  else:
    raise Exception("argument out of range: "+str(x))
def _prog() -> str:
  return os.path.basename(sys.argv[0])
if __name__=="__main__":
  main()
