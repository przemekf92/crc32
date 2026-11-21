#!/usr/bin/env python3
import zlib
import hashlib
import os.path
import sys
from typing import Optional
def exitusage(code: int = 1, usestdout: bool = False):
  out = (sys.stderr if not usestdout else sys.stdout)
  out.write("Usage: "+_prog()+" [OPTION...] <FILE...>\n")
  out.write("Print CRC32 checksums.\n")
  out.write("When FILE is -, read standard input.\n")
  out.write("Options:\n")
  out.write("      --lhex        lowercase hexadecimal format (default)\n")
  out.write("      --uhex        uppercase hexadecimal format\n")
  out.write("      --uint        unsigned int decimal format\n")
  out.write("      --sint        signed int decimal format\n")
  out.write("      --md5         use MD5 instead of CRC32\n")
  out.write("      --sha1        use SHA1 instead of CRC32\n")
  out.write("      --sha256      use SHA256 instead of CRC32\n")
  out.write("      --help        display this help and exit\n")
  exit(code)
def main() -> None:
  fmt = None
  algo = None
  args = sys.argv[1:]
  while len(args) > 0 and args[0].startswith("-") and args[0] != "-":
    opt = args.pop(0)
    if opt == "--":
      break
    elif opt in ["--lhex", "--uhex", "--uint", "--sint"]:
      fmt = opt[2:]
    elif opt in ["--md5", "--sha1", "--sha256"]:
      algo = opt[2:]
    elif opt == "--help":
      exitusage(code=0, usestdout=True)
    else:
      sys.stderr.write(_prog()+": invalid option '"+opt+"'\n")
      sys.stderr.write("\n")
      exitusage()
  if len(args) == 0:
    exitusage()
  try:
    ret = 0
    for fn in args:
      try:
        chksumstr = chksumfile(fn, fmt=fmt, algo=algo)
        print(chksumstr+"  "+fn)
      except OSError as exc:
        ret = 1
        sys.stderr.write(_prog()+": "+fn+": "+(exc.strerror or str(exc))+"\n")
    exit(ret)
  except UnsupportedFmtForAlgo as exc:
    sys.stderr.write(_prog()+": "+str(exc)+"\n")
    exit(1)
def chksumfile(fn: str, fmt: Optional[str] = None, algo: Optional[str] = None) -> str:
  fmt = ("lhex" if fmt is None else fmt)
  algo = ("crc32" if algo is None else algo)
  if fmt not in ["lhex", "uhex", "uint", "sint"]:
    raise UnsupportedFmt(fmt)
  if fmt in ["uint", "sint"] and algo != "crc32":
    raise UnsupportedFmtForAlgo(fmt=fmt, algo=algo)
  if algo == "crc32":
    chksum = CRC32()
  else:
    chksum = Hash(algo)
  with (open(fn, "rb") if fn != "-" else sys.stdin.buffer) as f:
    while True:
      chunk = f.read(131072)
      if len(chunk) > 0:
        chksum.update(chunk)
      else:
        break
  if fmt == "lhex":
    return chksum.lhex()
  elif fmt == "uhex":
    return chksum.uhex()
  elif fmt == "uint":
    if isinstance(chksum, CRC32):
      return str(chksum.uint())
    else:
      raise InternalError
  elif fmt == "sint":
    if isinstance(chksum, CRC32):
      return str(chksum.sint())
    else:
      raise InternalError
  else:
    raise InternalError
class CRC32:
  def __init__(self, data: bytes = b""):
    self._crc = zlib.crc32(data)
  def update(self, data: bytes) -> None:
    self._crc = zlib.crc32(data, self._crc)
  def lhex(self) -> str:
    return _lhex32(self._crc)
  def uhex(self) -> str:
    return _uhex32(self._crc)
  def uint(self) -> int:
    return _uint32(self._crc)
  def sint(self) -> int:
    return _sint32(self._crc)
  def bbytes(self) -> bytes:
      # bbytes = big-endian bytes
    return _bbytes32(self._crc)
  def lbytes(self) -> bytes:
      # lbytes = little-endian bytes
    return _lbytes32(self._crc)
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
    raise OverflowError("argument out of range: "+str(x))
def _sint32(x: int) -> int:
  if x >= -0x80000000 and x < 0x80000000:
    return x
  elif x >= 0x80000000 and x < 0x100000000:
    return x - 0x100000000
  else:
    raise OverflowError("argument out of range: "+str(x))
def _bbytes32(x: int) -> bytes:
  return _uint32(x).to_bytes(4, "big", signed=False)
def _lbytes32(x: int) -> bytes:
  return _uint32(x).to_bytes(4, "little", signed=False)
class Hash:
  def __init__(self, algo: str, data: bytes = b""):
    if algo == "sha256":
      self._hashobj = hashlib.sha256(data)
    elif algo == "sha1":
      self._hashobj = hashlib.sha1(data)
    elif algo == "md5":
      self._hashobj = hashlib.md5(data)
    else:
      raise UnsupportedAlgo(algo)
  def update(self, data: bytes) -> None:
    self._hashobj.update(data)
  def lhex(self) -> str:
    return self._hashobj.hexdigest().lower()
  def uhex(self) -> str:
    return self._hashobj.hexdigest().upper()
  def bytes(self) -> bytes:
    return self._hashobj.digest()
def _prog() -> str:
  return os.path.basename(sys.argv[0])
class UnsupportedFmt(Exception):
  def __init__(self, fmt: str):
    super().__init__("unsupported format '"+fmt+"'")
    self.fmt = fmt
class UnsupportedAlgo(Exception):
  def __init__(self, algo: str):
    super().__init__("unsupported algorithm '"+algo+"'")
    self.algo = algo
class UnsupportedFmtForAlgo(Exception):
  def __init__(self, fmt: str, algo: str):
    super().__init__("format '"+fmt+"' unsupported for algorithm '"+algo+"'")
    self.fmt = fmt
    self.algo = algo
class InternalError(Exception):
  def __init__(self):
    super().__init__("internal error")
if __name__=="__main__":
  main()
