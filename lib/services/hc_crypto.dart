import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

class HCError implements Exception {
  final String message;
  HCError(this.message);
  @override
  String toString() => message;
}

final Uint8List _pkg = Uint8List.fromList(utf8.encode('xyz.easypro.httpcustom'));
final Uint8List _outerAad =
    Uint8List.fromList(utf8.encode('HCX1|xyz.easypro.httpcustom|1'));
final Uint8List _outerSeed =
    Uint8List.fromList(utf8.encode('hc-envelope-seal-v1 xyz.easypro.httpcustom'));
final Uint8List _outerSalt =
    Uint8List.fromList(utf8.encode('hc-envelope-seal-salt-v1'));
final Uint8List _outerInfo =
    Uint8List.fromList(utf8.encode('hc-envelope-seal-info-v1'));
final Uint8List _outerKeyV3 = _hex(
    '88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f');
final Uint8List _n7HmacKey = _hex(
    '9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3');
final Uint8List _c0Prefix = _hex(
    '95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181'
    '38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92');

Uint8List _hex(String s) {
  final clean = s.replaceAll(RegExp(r'\s+'), '');
  if (clean.length.isOdd) throw HCError('Invalid hex');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List _sha256(List<int> data) =>
    Uint8List.fromList(crypto.sha256.convert(data).bytes);

Uint8List _hmacSha256(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

Uint8List _c0(List<int> data) => _sha256([..._c0Prefix, ...data]);

Uint8List _hkdf(List<int> ikm, List<int> salt, List<int> info,
    [int length = 32]) {
  final prk = _hmacSha256(salt, ikm);
  final out = <int>[];
  var prev = <int>[];
  var ctr = 1;
  while (out.length < length) {
    prev = _hmacSha256(prk, [...prev, ...info, ctr]);
    out.addAll(prev);
    ctr++;
  }
  return Uint8List.fromList(out.take(length).toList());
}

int _rotl(int v, int b) =>
    ((v << b) & 0xffffffff) | ((v & 0xffffffff) >> (32 - b));

void _qr(List<int> s, int a, int b, int c, int d) {
  s[a] = (s[a] + s[b]) & 0xffffffff;
  s[d] = _rotl((s[d] ^ s[a]) & 0xffffffff, 16);
  s[c] = (s[c] + s[d]) & 0xffffffff;
  s[b] = _rotl((s[b] ^ s[c]) & 0xffffffff, 12);
  s[a] = (s[a] + s[b]) & 0xffffffff;
  s[d] = _rotl((s[d] ^ s[a]) & 0xffffffff, 8);
  s[c] = (s[c] + s[d]) & 0xffffffff;
  s[b] = _rotl((s[b] ^ s[c]) & 0xffffffff, 7);
}

void _rounds(List<int> s) {
  for (var i = 0; i < 10; i++) {
    _qr(s, 0, 4, 8, 12);
    _qr(s, 1, 5, 9, 13);
    _qr(s, 2, 6, 10, 14);
    _qr(s, 3, 7, 11, 15);
    _qr(s, 0, 5, 10, 15);
    _qr(s, 1, 6, 11, 12);
    _qr(s, 2, 7, 8, 13);
    _qr(s, 3, 4, 9, 14);
  }
}

int _u32(Uint8List d, int o) =>
    d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24);

Uint8List _u32le(int v) {
  final x = v & 0xffffffff;
  return Uint8List.fromList(
      [x & 255, (x >> 8) & 255, (x >> 16) & 255, (x >> 24) & 255]);
}

Uint8List _hchacha20(List<int> key, List<int> nonce16) {
  final s = <int>[
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    for (var i = 0; i < 8; i++) _u32(Uint8List.fromList(key), i * 4),
    for (var i = 0; i < 4; i++) _u32(Uint8List.fromList(nonce16), i * 4),
  ];
  _rounds(s);
  return Uint8List.fromList([
    ..._u32le(s[0]), ..._u32le(s[1]), ..._u32le(s[2]), ..._u32le(s[3]),
    ..._u32le(s[12]), ..._u32le(s[13]), ..._u32le(s[14]), ..._u32le(s[15]),
  ]);
}

Uint8List _chachaBlock(List<int> key, List<int> nonce12, int ctr) {
  final k = Uint8List.fromList(key);
  final n = Uint8List.fromList(nonce12);
  final init = <int>[
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    for (var i = 0; i < 8; i++) _u32(k, i * 4),
    ctr & 0xffffffff,
    _u32(n, 0), _u32(n, 4), _u32(n, 8),
  ];
  final s = [...init];
  _rounds(s);
  final out = <int>[];
  for (var i = 0; i < 16; i++) {
    out.addAll(_u32le((s[i] + init[i]) & 0xffffffff));
  }
  return Uint8List.fromList(out);
}

Uint8List _streamXor(List<int> data, List<int> key, List<int> nonce12,
    [int ctr = 1]) {
  final out = Uint8List(data.length);
  for (var off = 0; off < data.length; off += 64) {
    final block = _chachaBlock(key, nonce12, ctr + off ~/ 64);
    final end = (off + 64 < data.length) ? off + 64 : data.length;
    for (var i = off; i < end; i++) {
      out[i] = data[i] ^ block[i - off];
    }
  }
  return out;
}

Uint8List _pad16(List<int> d) =>
    d.length % 16 == 0 ? Uint8List(0) : Uint8List(16 - d.length % 16);

Uint8List _u64le(int v) {
  var x = v;
  final out = Uint8List(8);
  for (var i = 0; i < 8; i++) {
    out[i] = x & 0xff;
    x >>= 8;
  }
  return out;
}

Future<Uint8List> xDec(
    List<int> key, List<int> nonce, List<int> aad, List<int> ctTag) async {
  if (key.length != 32 || nonce.length != 24 || ctTag.length < 16) {
    throw HCError('bad XChaCha20 input');
  }
  final ct = ctTag.sublist(0, ctTag.length - 16);
  final tag = ctTag.sublist(ctTag.length - 16);
  final algorithm = Xchacha20.poly1305Aead();
  final box = SecretBox(ct, nonce: nonce, mac: Mac(tag));
  try {
    final clear = await algorithm.decrypt(
      box,
      secretKey: SecretKey(key),
      aad: aad,
    );
    return Uint8List.fromList(clear);
  } catch (_) {
    throw HCError('XChaCha20-Poly1305 auth failed');
  }
}

Future<Uint8List> argon2id(List<int> password, List<int> salt, int ops,
    int mem, int length) async {
  if (salt.length != 16) throw HCError('Argon2 salt must be 16 bytes');
  // cryptography uses memory in 1 KiB blocks, matching the Python implementation.
  final algorithm = Argon2id(
    parallelism: 1,
    memory: mem ~/ 1024,
    iterations: ops,
    hashLength: length,
  );
  final key = await algorithm.deriveKey(
    secretKey: SecretKey(password),
    nonce: salt,
  );
  return Uint8List.fromList(await key.extractBytes());
}

Uint8List outerKey() => _hkdf(_c0(_outerSeed), _outerSalt, _outerInfo);

Iterable<Uint8List> carriers(Uint8List data) sync* {
  final seen = <String>{};
  var cur = data;
  for (var i = 0; i < 6; i++) {
    final id = base64Encode(cur);
    if (seen.contains(id)) break;
    seen.add(id);
    if (cur.length >= 40) yield cur;
    try {
      final text = utf8.decode(cur);
      final next = Uint8List.fromList(text.codeUnits);
      if (next.length != cur.length) break;
      var same = true;
      for (var j = 0; j < cur.length; j++) {
        if (next[j] != cur[j]) {
          same = false;
          break;
        }
      }
      if (same) break;
      cur = next;
    } catch (_) {
      break;
    }
  }
}

Future<Map<String, dynamic>> openOuter(Uint8List data) async {
  final key = outerKey();
  Object? lastErr;

  for (final logical in carriers(data)) {
    if (logical.length < 40) continue;

    try {
      final pt = await xDec(
        key,
        logical.sublist(0, 24),
        _outerAad,
        logical.sublist(24),
      );
      final v = jsonDecode(utf8.decode(pt));
      if (v is Map<String, dynamic>) return v;
    } catch (e) {
      lastErr = e;
    }

    try {
      final nonce = logical.sublist(0, 24);
      final ct = logical.sublist(24, logical.length - 16);
      final sub = _hchacha20(_outerKeyV3, nonce.sublist(0, 16));
      final n12 = Uint8List.fromList([0, 0, 0, 0, ...nonce.sublist(16)]);
      final pt = _streamXor(ct, sub, n12);
      final v = jsonDecode(utf8.decode(pt));
      if (v is Map<String, dynamic> && v['a'] == 'HCCFG') return v;
    } catch (e) {
      lastErr = e;
    }
  }
  throw HCError('Not a valid HTTP Custom envelope: $lastErr');
}


// Public helpers used by the parser layer.
Uint8List sha256Bytes(List<int> data) =>
    Uint8List.fromList(crypto.sha256.convert(data).bytes);

Uint8List hmacSha256Bytes(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

Uint8List hkdfSha256Bytes(
    List<int> ikm, List<int> salt, List<int> info, int length) {
  final prk = hmacSha256Bytes(salt, ikm);
  final out = <int>[];
  var prev = <int>[];
  var counter = 1;
  while (out.length < length) {
    prev = hmacSha256Bytes(prk, [...prev, ...info, counter]);
    out.addAll(prev);
    counter++;
  }
  return Uint8List.fromList(out.take(length).toList());
}
