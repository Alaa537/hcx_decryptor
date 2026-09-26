import 'dart:convert';
import 'dart:typed_data';

import 'hc_crypto.dart';

class _Reader {
  final Uint8List d;
  int o = 0;
  _Reader(this.d);

  Uint8List take(int n) {
    if (o + n > d.length) throw HCError('Truncated HPC1');
    final v = d.sublist(o, o + n);
    o += n;
    return v;
  }

  int u32() {
    final b = take(4);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
  }

  int u64() {
    final b = take(8);
    var v = 0;
    for (final x in b) v = (v << 8) | x;
    return v;
  }

  String txt() {
    final s = u32();
    if (s > 16 * 1024 * 1024) throw HCError('HPC1 string too long');
    return utf8.decode(take(s));
  }
}

int _asInt(dynamic v) {
  if (v is bool || v == null) throw HCError('Bad integer');
  final i = int.tryParse(v.toString());
  if (i == null) throw HCError('Bad integer');
  return i;
}

Uint8List _bytesHex(dynamic v, String message) {
  if (v is! String) throw HCError(message);
  final s = v.trim();
  if (s.length.isOdd) throw HCError(message);
  try {
    final out = Uint8List(s.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  } catch (_) {
    throw HCError(message);
  }
}

int _validate(Map<String, dynamic> env) {
  if (env['a'] != 'HCCFG') throw HCError('Bad magic: ${env['a']}');
  final schema = _asInt(env['b'] ?? 0);
  String expC;
  String expK;
  if (schema == 1) {
    expC = 'XCHACHA20P1305';
    expK = 'NATIVE-HKDF-SHA256';
  } else if ([2, 5, 7].contains(schema)) {
    expC = 's1';
    expK = 'h1';
  } else {
    throw HCError('Unsupported schema b=$schema');
  }
  if (env['c'] != expC) throw HCError('Bad cipher: ${env['c']}');
  if (env['d'] != expK) throw HCError('Bad KDF: ${env['d']}');
  if (!['n1', 'n2', 'n7', 'n8'].contains(env['e'])) {
    throw HCError('Bad schedule: ${env['e']}');
  }
  return schema;
}

Uint8List _features(Map<String, dynamic> env) {
  final f = env['f'];
  if (f is! List || !f.every((x) => x is String)) {
    throw HCError('Bad features');
  }
  return Uint8List.fromList(utf8.encode(f.join(',')));
}

Uint8List? _nBytes(Map<String, dynamic> env) {
  final n = env['n'];
  if (n == null || n is bool) return null;
  final i = _asInt(n);
  if (i < 0 || i.toString() != n.toString()) throw HCError('Bad n value');
  return Uint8List.fromList(utf8.encode(i.toString()));
}

Uint8List _normHwid(String hwid) {
  final v = hwid.trim();
  if (v.length != 32) throw HCError('HWID must be 32 chars');
  if (!RegExp(r'^[0-9a-fA-FhH]{32}$').hasMatch(v)) {
    throw HCError('Bad HWID chars');
  }
  return Uint8List.fromList(utf8.encode(v.toUpperCase()));
}

Uint8List _envKey(Map<String, dynamic> env) {
  final k = _bytesHex(env['g'], 'Bad inner key');
  if (k.length != 32) throw HCError('Inner key must be 32 bytes');
  return k;
}

Future<(Uint8List, Uint8List)> _pwKdf(
    Map<String, dynamic> env, String password, Uint8List ekey) async {
  final kdf = env['k'];
  if (kdf != 'ARGON2ID13' && kdf != 'a1') {
    throw HCError('Bad pw KDF: $kdf');
  }
  final ops = _asInt(env['l']);
  final mem = _asInt(env['m']);
  final pk = await argon2id(
    utf8.encode(password),
    ekey.sublist(0, 16),
    ops,
    mem,
    32,
  );
  return (
    pk,
    Uint8List.fromList(
      [...utf8.encode('|1|ARGON2ID13|$ops|$mem')],
    )
  );
}

bool _hFlag(Map<String, dynamic> env) {
  final h = env['h'] ?? 0;
  if (![0, 1, false, true].contains(h)) throw HCError('Bad h flag: $h');
  return h == true || h == 1;
}

Uint8List _transcript(Map<String, dynamic> env, Uint8List ekey,
    Uint8List? hwid, bool n7Mode) {
  final feats = _features(env);
  final nb = _nBytes(env);
  final t = <int>[
    ...utf8.encode('HCCFG'),
    0,
    ...utf8.encode('xyz.easypro.httpcustom'),
    0,
    49,
    0,
    ...feats,
    0,
  ];
  if (nb != null) {
    t.addAll(nb);
    t.add(0);
  }
  if (hwid != null) {
    t.addAll(utf8.encode('hwid'));
    t.add(0);
    t.addAll(hwid);
    t.add(0);
  }
  t.addAll(ekey);

  if (n7Mode) {
    return _hmacSha256Local(
      _n7HmacKeyLocal,
      [0xd3, ..._c0PrefixLocal.sublist(0, 32), ...t],
    );
  }
  return _sha256Local([..._c0PrefixLocal, ...t]);
}

final Uint8List _n7HmacKeyLocal = _hexLocal(
    '9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3');
final Uint8List _c0PrefixLocal = _hexLocal(
    '95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181'
    '38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92');

Uint8List _hexLocal(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List _sha256Local(List<int> data) {
  // Keep the hashing implementation in hc_crypto.dart's exported helpers
  // inaccessible; duplicate only this small primitive through the public
  // crypto facade below.
  return sha256Bytes(data);
}

Uint8List _hmacSha256Local(List<int> key, List<int> data) =>
    hmacSha256Bytes(key, data);

Future<(Uint8List, Uint8List)> _derive(
    Map<String, dynamic> env, String? password, String? hwid) async {
  final sched = env['e'] as String;
  final schema = _validate(env);
  final ekey = _envKey(env);
  final feats = _features(env);
  final nb = _nBytes(env);
  final hwidMode = sched == 'n2' || sched == 'n8';
  final n7Mode = sched == 'n7' || sched == 'n8';

  if (hwidMode && hwid == null) {
    final o = env['o'];
    final cnt = o is List ? o.length : 0;
    throw HCError('HWID_REQUIRED:$cnt');
  }

  final hwidB = hwidMode ? _normHwid(hwid!) : null;
  var ikm = _transcript(env, ekey, hwidB, n7Mode);
  var aadProt = Uint8List.fromList(utf8.encode('|0'));

  if (_hFlag(env)) {
    if (password == null) {
      throw HCError(hwidMode ? 'HWID_PASSWORD_REQUIRED' : 'PASSWORD_REQUIRED');
    }
    final r = await _pwKdf(env, password, ekey);
    ikm = Uint8List.fromList([...ikm, ...r.$1]);
    aadProt = r.$2;
  }

  final info = <int>[
    ...utf8.encode('app-config|$sched|xyz.easypro.httpcustom|1'),
    ...?nb == null ? null : [124, ...nb],
    ...?hwidB == null ? null : [...utf8.encode('|hwid|'), ...hwidB],
  ];
  final skey = _hkdfLocal(ikm, ekey, info, 32);

  final aad = <int>[
    ...utf8.encode(
        'HCCFG|$schema|XCHACHA20P1305|NATIVE-HKDF-SHA256|$sched|xyz.easypro.httpcustom|1|${utf8.decode(feats)}'),
    ...aadProt,
    ...?nb == null ? null : [124, ...nb],
  ];

  if (hwidMode) {
    final slots = env['o'];
    if (slots is! List || slots.isEmpty) throw HCError('No HWID key slots');

    for (final slot in slots) {
      if (slot is! Map) continue;
      try {
        final nonce = _bytesHex(slot['a'], 'Bad HWID slot');
        final ct = _bytesHex(slot['b'], 'Bad HWID slot');
        final sk = await xDec(
          skey,
          nonce,
          [...aad, 0, 119],
          ct,
        );
        if (sk.length == 32) return (sk, Uint8List.fromList(aad));
      } catch (_) {}
    }
    throw HCError('AUTH_FAILED');
  }

  return (skey, Uint8List.fromList(aad));
}

Uint8List _hkdfLocal(
    List<int> ikm, List<int> salt, List<int> info, int length) {
  return hkdfSha256Bytes(ikm, salt, info, length);
}

Future<Uint8List> _decSection(
    Map<String, dynamic> sec, Uint8List key, Uint8List aadBase) async {
  final label = sec['a'];
  if (label is! String || label.isEmpty) throw HCError('Bad section label');
  final nonce = _bytesHex(sec['b'], 'Bad section');
  final ct = _bytesHex(sec['c'], 'Bad section');
  return xDec(key, nonce, [...aadBase, 0, ...utf8.encode(label)], ct);
}

Future<Uint8List?> _decSidecar(
    Map<String, dynamic> sec, Uint8List key, Uint8List aadBase) async {
  final nested = sec['d'];
  if (nested == null) return null;
  if (nested is! Map) throw HCError('Bad sidecar');
  final label = sec['a'] ?? '';
  final nonce = _bytesHex(nested['a'], 'Bad sidecar data');
  final ct = _bytesHex(nested['b'], 'Bad sidecar data');
  return xDec(
      key, nonce, [...aadBase, 0, ...utf8.encode('$label:x')], ct);
}

Future<Uint8List> _decHpr1(Uint8List data, Uint8List key,
    Uint8List aadBase, String? label) async {
  if (data.length < 44 ||
      data[0] != 72 ||
      data[1] != 80 ||
      data[2] != 82 ||
      data[3] != 49) {
    return data;
  }
  final nonce = data.sublist(4, 28);
  final ctTag = data.sublist(28);
  final tag = utf8.encode('${label ?? 's0'}:r');
  try {
    return await xDec(key, nonce, [...aadBase, 0, ...tag], ctTag);
  } catch (_) {
    final sub = _hchachaLocal(key, nonce.sublist(0, 16));
    final n12 = Uint8List.fromList([0, 0, 0, 0, ...nonce.sublist(16)]);
    return _streamLocal(ctTag.sublist(0, ctTag.length - 16), sub, n12);
  }
}

Uint8List _hchachaLocal(List<int> key, List<int> nonce16) {
  int u32(List<int> b, int o) =>
      b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
  int rol(int v, int n) =>
      ((v << n) & 0xffffffff) | ((v & 0xffffffff) >> (32 - n));
  void qr(List<int> s, int a, int b, int c, int d) {
    s[a] = (s[a] + s[b]) & 0xffffffff;
    s[d] = rol(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) & 0xffffffff;
    s[b] = rol(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) & 0xffffffff;
    s[d] = rol(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) & 0xffffffff;
    s[b] = rol(s[b] ^ s[c], 7);
  }
  final k = Uint8List.fromList(key);
  final n = Uint8List.fromList(nonce16);
  final s = <int>[
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    for (var i = 0; i < 8; i++) u32(k, i * 4),
    for (var i = 0; i < 4; i++) u32(n, i * 4),
  ];
  for (var i = 0; i < 10; i++) {
    qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13);
    qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15);
    qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12);
    qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14);
  }
  final out = <int>[];
  void put(int x) => out.addAll(
      [x & 255, (x >> 8) & 255, (x >> 16) & 255, (x >> 24) & 255]);
  put(s[0]); put(s[1]); put(s[2]); put(s[3]);
  put(s[12]); put(s[13]); put(s[14]); put(s[15]);
  return Uint8List.fromList(out);
}

Uint8List _streamLocal(List<int> data, List<int> key, List<int> nonce12,
    [int ctr = 1]) {
  int u32(List<int> b, int o) =>
      b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
  int rol(int v, int n) =>
      ((v << n) & 0xffffffff) | ((v & 0xffffffff) >> (32 - n));
  void qr(List<int> s, int a, int b, int c, int d) {
    s[a] = (s[a] + s[b]) & 0xffffffff;
    s[d] = rol(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) & 0xffffffff;
    s[b] = rol(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) & 0xffffffff;
    s[d] = rol(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) & 0xffffffff;
    s[b] = rol(s[b] ^ s[c], 7);
  }
  Uint8List block(int count) {
    final k = Uint8List.fromList(key);
    final n = Uint8List.fromList(nonce12);
    final init = <int>[
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
      for (var i = 0; i < 8; i++) u32(k, i * 4),
      count & 0xffffffff,
      u32(n, 0), u32(n, 4), u32(n, 8),
    ];
    final s = [...init];
    for (var i = 0; i < 10; i++) {
      qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13);
      qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15);
      qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12);
      qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14);
    }
    final out = <int>[];
    for (var i = 0; i < 16; i++) {
      final x = (s[i] + init[i]) & 0xffffffff;
      out.addAll([x & 255, (x >> 8) & 255, (x >> 16) & 255, (x >> 24) & 255]);
    }
    return Uint8List.fromList(out);
  }

  final out = Uint8List(data.length);
  for (var off = 0; off < data.length; off += 64) {
    final st = block(ctr + off ~/ 64);
    final end = (off + 64 < data.length) ? off + 64 : data.length;
    for (var i = off; i < end; i++) out[i] = data[i] ^ st[i - off];
  }
  return out;
}

const Map<String, String> _pkm = {
  'a': 'accessMode',
  'c': 'expiryEnabled',
  'd': 'expiryTime',
  'e': 'noteEnabled',
  'f': 'hwidLockEnabled',
  'g': 'hwids',
  'h': 'loginHwidEnabled',
  'j': 'loginHwidAuthorizationRequired',
  'l': 'mobileDataOnly',
  'm': 'blockRoot',
  'o': 'providerLockEnabled',
  'p': 'providerCodes',
  'v': 'note',
};

const Map<int, String> _versions = {
  756: '7.9.21',
  759: '7.9.24',
  766: '7.9.28',
  789: '7.10.7',
  810: '7.10.12',
  831: '7.10.19',
  848: '7.10.25',
  859: '7.11.1',
  864: '7.11.8',
};

String _version(dynamic n) {
  final i = int.tryParse('$n');
  return i == null ? 'build-$n' : '${_versions[i] ?? 'build-$i'} ($i)';
}

dynamic _normProt(dynamic p) {
  if (p is! Map) return p;
  return p.map((k, v) => MapEntry(_pkm[k] ?? k, v));
}

Map<String, dynamic> _parseHpc1(Uint8List data, String? label) {
  final r = _Reader(data);
  final magic = r.take(4);
  if (utf8.decode(magic) != 'HPC1') throw HCError('Not HPC1');
  if (r.u32() != 11) throw HCError('Bad HPC1 field count');

  final name = r.txt();
  final proto = r.txt();
  final host = r.txt();
  final port = r.u32();
  final user = r.txt();
  final pw = r.txt();
  final payload = r.txt();
  final optsTxt = r.txt();
  final flags = r.u32();
  final updated = r.u64();
  final mode = r.txt();

  if (r.o != data.length) throw HCError('HPC1 trailing bytes');

  dynamic opts;
  if (optsTxt.isEmpty) {
    opts = <String, dynamic>{};
  } else {
    try {
      opts = jsonDecode(optsTxt);
    } catch (_) {
      opts = optsTxt;
    }
  }

  final res = <String, dynamic>{
    'name': name,
    'protocol': proto,
    'host': host,
    'port': port,
    'username': user,
    'password': pw,
    'payload': payload,
    'options': opts,
    'flags': flags,
    'updated_at_ms': updated,
    'mode': mode,
  };
  if (label != null) res['label'] = label;
  return res;
}

List<Map<String, dynamic>> _secList(dynamic v) {
  if (v is List && v.every((x) => x is Map)) {
    return v.cast<Map<String, dynamic>>();
  }
  if (v is Map && v.values.every((x) => x is Map)) {
    return v.values.cast<Map<String, dynamic>>().toList();
  }
  throw HCError('Bad section collection');
}

String _appVersion(dynamic n) => _version(n);

Future<Map<String, dynamic>> decryptHC(
    Uint8List data, {String? password, String? hwid}) async {
  final env = await openOuter(data);
  final derived = await _derive(env, password, hwid);
  final skey = derived.$1;
  final aadBase = derived.$2;

  final mainSec = env['i'];
  if (mainSec is! Map) throw HCError('Missing main section');
  final mainPt = await _decSection(mainSec.cast<String, dynamic>(), skey, aadBase);

  dynamic mainCfg;
  try {
    mainCfg = jsonDecode(utf8.decode(mainPt));
  } catch (_) {
    throw HCError('Main section not JSON');
  }

  final profiles = <Map<String, dynamic>>[];
  final others = <Map<String, dynamic>>[];

  for (final sec in _secList(env['j'] ?? <dynamic>[])) {
    var pt = await _decSection(sec, skey, aadBase);
    final label = sec['a'] as String?;
    if (pt.length >= 4 && utf8.decode(pt.sublist(0, 4), allowMalformed: true) == 'HPR1') {
      pt = await _decHpr1(pt, skey, aadBase, label);
    }

    final sidecar = await _decSidecar(sec, skey, aadBase);

    if (pt.length >= 4 && utf8.decode(pt.sublist(0, 4), allowMalformed: true) == 'HPC1') {
      final prof = _parseHpc1(pt, label);
      if (sidecar != null) {
        try {
          prof['custom_payload_sidecar'] = utf8.decode(sidecar);
        } catch (_) {
          prof['custom_payload_sidecar_hex'] =
              base64Encode(sidecar); // transport-safe fallback
        }
      }
      profiles.add(prof);
    } else {
      dynamic dec;
      try {
        final text = utf8.decode(pt);
        if (text.startsWith('{') || text.startsWith('[')) {
          dec = jsonDecode(text);
        } else {
          dec = text;
        }
      } catch (_) {
        dec = {'hex': pt.map((e) => e.toRadixString(16).padLeft(2, '0')).join()};
      }
      others.add({'label': label, 'content': dec});
    }
  }

  final clean = <Map<String, dynamic>>[];
  for (final p in profiles) {
    final cp = <String, dynamic>{
      'name': p['name'] ?? '',
      'protocol': p['protocol'] ?? '',
      'host': p['host'] ?? '',
      'port': p['port'] ?? 0,
      'username': p['username'] ?? '',
      'password': p['password'] ?? '',
      'mode': p['mode'] ?? '',
    };
    final opts = p['options'];
    if (opts is Map) cp.addAll(opts.cast<String, dynamic>());
    if ((p['payload'] ?? '').toString().isNotEmpty) cp['payload'] = p['payload'];
    if (p.containsKey('custom_payload_sidecar')) {
      cp['custom_payload_sidecar'] = p['custom_payload_sidecar'];
    }
    if (p.containsKey('custom_payload_sidecar_hex')) {
      cp['custom_payload_sidecar_hex'] = p['custom_payload_sidecar_hex'];
    }
    clean.add(cp);
  }

  final result = <String, dynamic>{
    'app_version': _appVersion(env['n']),
    'config': clean,
    'protections': _normProt(mainCfg is Map ? (mainCfg['g'] ?? {}) : {}),
  };
  if (others.isNotEmpty) result['other_sections'] = others;
  return result;
}
