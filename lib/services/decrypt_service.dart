import 'dart:typed_data';

import 'hc_decryptor.dart';

class DecryptResult {
  final bool success;
  final String message;
  final Map<String, dynamic> data;

  const DecryptResult({
    required this.success,
    required this.message,
    this.data = const {},
  });
}

class DecryptService {
  Future<DecryptResult> analyze({
    required Uint8List fileBytes,
    String? password,
    String? hwid,
  }) async {
    try {
      final result = await decryptHC(
        fileBytes,
        password: password?.isEmpty == true ? null : password,
        hwid: hwid?.isEmpty == true ? null : hwid,
      );

      return DecryptResult(
        success: true,
        message: 'تم فك وتحليل الملف بنجاح',
        data: result,
      );
    } catch (e) {
      return DecryptResult(
        success: false,
        message: e.toString(),
      );
    }
  }
}
