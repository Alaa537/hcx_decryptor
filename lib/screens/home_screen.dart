import 'dart:convert';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';

import '../services/decrypt_service.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final passwordController = TextEditingController();
  final hwidController = TextEditingController();

  Uint8List? fileBytes;
  String? selectedFile;
  bool processing = false;
  Map<String, dynamic>? result;
  String? error;

  @override
  void dispose() {
    passwordController.dispose();
    hwidController.dispose();
    super.dispose();
  }

  Future<void> pickFile() async {
    final picked = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['hc'],
      withData: true,
    );
    if (picked == null || picked.files.isEmpty) return;

    final f = picked.files.first;
    if (f.bytes == null) {
      showMessage('تعذر قراءة الملف');
      return;
    }

    setState(() {
      selectedFile = f.name;
      fileBytes = f.bytes;
      result = null;
      error = null;
    });
  }

  Future<void> decrypt() async {
    final bytes = fileBytes;
    if (bytes == null) {
      showMessage('اختر ملف .hc أولاً');
      return;
    }

    setState(() {
      processing = true;
      error = null;
      result = null;
    });

    final r = await DecryptService().analyze(
      fileBytes: bytes,
      password: passwordController.text,
      hwid: hwidController.text,
    );

    if (!mounted) return;

    setState(() {
      processing = false;
      if (r.success) {
        result = r.data;
      } else {
        error = r.message;
      }
    });
  }

  void showMessage(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: CustomScrollView(
          slivers: [
            SliverPadding(
              padding: const EdgeInsets.fromLTRB(20, 28, 20, 40),
              sliver: SliverList(
                delegate: SliverChildListDelegate([
                  _header(),
                  const SizedBox(height: 26),
                  _fileCard(),
                  const SizedBox(height: 14),
                  _credentialsCard(),
                  const SizedBox(height: 20),
                  _actionButton(),
                  if (error != null) ...[
                    const SizedBox(height: 16),
                    _errorCard(),
                  ],
                  if (result != null) ...[
                    const SizedBox(height: 16),
                    _resultCard(),
                  ],
                ]),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _header() {
    return Row(
      children: [
        Container(
          width: 54,
          height: 54,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(17),
            gradient: const LinearGradient(
              colors: [Color(0xFF7C4DFF), Color(0xFF3D7BFF)],
            ),
            boxShadow: [
              BoxShadow(
                color: const Color(0xFF6D4AFF).withOpacity(.28),
                blurRadius: 24,
              ),
            ],
          ),
          child: const Icon(Icons.security_rounded, size: 29),
        ),
        const SizedBox(width: 14),
        const Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'HCX Decryptor',
                style: TextStyle(fontSize: 25, fontWeight: FontWeight.w900),
              ),
              SizedBox(height: 4),
              Text(
                'HTTP Custom Configuration Analyzer',
                style: TextStyle(color: Colors.white54, fontSize: 12),
              ),
            ],
          ),
        ),
      ],
    ).animate().fadeIn(duration: 450.ms).slideY(begin: .08);
  }

  Widget _fileCard() {
    return _glass(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _title(
            Icons.insert_drive_file_rounded,
            'HC Configuration',
            'اختر ملف HTTP Custom للتحليل',
          ),
          const SizedBox(height: 18),
          InkWell(
            onTap: pickFile,
            borderRadius: BorderRadius.circular(18),
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(22),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(18),
                color: Colors.white.withOpacity(.035),
                border: Border.all(color: Colors.white.withOpacity(.09)),
              ),
              child: Column(
                children: [
                  Icon(
                    fileBytes == null
                        ? Icons.upload_file_rounded
                        : Icons.check_circle_rounded,
                    size: 42,
                    color: fileBytes == null
                        ? const Color(0xFF9C7BFF)
                        : const Color(0xFF48E5A5),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    selectedFile ?? 'اضغط لاختيار ملف .hc',
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  if (fileBytes != null) ...[
                    const SizedBox(height: 4),
                    Text(
                      '${fileBytes!.length} bytes',
                      style: const TextStyle(
                        color: Colors.white38,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    ).animate().fadeIn(delay: 80.ms).slideY(begin: .06);
  }

  Widget _credentialsCard() {
    return _glass(
      child: Column(
        children: [
          TextField(
            controller: passwordController,
            obscureText: true,
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.lock_rounded),
              labelText: 'Password',
              hintText: 'اتركه فارغًا إذا لم يكن مطلوبًا',
              border: InputBorder.none,
            ),
          ),
          Divider(color: Colors.white.withOpacity(.08)),
          TextField(
            controller: hwidController,
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.fingerprint_rounded),
              labelText: 'HWID',
              hintText: '32 حرفًا عند الحاجة',
              border: InputBorder.none,
            ),
          ),
        ],
      ),
    ).animate().fadeIn(delay: 140.ms);
  }

  Widget _actionButton() {
    return SizedBox(
      width: double.infinity,
      height: 58,
      child: DecoratedBox(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(18),
          gradient: const LinearGradient(
            colors: [Color(0xFF7C4DFF), Color(0xFF3D7BFF)],
          ),
        ),
        child: ElevatedButton(
          onPressed: processing ? null : decrypt,
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.transparent,
            shadowColor: Colors.transparent,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(18),
            ),
          ),
          child: processing
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2.4),
                )
              : const Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.lock_open_rounded),
                    SizedBox(width: 10),
                    Text(
                      'ANALYZE & DECRYPT',
                      style: TextStyle(
                        fontWeight: FontWeight.w900,
                        letterSpacing: .7,
                      ),
                    ),
                  ],
                ),
        ),
      ),
    ).animate().fadeIn(delay: 200.ms).scale();
  }

  Widget _errorCard() {
    return _glass(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.error_outline_rounded, color: Colors.redAccent),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              error!,
              style: const TextStyle(color: Colors.redAccent),
            ),
          ),
        ],
      ),
    );
  }

  Widget _resultCard() {
    final pretty = const JsonEncoder.withIndent('  ').convert(result);
    return _glass(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _title(
            Icons.data_object_rounded,
            'Decrypted Result',
            'البيانات المستخرجة من ملف HC',
          ),
          const SizedBox(height: 16),
          Container(
            width: double.infinity,
            constraints: const BoxConstraints(maxHeight: 520),
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: Colors.black.withOpacity(.28),
              borderRadius: BorderRadius.circular(15),
            ),
            child: SingleChildScrollView(
              child: SelectableText(
                pretty,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 11.5,
                  height: 1.45,
                  color: Color(0xFFD9D2FF),
                ),
              ),
            ),
          ),
        ],
      ),
    ).animate().fadeIn().slideY(begin: .05);
  }

  Widget _title(IconData icon, String title, String subtitle) {
    return Row(
      children: [
        Icon(icon, color: const Color(0xFF9C7BFF)),
        const SizedBox(width: 11),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title,
                  style: const TextStyle(fontWeight: FontWeight.w800)),
              const SizedBox(height: 3),
              Text(
                subtitle,
                style: const TextStyle(color: Colors.white54, fontSize: 12),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _glass({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        color: Colors.white.withOpacity(.045),
        border: Border.all(color: Colors.white.withOpacity(.08)),
      ),
      child: child,
    );
  }
}
