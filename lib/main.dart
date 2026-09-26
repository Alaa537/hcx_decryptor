import 'package:flutter/material.dart';
import 'screens/home_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const HCXApp());
}

class HCXApp extends StatelessWidget {
  const HCXApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'HCX Decryptor',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFF070812),
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF7C4DFF),
          brightness: Brightness.dark,
        ),
      ),
      home: const HomeScreen(),
    );
  }
}
