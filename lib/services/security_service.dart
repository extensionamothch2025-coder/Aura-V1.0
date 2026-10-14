import 'dart:developer' as developer;

import 'package:flutter/services.dart';

class SecurityService {
  SecurityService({MethodChannel? nativeChannel})
      : _nativeChannel = nativeChannel ?? _defaultNativeChannel;

  static const MethodChannel _defaultNativeChannel =
      MethodChannel('com.ciberdefensa.aura/security');

  final MethodChannel _nativeChannel;
  Future<void>? _environmentCheck;
  bool _isRooted = false;
  bool _isMlAdvancedEnabled = true;

  bool get isRooted => _isRooted;
  bool get isMlAdvancedEnabled => _isMlAdvancedEnabled && !_isRooted;

  Future<void> checkEnvironment() =>
      _environmentCheck ??= _checkEnvironment();

  Future<void> _checkEnvironment() async {
    try {
      final report = await _nativeChannel.invokeMapMethod<String, dynamic>(
        'checkHostileEnvironment',
      );
      final status = report?['environmentStatus'];
      _isRooted = status == 'ROOTED' ||
          status == 'EMULATOR' ||
          report?['isRooted'] == true ||
          report?['isEmulator'] == true;
      _isMlAdvancedEnabled = !_isRooted;
      if (_isRooted) _showDegradedModeWarning();
    } on PlatformException catch (error, stackTrace) {
      developer.log(
        'No se pudo comprobar el entorno; se conserva la configuración ML actual.',
        name: 'AuraSecurity',
        error: error,
        stackTrace: stackTrace,
        level: 900,
      );
    } on MissingPluginException catch (error, stackTrace) {
      developer.log(
        'La comprobación nativa del entorno no está disponible.',
        name: 'AuraSecurity',
        error: error,
        stackTrace: stackTrace,
        level: 900,
      );
    }
  }

  void _showDegradedModeWarning() {
    developer.log(
      'Sistema modificado detectado. ML avanzado pausado; las listas de '
      'bloqueo y reglas locales siguen activas.',
      name: 'AuraSecurity',
      level: 900,
    );
  }
}