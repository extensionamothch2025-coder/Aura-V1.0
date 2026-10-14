import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:aura_mobile_defens/services/security_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const securityChannel = MethodChannel('com.ciberdefensa.aura/security');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  var environmentStatus = 'CLEAN';

  setUp(() {
    messenger.setMockMethodCallHandler(securityChannel, (call) async {
      expect(call.method, 'checkHostileEnvironment');
      return <String, Object>{'environmentStatus': environmentStatus};
    });
  });

  tearDown(() {
    messenger.setMockMethodCallHandler(securityChannel, null);
  });

  test('keeps advanced ML enabled in a clean environment', () async {
    environmentStatus = 'CLEAN';
    final service = SecurityService();

    await service.checkEnvironment();

    expect(service.isRooted, isFalse);
    expect(service.isMlAdvancedEnabled, isTrue);
  });

  for (final status in <String>['ROOTED', 'EMULATOR']) {
    test('disables advanced ML for $status environments', () async {
      environmentStatus = status;
      final service = SecurityService();

      await service.checkEnvironment();

      expect(service.isRooted, isTrue);
      expect(service.isMlAdvancedEnabled, isFalse);
    });
  }
}