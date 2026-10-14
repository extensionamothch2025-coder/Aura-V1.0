import 'package:aura_mobile_defens/crypto/aura_crypto_layer.dart';
import 'package:test/test.dart';

void main() {
  group('AuraCryptoLayer AES-GCM model encryption', () {
    const secureKey = 'unit-test-model-key';

    test('round-trips model JSON', () {
      const plaintext = '{"model_version":"test","trees":[]}';
      final encrypted = AuraCryptoLayer.encryptModel(plaintext, secureKey);

      expect(AuraCryptoLayer.decryptModel(encrypted, secureKey), plaintext);
    });

    test('rejects ciphertext with a modified authentication tag', () {
      const plaintext = '{"model_version":"test","trees":[]}';
      final encrypted = AuraCryptoLayer.encryptModel(plaintext, secureKey);
      final lastHexDigit = encrypted.endsWith('0') ? '1' : '0';
      final tampered = '${encrypted.substring(0, encrypted.length - 1)}'
          '$lastHexDigit';

      expect(
        () => AuraCryptoLayer.decryptModel(tampered, secureKey),
        throwsA(isA<AuraCryptoException>()),
      );
    });
  });
}