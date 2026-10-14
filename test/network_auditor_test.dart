import 'package:aura_mobile_defens/network_auditor.dart';
import 'package:test/test.dart';

void main() {
  group('DoH behavior detector', () {
    test('warns once after more than 50 matching UDP connections', () {
      final warnings = <String>[];
      final detector = DoHBehaviorDetector(
        onWarning: (appName, count) => warnings.add('$appName:$count'),
      );
      final start = DateTime.utc(2026, 10, 14);

      for (var index = 0; index < 50; index++) {
        expect(
          detector.trackUdpConnection('com.example.app', 853, at: start),
          isFalse,
        );
      }
      expect(warnings, isEmpty);
      expect(
        detector.trackUdpConnection('com.example.app', 443, at: start),
        isTrue,
      );
      expect(warnings, <String>['com.example.app:51']);
      expect(
        detector.trackUdpConnection('com.example.app', 443, at: start),
        isTrue,
      );
      expect(warnings, hasLength(1));

      final afterWindow = start.add(const Duration(hours: 1, seconds: 1));
      for (var index = 0; index < 51; index++) {
        detector.trackUdpConnection('com.example.app', 443, at: afterWindow);
      }
      expect(warnings, hasLength(2));
    });

    test('expires old connections outside the rolling hour', () {
      final warnings = <String>[];
      final detector = DoHBehaviorDetector(
        onWarning: (appName, count) => warnings.add(appName),
      );
      final start = DateTime.utc(2026, 10, 14);
      for (var index = 0; index < 51; index++) {
        detector.trackUdpConnection('com.example.app', 853, at: start);
      }

      expect(
        detector.trackUdpConnection(
          'com.example.app',
          853,
          at: start.add(const Duration(hours: 1, seconds: 1)),
        ),
        isFalse,
      );
      expect(warnings, <String>['com.example.app']);
    });

    test('ignores ports outside encrypted DNS and blank app names', () {
      final detector = DoHBehaviorDetector();

      expect(detector.trackUdpConnection('com.example.app', 53), isFalse);
      expect(detector.trackUdpConnection('', 853), isFalse);
    });
  });

  group('NetworkAuditEvent platform events', () {
    test('preserves observed SNI and resolver endpoint metadata', () {
      final event = NetworkAuditEvent.fromPlatform(<String, Object>{
        'timestamp': 123,
        'source_app': 'uid-unavailable',
        'requested_domain': 'dns.google',
        'action': 'SNI_OBSERVED',
        'destination_address': '8.8.8.8',
        'destination_port': 443,
        'transport_protocol': 'TCP',
        'public_dns_resolver': true,
      });

      expect(event.action, NetworkAuditAction.sniObserved);
      expect(event.requestedDomain, 'dns.google');
      expect(event.destinationAddress, '8.8.8.8');
      expect(event.destinationPort, 443);
      expect(event.transportProtocol, 'TCP');
      expect(event.publicDnsResolver, isTrue);
      expect(event.toJson()['action'], 'SNI_OBSERVED');
    });

    test('preserves blocked encrypted DNS endpoint metadata', () {
      final event = NetworkAuditEvent.fromPlatform(<String, Object>{
        'timestamp': 123,
        'source_app': 'uid-unavailable',
        'requested_domain': 'Encrypted DNS attempt',
        'action': 'ENCRYPTED_DNS_BLOCKED',
        'destination_address': '2620:fe::fe',
        'destination_port': 853,
        'transport_protocol': 'UDP',
        'public_dns_resolver': true,
      });

      expect(event.action, NetworkAuditAction.encryptedDnsBlocked);
      expect(event.destinationAddress, '2620:fe::fe');
      expect(event.toJson()['transport_protocol'], 'UDP');
    });

    test('normalizes bracketed IPv6 destination addresses', () {
      final event = NetworkAuditEvent.fromPlatform(<String, Object>{
        'timestamp': 123,
        'source_app': 'uid-unavailable',
        'requested_domain': 'Encrypted DNS attempt',
        'action': 'ENCRYPTED_DNS_BLOCKED',
        'destination_address': '[2001:0db8:0:0:0:0:0:1]',
        'destination_port': 853,
        'transport_protocol': 'UDP',
      });

      expect(event.destinationAddress, '2001:db8::1');
    });

    test('rejects malformed destination IP addresses', () {
      expect(
        () => NetworkAuditEvent.fromPlatform(<String, Object>{
          'timestamp': 123,
          'source_app': 'uid-unavailable',
          'requested_domain': 'dns.google',
          'action': 'SNI_OBSERVED',
          'destination_address': '2001:db8:::1',
        }),
        throwsFormatException,
      );
    });

    test('rejects invalid destination ports', () {
      expect(
        () => NetworkAuditEvent.fromPlatform(<String, Object>{
          'timestamp': 123,
          'source_app': 'uid-unavailable',
          'requested_domain': 'dns.google',
          'action': 'SNI_OBSERVED',
          'destination_port': 70000,
        }),
        throwsFormatException,
      );
    });
  });
}
