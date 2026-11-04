// Licensed under the Apache License, Version 2.0
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry/testing.dart';
import 'package:otel_snyk/otel_snyk.dart';
import 'package:test/test.dart';

void main() {
  late TestHarness harness;
  late InMemorySpanExporter spans;

  setUpAll(() async {
    harness = await maybeInitializeOtelForTest(
      serviceName: 'otel_snyk-test',
    );
    spans = harness.spans;
  });

  setUp(() => harness.clear());

  Map<String, Object> attrsOf(Span s) =>
      {for (final a in s.attributes.toList()) a.key: a.value};

  test('open_source test records SCA counts', () async {
    await tracedSnyk<String>(
      operation: 'test.open_source',
      invoke: () async => const SnykCallResult(
        value: 'ok',
        result: SnykResult(
          surface: 'open_source',
          projectType: 'npm',
          packageManager: 'npm',
          issuesTotal: 42,
          issuesCritical: 1,
          issuesHigh: 4,
          issuesFixable: 30,
          dependenciesScanned: 1850,
        ),
      ),
    );
    final a = attrsOf(spans.findSpanByName('snyk test.open_source')!);
    expect(a['snyk.issues.total'], 42);
    expect(a['snyk.issues.critical'], 1);
    expect(a['snyk.dependencies.scanned'], 1850);
  });

  test('container test records image + layer', () async {
    await tracedSnyk<String>(
      operation: 'test.container',
      invoke: () async => const SnykCallResult(
        value: 'ok',
        result: SnykResult(
          surface: 'container',
          containerImage: 'docker.io/library/alpine:3.20',
          containerLayer: 'sha256:abc',
          issuesTotal: 3,
        ),
      ),
    );
    final a = attrsOf(spans.findSpanByName('snyk test.container')!);
    expect(a['snyk.container.image'], 'docker.io/library/alpine:3.20');
    expect(a['snyk.container.layer'], 'sha256:abc');
  });

  test('iac test records file type', () async {
    await tracedSnyk<String>(
      operation: 'test.iac',
      invoke: () async => const SnykCallResult(
        value: 'ok',
        result: SnykResult(
          surface: 'iac',
          iacFileType: 'terraform',
          issuesTotal: 7,
        ),
      ),
    );
    final a = attrsOf(spans.findSpanByName('snyk test.iac')!);
    expect(a['snyk.iac.file_type'], 'terraform');
  });

  test('rate_limit sets span error', () async {
    await tracedSnyk<String>(
      operation: 'projects.list',
      invoke: () async => const SnykCallResult(
        value: 'ok',
        result: SnykResult(
          errorCode: 'rate_limit',
          statusCode: 429,
        ),
      ),
    );
    expect(
      spans.findSpanByName('snyk projects.list')!.status,
      SpanStatusCode.Error,
    );
  });

  test('suppression skips spans', () async {
    await runWithoutSnykInstrumentationAsync(() async {
      await tracedSnyk<String>(
        operation: 'orgs.list',
        invoke: () async => const SnykCallResult(value: 'v'),
      );
    });
    expect(spans.findSpansStartingWith('snyk '), isEmpty);
  });
}
