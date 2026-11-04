// Licensed under the Apache License, Version 2.0
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry_api/dartastic_opentelemetry_api.dart';

import 'otel_snyk_suppression.dart';

class SnykResult {
  /// Creates a result.
  const SnykResult({
    this.orgId,
    this.surface,
    this.projectId,
    this.projectType,
    this.packageManager,
    this.target,
    this.testCount,
    this.issuesTotal,
    this.issuesCritical,
    this.issuesHigh,
    this.issuesMedium,
    this.issuesLow,
    this.issuesFixable,
    this.dependenciesScanned,
    this.licenseIssues,
    this.containerImage,
    this.containerLayer,
    this.iacFileType,
    this.codeQualityIssues,
    this.snykCodeRuleId,
    this.severityThreshold,
    this.statusCode,
    this.errorCode,
    this.errorMessage,
  });

  final String? orgId;
  final String? surface;
  final String? projectId;
  final String? projectType;
  final String? packageManager;
  final String? target;
  final int? testCount;
  final int? issuesTotal;
  final int? issuesCritical;
  final int? issuesHigh;
  final int? issuesMedium;
  final int? issuesLow;
  final int? issuesFixable;
  final int? dependenciesScanned;
  final int? licenseIssues;
  final String? containerImage;
  final String? containerLayer;
  final String? iacFileType;
  final int? codeQualityIssues;
  final String? snykCodeRuleId;
  final String? severityThreshold;
  final int? statusCode;
  final String? errorCode;
  final String? errorMessage;
}

/// What a traced call returned: the value for the caller plus fields
/// recorded on the span.
class SnykCallResult<T> {
  /// Creates a call result.
  const SnykCallResult({required this.value, this.result});

  /// The value returned to the caller.
  final T value;
  final SnykResult? result;
}

Future<T> tracedSnyk<T>({
  required String operation,
  required Future<SnykCallResult<T>> Function() invoke,
  APITracer? tracer,
}) async {
  if (snykInstrumentationSuppressed()) {
    final r = await invoke();
    return r.value;
  }
  final t = tracer ?? OTelAPI.tracerProvider().getTracer('otel_snyk');
  final span = t.startSpan('snyk $operation', kind: SpanKind.client);
  try {
    span.addAttributes(
        OTelAPI.attributes([OTelAPI.attributeString('rpc.system', 'snyk')]));
    span.addAttributes(
        OTelAPI.attributes([OTelAPI.attributeString('rpc.method', operation)]));
    final r = await invoke();
    final res = r.result;
    if (res != null) {
      if (res.orgId != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.org.id', res.orgId!)]));
      }
      if (res.surface != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.surface', res.surface!)]));
      }
      if (res.projectId != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.project.id', res.projectId!)]));
      }
      if (res.projectType != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.project.type', res.projectType!)]));
      }
      if (res.packageManager != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeString('snyk.package_manager', res.packageManager!)
        ]));
      }
      if (res.target != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.target', res.target!)]));
      }
      if (res.testCount != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.test_count', res.testCount!)]));
      }
      if (res.issuesTotal != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.issues.total', res.issuesTotal!)]));
      }
      if (res.issuesCritical != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeInt('snyk.issues.critical', res.issuesCritical!)
        ]));
      }
      if (res.issuesHigh != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.issues.high', res.issuesHigh!)]));
      }
      if (res.issuesMedium != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.issues.medium', res.issuesMedium!)]));
      }
      if (res.issuesLow != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.issues.low', res.issuesLow!)]));
      }
      if (res.issuesFixable != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.issues.fixable', res.issuesFixable!)]));
      }
      if (res.dependenciesScanned != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeInt(
              'snyk.dependencies.scanned', res.dependenciesScanned!)
        ]));
      }
      if (res.licenseIssues != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeInt('snyk.license.issues', res.licenseIssues!)]));
      }
      if (res.containerImage != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeString('snyk.container.image', res.containerImage!)
        ]));
      }
      if (res.containerLayer != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeString('snyk.container.layer', res.containerLayer!)
        ]));
      }
      if (res.iacFileType != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.iac.file_type', res.iacFileType!)]));
      }
      if (res.codeQualityIssues != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeInt(
              'snyk.code.quality_issues', res.codeQualityIssues!)
        ]));
      }
      if (res.snykCodeRuleId != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeString('snyk.code.rule_id', res.snykCodeRuleId!)
        ]));
      }
      if (res.severityThreshold != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeString(
              'snyk.severity_threshold', res.severityThreshold!)
        ]));
      }
      if (res.statusCode != null) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeInt('http.response.status_code', res.statusCode!)
        ]));
      }
      if (res.errorCode != null) {
        span.addAttributes(OTelAPI.attributes(
            [OTelAPI.attributeString('snyk.error.code', res.errorCode!)]));
      }
      final fail = res.errorCode != null ||
          (res.statusCode != null && res.statusCode! >= 400);
      if (fail) {
        span.addAttributes(OTelAPI.attributes([
          OTelAPI.attributeString(
              ErrorAttributes.errorType.key, res.errorCode ?? 'snyk.error')
        ]));
        span.setStatus(SpanStatusCode.Error, res.errorMessage);
      }
    }
    return r.value;
  } catch (e, st) {
    span.recordException(e, stackTrace: st);
    span.setStatus(SpanStatusCode.Error, e.toString());
    rethrow;
  } finally {
    span.end();
  }
}
