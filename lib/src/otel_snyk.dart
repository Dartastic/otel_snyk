// Licensed under the Dartastic Pro Software License Agreement.
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry_api/dartastic_opentelemetry_api.dart';

import 'otel_snyk_suppression.dart';

class SnykResult {
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

class SnykCallResult<T> {
  const SnykCallResult({required this.value, this.result});
  final T value;
  final SnykResult? result;
}

Future<T> tracedSnyk<T>({
  required String operation,
  required Future<SnykCallResult<T>> Function() invoke,
  Tracer? tracer,
}) async {
  if (snykInstrumentationSuppressed()) {
    final r = await invoke();
    return r.value;
  }
  final t = tracer ?? OTel.tracerProvider().getTracer('otel_snyk');
  final span = t.startSpan('snyk $operation', kind: SpanKind.client);
  try {
    span.setStringAttribute('rpc.system', 'snyk');
    span.setStringAttribute('rpc.method', operation);
    final r = await invoke();
    final res = r.result;
    if (res != null) {
      if (res.orgId != null) {
        span.setStringAttribute('snyk.org.id', res.orgId!);
      }
      if (res.surface != null) {
        span.setStringAttribute('snyk.surface', res.surface!);
      }
      if (res.projectId != null) {
        span.setStringAttribute('snyk.project.id', res.projectId!);
      }
      if (res.projectType != null) {
        span.setStringAttribute('snyk.project.type', res.projectType!);
      }
      if (res.packageManager != null) {
        span.setStringAttribute('snyk.package_manager', res.packageManager!);
      }
      if (res.target != null) {
        span.setStringAttribute('snyk.target', res.target!);
      }
      if (res.testCount != null) {
        span.setIntAttribute('snyk.test_count', res.testCount!);
      }
      if (res.issuesTotal != null) {
        span.setIntAttribute('snyk.issues.total', res.issuesTotal!);
      }
      if (res.issuesCritical != null) {
        span.setIntAttribute('snyk.issues.critical', res.issuesCritical!);
      }
      if (res.issuesHigh != null) {
        span.setIntAttribute('snyk.issues.high', res.issuesHigh!);
      }
      if (res.issuesMedium != null) {
        span.setIntAttribute('snyk.issues.medium', res.issuesMedium!);
      }
      if (res.issuesLow != null) {
        span.setIntAttribute('snyk.issues.low', res.issuesLow!);
      }
      if (res.issuesFixable != null) {
        span.setIntAttribute('snyk.issues.fixable', res.issuesFixable!);
      }
      if (res.dependenciesScanned != null) {
        span.setIntAttribute(
            'snyk.dependencies.scanned', res.dependenciesScanned!);
      }
      if (res.licenseIssues != null) {
        span.setIntAttribute('snyk.license.issues', res.licenseIssues!);
      }
      if (res.containerImage != null) {
        span.setStringAttribute('snyk.container.image', res.containerImage!);
      }
      if (res.containerLayer != null) {
        span.setStringAttribute('snyk.container.layer', res.containerLayer!);
      }
      if (res.iacFileType != null) {
        span.setStringAttribute('snyk.iac.file_type', res.iacFileType!);
      }
      if (res.codeQualityIssues != null) {
        span.setIntAttribute(
            'snyk.code.quality_issues', res.codeQualityIssues!);
      }
      if (res.snykCodeRuleId != null) {
        span.setStringAttribute('snyk.code.rule_id', res.snykCodeRuleId!);
      }
      if (res.severityThreshold != null) {
        span.setStringAttribute(
            'snyk.severity_threshold', res.severityThreshold!);
      }
      if (res.statusCode != null) {
        span.setIntAttribute('http.response.status_code', res.statusCode!);
      }
      if (res.errorCode != null) {
        span.setStringAttribute('snyk.error.code', res.errorCode!);
      }
      final fail = res.errorCode != null ||
          (res.statusCode != null && res.statusCode! >= 400);
      if (fail) {
        span.setStringAttribute(
            ErrorResource.errorType.key, res.errorCode ?? 'snyk.error');
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
