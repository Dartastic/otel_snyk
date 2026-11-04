// Licensed under the Apache License, Version 2.0
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:otel_snyk/otel_snyk.dart';

/// Traces Snyk calls with OpenTelemetry.
///
/// `otel_snyk` depends on the OpenTelemetry API only, so the application
/// initializes an SDK once at startup. Wrap each Snyk call in
/// [tracedSnyk]; the `invoke` callback makes the real call and reports what
/// came back, which is recorded on the span.
Future<void> main() async {
  await OTel.initialize(serviceName: 'snyk-example');

  // Traces a Snyk call.
  final snykId = await tracedSnyk<String>(
    operation: 'create',
    invoke: () async {
      // Make the Snyk call here, then report what it returned.
      const id = 'snyk_8f3a2c';
      return const SnykCallResult(
          value: id,
          result: SnykResult(
              orgId: 'org_8f3a2c',
              surface: 'example',
              projectId: 'project_8f3a2c',
              projectType: 'standard',
              packageManager: 'example',
              target: 'example',
              testCount: 3,
              issuesTotal: 1,
              issuesCritical: 1,
              issuesHigh: 1,
              issuesMedium: 1,
              issuesLow: 1,
              issuesFixable: 1,
              dependenciesScanned: 1,
              licenseIssues: 1,
              containerImage: 'example',
              containerLayer: 'example',
              iacFileType: 'standard',
              codeQualityIssues: 1,
              snykCodeRuleId: 'snykcoderule_8f3a2c',
              severityThreshold: 'example',
              statusCode: 201,
              errorCode: 'example',
              errorMessage: 'example'));
    },
  );
  OTelLog.info('tracedSnyk create returned $snykId');

  // Calls that should not be traced, such as health checks, run inside
  // runWithoutSnykInstrumentationAsync.
  await runWithoutSnykInstrumentationAsync(
    () => tracedSnyk<String>(
      operation: 'create',
      invoke: () async {
        const id = 'snyk_8f3a2c';
        return const SnykCallResult(
            value: id,
            result: SnykResult(
                orgId: 'org_8f3a2c',
                surface: 'example',
                projectId: 'project_8f3a2c',
                projectType: 'standard',
                packageManager: 'example',
                target: 'example',
                testCount: 3,
                issuesTotal: 1,
                issuesCritical: 1,
                issuesHigh: 1,
                issuesMedium: 1,
                issuesLow: 1,
                issuesFixable: 1,
                dependenciesScanned: 1,
                licenseIssues: 1,
                containerImage: 'example',
                containerLayer: 'example',
                iacFileType: 'standard',
                codeQualityIssues: 1,
                snykCodeRuleId: 'snykcoderule_8f3a2c',
                severityThreshold: 'example',
                statusCode: 201,
                errorCode: 'example',
                errorMessage: 'example'));
      },
    ),
  );

  await OTel.shutdown();
}
