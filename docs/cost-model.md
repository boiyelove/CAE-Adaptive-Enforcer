# Cost model

The reference template uses an Elastic Premium Functions plan for predictable
warm execution, geo-redundant Storage with versioning/immutability, Event Grid,
Application Insights, and Log Analytics. Fixed Premium compute dominates light
loads; variable drivers are events, Graph calls, storage versions, log volume,
retention, and egress.

Price the target region immediately before deployment. Set budgets and alerts,
cap event schema size, tune telemetry sampling without dropping security
failures, and model immutable retention growth because protected versions cannot
be deleted early. `deployPlatform=false` is the safe default.
