package ingest

// cloudRuleFields are the fields of cloud records that the shipped rules
// read, beyond the ones each parser maps already (cloudTrailMapped,
// azureMapped, o365Mapped). The index template maps them up front, so
// names a caller chooses (a call's parameters, an audit record's
// properties) can't use up a day's budget of new names and leave a
// rule's fields out of the index. TestCloudRuleFieldsMapped in
// internal/detect checks the list stays complete.
var cloudRuleFields = []string{
	// AWS CloudTrail.
	"additionalEventData.MFAUsed", "userIdentity.sessionContext.sessionIssuer.type",
	"requestParameters.VersioningConfiguration.Status", "requestParameters.attribute", "requestParameters.egress",
	"requestParameters.masterUserPassword", "requestParameters.x-amz-server-side-encryption",
	"responseElements.publiclyAccessible",
	// Entra ID and Azure.
	"properties.activityDisplayName", "properties.appDisplayName", "properties.appId",
	"properties.authenticationDetails{}.succeeded", "properties.authenticationProtocol",
	"properties.authenticationRequirement", "properties.category", "properties.conditionalAccessStatus",
	"properties.deviceDetail.deviceId", "properties.deviceDetail.isCompliant", "properties.deviceDetail.trustType",
	"properties.initiatedBy.app.appId", "properties.initiatedBy.app.displayName", "properties.initiatedBy.user.id",
	"properties.loggedByService", "properties.message", "properties.networkLocationDetails", "properties.operationType",
	"properties.resourceDisplayName", "properties.result", "properties.riskEventType", "properties.riskLevel",
	"properties.riskState", "properties.status.additionalDetails", "properties.status.errorCode",
	"properties.targetResources{}.displayName", "properties.targetResources{}.modifiedProperties{}.displayName",
	"properties.targetResources{}.modifiedProperties{}.newValue", "properties.userAgent",
	// Microsoft 365.
	"AppId", "ApplicationId", "Category", "ClientAppId", "ClientInfoString", "DeliveryAction", "Directionality",
	"ErrorNumber", "LogonError", "Name", "Payload",
}
