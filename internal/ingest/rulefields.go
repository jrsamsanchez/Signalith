package ingest

// cloudRuleFields are the fields of cloud records that the shipped rules
// read, beyond the ones each parser maps already (cloudTrailMapped,
// azureMapped, o365Mapped, oktaMapped). The index template maps them up front, so
// names a caller chooses (a call's parameters, an audit record's
// properties) can't use up a day's budget of new names and leave a
// rule's fields out of the index. TestCloudRuleFieldsMapped in
// internal/detect checks the list stays complete.
var cloudRuleFields = []string{
	// AWS CloudTrail.
	"additionalEventData.MFAUsed", "userIdentity.sessionContext.sessionIssuer.type",
	"requestParameters.VersioningConfiguration.Status", "requestParameters.attribute", "requestParameters.bucketName", "requestParameters.egress",
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
	// Read by the later stages of Microsoft 365 rules (stats values(...)).
	"DetectionMethod", "FileData.FileName", "FileData.FilePath", "FileData.FileSize", "FileData.MalwareFamily", "Id",
	"ModifiedProperties{}.NewValue", "Item.ParentFolder.MemberRights", "Item.ParentFolder.MemberUpn", "SessionId",
	"SiteUrl", "SourceFileName", "UserAgent", "ZipFileName", "AlertId", "ModifiedProperties{}.Name", "ClientIPAddress",
	"MailboxOwnerUPN",
	// A stats group of Microsoft 365 rules that the records lack ("unknown").
	"authentication_service",
	// Google Workspace: an admin event's parameters.
	"event_parameters.new_value", "event_parameters.setting_name",
	// Okta: what an event's debugData says, whose names vary by event.
	"debugContext.debugData.behaviors", "debugContext.debugData.factor", "debugContext.debugData.logOnlySecurityData",
	"debugContext.debugData.url", "debugContext.debugData.dtHash",
	// Okta: the client of a sign-on, read by later stages.
	"client.geographicalContext.city", "client.userAgent.browser", "client.userAgent.os",
}
