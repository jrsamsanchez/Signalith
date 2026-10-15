package agents

// The Microsoft Entra ID and Azure option: an OpenTelemetry Collector that
// reads the logs Entra ID and Azure stream to an Azure Event Hub and
// sends their records to Signalith. Entra ID's diagnostic settings send
// its sign-ins, audit log and risk detections there, and each
// subscription's diagnostic settings its activity log; the Collector's
// azure_event_hub receiver passes each message on whole (format raw), and
// Signalith splits it into records. The Collector runs anywhere it can
// reach Azure and Signalith, and gets the event hub's connection string
// from its environment, so the configuration does not hold it.

// azureHubEnv is the environment variable the Collector reads the event
// hub's connection string from.
const azureHubEnv = "SIGNALITH_EVENT_HUB"

// azureHubName is the event hub the steps have the admin create.
const azureHubName = "signalith"

// azureReceiver is the azure_event_hub receiver of the Collector's config.
func azureReceiver() string {
	return "  azure_event_hub/signalith:\n" +
		"    connection: ${env:" + azureHubEnv + "}\n" +
		"    format: raw\n" +
		"    storage: file_storage/signalith\n"
}

// azureSteps are the Azure side of the setup, before the Collector's own.
func azureSteps() []string {
	return []string{
		"In the Azure portal, create an Event Hubs namespace (Standard tier) and, in it, an event hub named " + azureHubName + ".",
		"In the " + azureHubName + " event hub's Shared access policies, add a policy with Listen only, and copy its Connection string-primary key. The Collector gets it in a later step; keep it private, as it lets anyone read your logs.",
		"Send Entra ID's logs to it: in the Microsoft Entra admin center, open Monitoring & health > Diagnostic settings > Add diagnostic setting, tick AuditLogs, SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, ManagedIdentitySignInLogs, RiskyUsers and UserRiskEvents, choose Stream to an event hub, and pick the namespace and the " + azureHubName + " event hub. Sign-in logs need Microsoft Entra ID P1 or P2.",
		"Send each Azure subscription's activity log there too: in the Azure portal, open Monitor > Activity log > Export Activity Logs, pick the subscription, add a diagnostic setting with Administrative, Security, Policy and Alert ticked, and stream it to the same event hub.",
	}
}
