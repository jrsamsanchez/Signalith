package splcheck_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
	"gopkg.in/yaml.v3"
)

// packDir is the Splunk pack shipped with Signalith.
var packDir = filepath.Join("..", "detect", "packs", "splunk")

// readPack reads the shipped Splunk pack: its manifest, macros and lookup
// tables.
func readPack(t *testing.T) (*detect.Pack, map[string]*splcheck.Macro, map[string]*splcheck.Lookup) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(packDir, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var p detect.Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	macros := map[string]*splcheck.Macro{}
	files, _ := filepath.Glob(filepath.Join(packDir, "macros", "*.yml"))
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m, err := splcheck.ParseMacro(src)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		macros[m.Name] = m
	}
	lookups := map[string]*splcheck.Lookup{}
	files, _ = filepath.Glob(filepath.Join(packDir, "lookups", "*.yml"))
	for _, f := range files {
		meta, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		csv, err := os.ReadFile(strings.TrimSuffix(f, ".yml") + ".csv")
		if err != nil {
			t.Fatal(err)
		}
		l, err := splcheck.ParseLookup(meta, csv)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		lookups[l.Name] = l
	}
	p.UseMacros(macros)
	p.UseLookups(lookups)
	return &p, macros, lookups
}

// slowCases are the shipped rules whose test events take a second or
// more to synthesize (their where clauses and later stages have many
// alternatives to try): splunkgen makes them once, and they are left out
// here to keep the test quick.
var slowCases = map[string]bool{
	"3cx_supply_chain_attack_network_indicators.yml":                       true,
	"aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.yml":   true,
	"aws_ecr_container_scanning_findings_low_informational_unknown.yml":    true,
	"aws_ecr_container_scanning_findings_medium.yml":                       true,
	"azure_ad_block_user_consent_for_risky_apps_disabled.yml":              true,
	"azure_ad_new_mfa_method_registered.yml":                               true,
	"azure_ad_privileged_role_assigned_to_service_principal.yml":           true,
	"azure_ad_service_principal_owner_added.yml":                           true,
	"azure_ad_tenant_wide_admin_consent_granted.yml":                       true,
	"azure_ad_user_consent_blocked_for_risky_application.yml":              true,
	"create_or_delete_windows_shares_using_net_exe.yml":                    true,
	"curl_execution_with_percent_encoded_url.yml":                          true,
	"detect_new_open_s3_buckets.yml":                                       true,
	"detect_new_open_s3_buckets_over_aws_cli.yml":                          true,
	"detect_path_interception_by_creation_of_program_exe.yml":              true,
	"exploit_public_facing_application_via_apache_commons_text.yml":        true,
	"http_request_to_reserved_name_on_iis_server.yml":                      true,
	"linux_auditd_doas_conf_file_creation.yml":                             true,
	"linux_auditd_possible_access_or_modification_of_sshd_config_file.yml": true,
	"linux_auditd_possible_access_to_sudoers_file.yml":                     true,
	"linux_auditd_preload_hijack_via_preload_file.yml":                     true,
	"linux_auditd_unix_shell_configuration_modification.yml":               true,
	"linux_decode_base64_to_shell.yml":                                     true,
	"linux_magic_sysrq_key_abuse.yml":                                      true,
	"malicious_powershell_executed_as_a_service.yml":                       true,
	"o365_admin_consent_bypassed_by_service_principal.yml":                 true,
	"o365_advanced_audit_disabled.yml":                                     true,
	"o365_application_registration_owner_added.yml":                        true,
	"o365_block_user_consent_for_risky_apps_disabled.yml":                  true,
	"o365_email_suspicious_behavior_alert.yml":                             true,
	"o365_file_permissioned_application_consent_granted_by_user.yml":       true,
	"o365_high_privilege_role_granted.yml":                                 true,
	"o365_mail_permissioned_application_consent_granted_by_user.yml":       true,
	"o365_mailbox_inbox_folder_shared_with_all_users.yml":                  true,
	"o365_mailbox_read_access_granted_to_application.yml":                  true,
	"o365_multiple_mailboxes_accessed_via_api.yml":                         true,
	"o365_multiple_service_principals_created_by_sp.yml":                   true,
	"o365_multiple_service_principals_created_by_user.yml":                 true,
	"o365_new_email_forwarding_rule_created.yml":                           true,
	"o365_new_federated_domain_added.yml":                                  true,
	"o365_new_mfa_method_registered.yml":                                   true,
	"o365_privileged_role_assigned.yml":                                    true,
	"o365_privileged_role_assigned_to_service_principal.yml":               true,
	"o365_security_and_compliance_alert_triggered.yml":                     true,
	"o365_tenant_wide_admin_consent_granted.yml":                           true,
	"o365_user_consent_blocked_for_risky_application.yml":                  true,
	"okta_suspicious_use_of_a_session_cookie.yml":                          true,
	"powershell_environment_variable_execution.yml":                        true,
	"powershell_pinvoke_process_injection_api_chain.yml":                   true,
	"process_deleting_its_process_file_path.yml":                           true,
	"suspicious_kerberos_service_ticket_request.yml":                       true,
	"system_processes_run_from_unexpected_locations.yml":                   true,
	"windows_ad_same_domain_sid_history_addition.yml":                      true,
	"windows_admin_password_changed_by_non_admin.yml":                      true,
	"windows_admin_permission_discovery.yml":                               true,
	"windows_anomalous_registry_value_length_in_environment_key.yml":       true,
	"windows_attempt_to_stop_security_service.yml":                         true,
	"windows_chromium_browser_launched_with_small_window_size.yml":         true,
	"windows_cisco_secure_endpoint_related_service_stopped.yml":            true,
	"windows_exchange_autodiscover_ssrf_abuse.yml":                         true,
	"windows_file_and_directory_enable_readonly_permissions.yml":           true,
	"windows_filtering_platform_filter_added_to_block_edr_process.yml":     true,
	"windows_known_abused_dll_created.yml":                                 true,
	"windows_lolbas_executed_outside_expected_path.yml":                    true,
	"windows_modify_registry_with_md5_reg_key_name.yml":                    true,
	"windows_powershell_process_with_malicious_string.yml":                 true,
	"windows_powershell_script_block_with_malicious_string.yml":            true,
	"windows_proxy_execution_of__net_utilities_via_scripts.yml":            true,
	"windows_pua_named_pipe.yml":                                           true,
	"windows_registry_payload_injection.yml":                               true,
	"windows_remote_access_software_brc4_loaded_dll.yml":                   true,
	"windows_renamed_python_binary_was_executed.yml":                       true,
	"windows_replication_through_removable_media.yml":                      true,
	"windows_rmm_named_pipe.yml":                                           true,
	"windows_rundll32_with_non_standard_file_extension.yml":                true,
	"windows_security_and_backup_services_stop.yml":                        true,
	"windows_suspicious_c2_named_pipe.yml":                                 true,
	"windows_suspicious_named_pipe.yml":                                    true,
	"windows_unsigned_dll_side_loading_in_same_process_path.yml":           true,
	"windows_unsigned_ms_dll_side_loading.yml":                             true,
	"windows_vulnerable_driver_installed.yml":                              true,
	"windows_windbg_spawning_autoit3.yml":                                  true,
	"wmi_permanent_event_subscription.yml":                                 true,
}

// TestShippedRulesSynthesizeAgreeingCases makes the test events of each
// shipped Splunk rule again, as splunkgen does, and requires what the
// pack promises of them: at least one event the rule finds, and the
// converted detection agreeing with Splunk's reading of the search on
// every one. A change to how splcheck reads searches or makes events that
// breaks a rule fails here by name, before the pack is next generated.
func TestShippedRulesSynthesizeAgreeingCases(t *testing.T) {
	p, macros, lookups := readPack(t)
	checked := 0
	for _, pr := range p.Rules {
		if slowCases[pr.File] {
			continue
		}
		src, err := os.ReadFile(filepath.Join(packDir, "rules", pr.File))
		if err != nil {
			t.Fatal(err)
		}
		r, err := splcheck.ParseWith(src, macros, splcheck.ParseOptions{Network: detect.SplunkNetworkRule(pr.Path), Lookups: lookups})
		if err != nil {
			t.Errorf("%s: %v", pr.ID, err)
			continue
		}
		d, err := detect.PackDetection(p, pr, src)
		if err != nil {
			t.Errorf("%s: %v", pr.ID, err)
			continue
		}
		q, err := query.Parse(d.Query)
		if err != nil {
			t.Errorf("%s: %v", pr.ID, err)
			continue
		}
		cs := splcheck.Cases(r)
		if !slices.ContainsFunc(cs, func(c sigmacheck.Case) bool { return c.Expect }) {
			t.Errorf("%s: no event the rule finds: %s", pr.ID, splcheck.NoEventsReason(r, cs))
			continue
		}
		if errs := splcheck.Verify(r, q, &sigmacheck.TestFile{Rule: r.ID, Cases: cs}); len(errs) > 0 {
			t.Errorf("%s: %v", pr.ID, errs[0])
		}
		checked++
	}
	if checked < len(p.Rules)/2 {
		t.Errorf("checked %d of %d rules", checked, len(p.Rules))
	}
}
