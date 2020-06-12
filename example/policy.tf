resource "sysdig_secure_policy" "disallowed_network_activity" {
  name        = "Disallowed Network Activity"
  description = "Identified network activity outside of an explicitly defined set"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Disallowed SSH Connection", "Unexpected outbound connection destination", "Unexpected inbound connection source"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_filesystem_changes" {
  name        = "Suspicious Filesystem Changes"
  description = "Identified suspicious filesystem activity that might change sensitive/important files"
  enabled     = true
  severity    = 0
  scope       = ""
  rule_names  = ["Set Setuid or Setgid bit", "Create Symlink Over Sensitive Files", "Write below monitored dir", "Create files below dev", "Create Hidden Files or Directories", "Modify binary dirs", "Delete Bash History", "Write below binary dir", "Modify Shell Configuration File", "Write below root", "Schedule Cron Jobs", "Clear Log Activities", "Remove Bulk Data from Disk", "Mkdir binary dirs", "Delete or rename shell history"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "notable_filesystem_changes" {
  name        = "Notable Filesystem Changes"
  description = "Identified notable filesystem activity that might change sensitive/important files. This differs from Suspicious Filesystem Changes in that it looks more broadly at filesystem activity, and might have more false positives as a result."
  enabled     = false
  severity    = 0
  scope       = ""
  rule_names  = ["Write below etc"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_package_management_changes" {
  name        = "Suspicious Package Management Changes"
  description = "Identified attempts to change package management db/supporting files"
  enabled     = true
  severity    = 0
  scope       = ""
  rule_names  = ["Write below rpm database", "Update Package Repository"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_filesystem_reads" {
  name        = "Suspicious Filesystem Reads"
  description = "Identified attempts to read potentially sensitive/important files, or attempts to read files by programs that do not normally read them (e.g. non-ssh programs reading ssh keys, etc)."
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Search Private Keys or Passwords", "Read sensitive file untrusted", "Read Shell Configuration File", "Read ssh information", "Read sensitive file trusted after startup"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "unexpected_spawned_processes" {
  name        = "Unexpected Spawned Processes"
  description = "Identified unusual spawned processes by programs that do not normally spawn them (e.g. DB programs, shells by non-shell programs, etc.)"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Run shell untrusted", "System user interactive", "DB program spawned process"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "unexpected_process_activity" {
  name        = "Unexpected Process Activity"
  description = "Identified unusual processes activity outside of normal operation (changing thread namespaces, uids, etc)"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Non sudo setuid", "Change thread namespace"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "inadvised_container_activity" {
  name        = "Inadvised Container Activity"
  description = "Identified container activity going against best practices (e.g. excess/unnecessary permissions, etc)"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Launch Sensitive Mount Container", "Launch Privileged Container"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_container_activity" {
  name        = "Suspicious Container Activity"
  description = "Identified suspicious container-related activity (execs into containers, etc)"
  enabled     = true
  severity    = 0
  scope       = ""
  rule_names  = ["Contact cloud metadata service from container", "Packet socket created in container", "Redirect STDOUT/STDIN to Network Connection in Container", "Contact K8S API Server From Container", "Netcat Remote Code Execution in Container", "Launch Remote File Copy Tools in Container", "Unexpected K8s NodePort Connection", "Detect crypto miners using the Stratum protocol", "Contact EC2 Instance Metadata Service From Container", "The docker client is executed in a container", "Launch Suspicious Network Tool in Container", "Launch Package Management Process in Container", "Terminal shell in container"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "disallowed_container_activity" {
  name        = "Disallowed Container Activity"
  description = "Identified container activity outside of an explicitly allowed set"
  enabled     = true
  severity    = 0
  scope       = ""
  rule_names  = ["Launch Disallowed Container"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "user_management_changes" {
  name        = "User Management Changes"
  description = "Identified activity related to changing user/account information"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["User mgmt binaries"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_network_activity" {
  name        = "Suspicious Network Activity"
  description = "Identified unusual network activity e.g. programs that do not normally use network connections opening a network connection, etc."
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Interpreted procs outbound network activity", "System procs network activity", "Unexpected UDP Traffic", "Network Connection outside Local Subnet", "Interpreted procs inbound network activity", "Outbound or Inbound Traffic not to Authorized Server Process and Port", "Launch Suspicious Network Tool on Host", "Program run with disallowed http proxy env"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "access_cryptomining_network" {
  name        = "Access Cryptomining Network"
  description = "Identified unusual network connection to crytomining network (note: enable rule might trigger alert from cloud provider as policy engine will do DNS lookups for crytomining domain)"
  enabled     = false
  severity    = 7
  scope       = ""
  rule_names  = ["Detect crypto miners using the Stratum protocol", "Detect outbound connections to common miner pool ports"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "all_k8s_activity" {
  name        = "All K8s Activity"
  description = "Show all K8s Audit activity in the audit stream. This is likely a high volume of events and should not be enabled by default."
  enabled     = false
  severity    = 7
  scope       = ""
  rule_names  = ["All K8s Audit Events"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "all_k8s_user_modifications" {
  name        = "All K8s User Modifications"
  description = "Identify K8s Audit activity related to user/rbac changes (adding/removing/modifying users, roles, etc.)"
  enabled     = true
  severity    = 6
  scope       = ""
  rule_names  = ["K8s Role/Clusterrole Deleted", "K8s Role/Clusterrolebinding Deleted", "K8s Role/Clusterrole Created", "K8s Serviceaccount Deleted", "K8s Serviceaccount Created", "K8s Role/Clusterrolebinding Created"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "all_k8s_object_modifications" {
  name        = "All K8s Object Modifications"
  description = "Identify K8s Audit activity related to object changes (adding/removing/modifying pods, services, etc)."
  enabled     = false
  severity    = 6
  scope       = ""
  rule_names  = ["K8s Deployment Deleted", "K8s ConfigMap Created", "K8s Namespace Deleted", "K8s Secret Deleted", "K8s Secret Created", "K8s Namespace Created", "K8s Deployment Created", "K8s ConfigMap Deleted", "K8s Service Created", "K8s Service Deleted"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_k8s_activity" {
  name        = "Suspicious K8s Activity"
  description = "Identify Suspicious/Unexpected K8s Activity (execing into pods, etc.)"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Untrusted Node Successfully Joined the Cluster", "Attach/Exec Pod", "Untrusted Node Unsuccessfully Tried to Join the Cluster"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "inadvised_k8s_user_activity" {
  name        = "Inadvised K8s User Activity"
  description = "Identify inadvised K8s audit activity related to users/roles/rolebindings"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Anonymous Request Allowed", "Attach to cluster-admin Role", "Service Account Created in Kube Namespace", "ClusterRole With Pod Exec Created", "ClusterRole With Wildcard Created", "ClusterRole With Write Privileges Created"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "suspicious_k8s_user_activity" {
  name        = "Suspicious K8s User Activity"
  description = "Identify suspicious/unexpected K8s Activity related to users (modifying system roles/bindings, etc.)"
  enabled     = true
  severity    = 0
  scope       = ""
  rule_names  = ["System ClusterRole Modified/Deleted", "Full K8s Administrative Access"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "inadvised_k8s_activity" {
  name        = "Inadvised K8s Activity"
  description = "Identify inadvised K8s audit activity related to pods, services, etc."
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Ingress Object without TLS Certificate Created", "Create/Modify Configmap With Private Credentials", "Create Sensitive Mount Pod", "Create HostNetwork Pod", "Pod Created in Kube Namespace", "Create NodePort Service"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "create_privileged_pod" {
  name        = "Create Privileged Pod"
  description = "Identify a K8s pod being created with privileged=true"
  enabled     = true
  severity    = 4
  scope       = ""
  rule_names  = ["Create Privileged Pod"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "disallowed_k8s_activity" {
  name        = "Disallowed K8s Activity"
  description = "Identify K8s audit activity outside of an explicitly allowed set (images, users, etc)."
  enabled     = true
  severity    = 0
  scope       = ""
  rule_names  = ["Create Disallowed Namespace", "Create Disallowed Pod", "Disallowed K8s User"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "payment_card_industry_data_security_standard_pci_dss" {
  name        = "Payment Card Industry Data Security Standard (PCI DSS)"
  description = "Identified suspicious activity as described in as described in Payment Card Industry Data Security Standard (PCI DSS)"
  enabled     = false
  severity    = 4
  scope       = ""
  rule_names  = ["Clear Log Activities", "Modify binary dirs", "Mkdir binary dirs", "DB program spawned process", "Change thread namespace", "Launch Privileged Container", "Terminal shell in container"]

  actions {}

  notification_channels = []
}

resource "sysdig_secure_policy" "nist_800-190_application_container_security_guide" {
  name        = "NIST 800-190 Application Container Security Guide"
  description = "Identified suspicious activity as described in NIST 800-190 Application Container Security Guide"
  enabled     = false
  severity    = 4
  scope       = ""
  rule_names  = ["Launch Disallowed Container", "Disallowed SSH Connection", "Create Symlink Over Sensitive Files", "Write below monitored dir", "Create files below dev", "Modify binary dirs", "Unexpected inbound connection source", "Contact K8S API Server From Container", "Launch Privileged Container", "Write below binary dir", "Write below etc", "Write below root", "Launch Sensitive Mount Container", "Clear Log Activities", "Unexpected UDP Traffic", "Unexpected K8s NodePort Connection", "Unexpected outbound connection destination", "Mkdir binary dirs", "Search Private Keys or Passwords", "Read sensitive file untrusted"]

  actions {}

  notification_channels = []
}

