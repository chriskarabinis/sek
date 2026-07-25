package subx

// DefaultWordlist is the built-in set of common subdomain prefixes used when no
// -w file is supplied.
var DefaultWordlist = []string{
	// Web
	"www", "www1", "www2", "www3", "web", "web1", "web2", "website",
	// Mail
	"mail", "mail1", "mail2", "smtp", "smtp1", "pop", "pop3", "imap",
	"webmail", "email", "mx", "mx1", "mx2", "mx3",
	// FTP / Files
	"ftp", "ftp1", "ftp2", "sftp", "files", "download", "downloads",
	"upload", "uploads",
	// API
	"api", "api1", "api2", "apis", "rest", "graphql", "v1", "v2", "v3",
	// Dev / Test / Staging
	"dev", "dev1", "dev2", "develop", "development",
	"test", "test1", "test2", "testing",
	"staging", "stage", "uat", "qa", "qa1",
	"sandbox", "demo", "preview", "beta", "alpha", "canary",
	// Production
	"prod", "production", "live",
	// Admin / Management
	"admin", "admin1", "administrator", "panel", "cpanel",
	"plesk", "manage", "management", "manager", "portal", "control",
	"dashboard", "dash",
	// Auth / Identity
	"auth", "oauth", "sso", "login", "signin", "signup",
	"account", "accounts", "user", "users", "id", "identity",
	// Security / Network
	"vpn", "vpn1", "vpn2", "remote", "ssh", "ssl",
	"secure", "security", "firewall", "fw", "proxy", "gateway",
	// DNS / NS
	"ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	// CDN / Static / Media
	"cdn", "cdn1", "cdn2", "static", "assets",
	"media", "img", "images", "image", "video", "videos",
	// Cloud / Storage
	"cloud", "aws", "azure", "gcp", "s3", "storage",
	"backup", "backups",
	// Apps / Mobile
	"app", "app1", "app2", "apps", "mobile", "m", "wap",
	// Monitoring / Analytics
	"monitor", "monitoring", "status", "health", "metrics",
	"grafana", "kibana", "prometheus", "nagios", "zabbix",
	"analytics", "stats", "statistics", "reports",
	// CI/CD / Git
	"ci", "cd", "jenkins", "gitlab", "git", "svn",
	"repo", "build", "builds", "deploy", "deployment", "pipeline",
	// Databases
	"db", "db1", "db2", "mysql", "postgres", "mongo", "redis",
	"elastic", "elasticsearch",
	// Support / Docs
	"support", "help", "helpdesk", "ticket", "tickets",
	"docs", "doc", "wiki", "kb", "blog", "news",
	"forum", "forums", "community",
	// Business
	"shop", "store", "commerce", "pay", "payment", "payments",
	"billing", "invoice", "crm",
	// Internal
	"internal", "intranet", "corp", "office", "private", "local",
	// Geographic
	"us", "eu", "uk", "de", "fr", "jp", "asia",
	// Old / Legacy
	"old", "new", "legacy", "archive", "beta2",
	// Misc
	"jira", "confluence", "slack", "zoom",
}
