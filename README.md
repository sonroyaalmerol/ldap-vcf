Environment Variables:
Set these environment variables before running the program (or in your Dockerfile or container runtime configuration):

LDAP_URL: (Required) URL of the LDAP server (e.g., ldap://ldap.example.com:389, ldaps://secure-ldap.example.com:636).
LDAP_BIND_DN: (Optional) Distinguished Name to bind as (e.g., cn=readonly,dc=example,dc=com). If empty, anonymous bind is attempted.
LDAP_BIND_PASSWORD: (Optional) Password for the Bind DN.
LDAP_BASE_DN: (Required) Base DN for the search (e.g., ou=users,dc=example,dc=com).
LDAP_SEARCH_FILTER: (Optional) LDAP filter for selecting entries (e.g., (&(objectClass=inetOrgPerson)(employeeType=active))). Defaults to (objectClass=*).
LDAP_ATTRIBUTE_MAPPING: (Required) Comma-separated list mapping vCard fields to LDAP attributes.

Format: VCF_FIELD:LDAP_ATTR,VCF_FIELD;PARAM=VALUE:LDAP_ATTR,...
Special N field: Use N:sn_attr;gn_attr to map surname and given name attributes (e.g., N:sn;givenName).
Example: FN:cn,N:sn;givenName,EMAIL;TYPE=work:mail,TEL;TYPE=work,VOICE:telephoneNumber,TEL;TYPE=mobile,VOICE:mobile,ORG:o,TITLE:title


VCF_OUTPUT_FILE: (Optional) Path where the generated VCF file will be saved. Defaults to contacts.vcf. Ensure the directory exists and is writable by the container user. Mount a volume here in Docker.
CRON_SCHEDULE: (Optional) Cron expression (e.g., 0 2 * * * for 2 AM daily). If empty or not set, the script runs once and exits. See robfig/cron documentation for syntax.
LDAP_USE_TLS: (Optional) Set to true to enable StartTLS on a non-LDAPS connection (ldap://). Defaults to false.
LDAP_SKIP_TLS_VERIFY: (Optional) Set to true to skip verification of the server's TLS certificate (useful for self-signed certs, use with caution). Defaults to false.
