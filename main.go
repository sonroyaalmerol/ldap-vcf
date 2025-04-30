package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/robfig/cron/v3"
)

type Config struct {
	LdapURL           string
	LdapBindDN        string
	LdapBindPassword  string
	LdapBaseDN        string
	LdapSearchFilter  string
	LdapUseTLS        bool
	LdapSkipTLSVerify bool
	AttributeMapping  map[string]string // vCard Field -> LDAP Attribute(s)
	VcfOutputFile     string
	CronSchedule      string
}

// vCardField represents a parsed vCard field from the mapping config
type vCardField struct {
	Name       string
	Parameters map[string]string
}

// ldapAttributes holds the required LDAP attributes based on the mapping
type ldapAttributes struct {
	All       []string          // List of all unique LDAP attributes needed
	NameAttrs map[string]string // Special handling for N field (e.g., "sn", "gn")
}

const (
	// Special vCard field key for structured Name (Surname;GivenName;Middle;Prefix;Suffix)
	vCardNameField = "N"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Parse the attribute mapping string into a usable map
	parsedMapping, ldapAttrsToFetch, err := parseMapping(cfg.AttributeMapping)
	if err != nil {
		log.Fatalf("Error parsing attribute mapping: %v", err)
	}

	// Function to perform the actual conversion
	conversionFunc := func() {
		log.Println("Starting LDAP to VCF conversion...")
		err := runConversion(cfg, parsedMapping, ldapAttrsToFetch)
		if err != nil {
			log.Printf("Conversion failed: %v", err)
		} else {
			log.Printf("Conversion successful. VCF file written to %s", cfg.VcfOutputFile)
		}
	}

	// Run once immediately if no schedule is defined
	if cfg.CronSchedule == "" {
		log.Println("No CRON_SCHEDULE defined. Running conversion once.")
		conversionFunc()
		log.Println("Exiting after single run.")
		return
	}

	// Set up and run the cron scheduler
	log.Printf("CRON_SCHEDULE '%s' defined. Running in scheduled mode.", cfg.CronSchedule)
	c := cron.New(cron.WithChain(
		cron.SkipIfStillRunning(cron.DefaultLogger), // Don't run if previous job is still active
	))

	_, err = c.AddFunc(cfg.CronSchedule, conversionFunc)
	if err != nil {
		log.Fatalf("Error adding cron job (schedule '%s'): %v", cfg.CronSchedule, err)
	}

	// Run once immediately on startup as well? Optional.
	// go conversionFunc() // Uncomment to run immediately in background

	c.Start()
	log.Println("Cron scheduler started. Waiting for jobs...")

	// Keep the application running
	select {} // Block forever
}

// loadConfig reads configuration from environment variables.
func loadConfig() (*Config, error) {
	cfg := &Config{
		// Provide defaults where sensible
		LdapURL:           getEnv("LDAP_URL", ""),
		LdapBindDN:        getEnv("LDAP_BIND_DN", ""),
		LdapBindPassword:  getEnv("LDAP_BIND_PASSWORD", ""),
		LdapBaseDN:        getEnv("LDAP_BASE_DN", ""),
		LdapSearchFilter:  getEnv("LDAP_SEARCH_FILTER", "(objectClass=*)"), // Default: find everything
		VcfOutputFile:     getEnv("VCF_OUTPUT_FILE", "contacts.vcf"),
		CronSchedule:      getEnv("CRON_SCHEDULE", ""),
		AttributeMapping:  make(map[string]string), // Parsed later
		LdapUseTLS:        getEnvAsBool("LDAP_USE_TLS", false),
		LdapSkipTLSVerify: getEnvAsBool("LDAP_SKIP_TLS_VERIFY", false),
	}

	// Basic validation
	if cfg.LdapURL == "" {
		return nil, fmt.Errorf("LDAP_URL environment variable is required")
	}
	if cfg.LdapBaseDN == "" {
		return nil, fmt.Errorf("LDAP_BASE_DN environment variable is required")
	}
	// Bind DN/Password can be empty for anonymous bind, but often required.
	// Add more validation as needed.

	// Load the raw mapping string
	mappingStr := getEnv("LDAP_ATTRIBUTE_MAPPING", "")
	if mappingStr == "" {
		return nil, fmt.Errorf("LDAP_ATTRIBUTE_MAPPING environment variable is required")
	}
	// Temporarily store the raw string; parsing happens in main
	cfg.AttributeMapping["_raw_"] = mappingStr

	return cfg, nil
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	log.Printf("Environment variable %s not set, using default: %s", key, fallback)
	return fallback
}

// getEnvAsBool retrieves an environment variable as a boolean.
func getEnvAsBool(key string, fallback bool) bool {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}
	valBool, err := strconv.ParseBool(strings.ToLower(valStr))
	if err != nil {
		log.Printf("Warning: Could not parse %s value '%s' as boolean: %v. Using default: %t", key, valStr, err, fallback)
		return fallback
	}
	return valBool
}

// parseMapping parses the LDAP_ATTRIBUTE_MAPPING string.
// Format: "vCardField1:ldapAttr1,vCardField2;PARAM=val:ldapAttr2,N:sn;gn,..."
// Returns the parsed mapping (vCard Field -> LDAP Attr), required LDAP attributes, and error.
func parseMapping(rawMapping map[string]string) (map[string]string, *ldapAttributes, error) {
	mappingStr := rawMapping["_raw_"]
	if mappingStr == "" {
		return nil, nil, fmt.Errorf("attribute mapping string is empty")
	}

	parsed := make(map[string]string)
	ldapAttrSet := make(map[string]struct{}) // Use a set for uniqueness
	nameAttrMap := make(map[string]string)   // For N field components

	pairs := strings.Split(mappingStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			log.Printf("Warning: Skipping invalid mapping pair '%s'", pair)
			continue
		}
		vCardKey := strings.TrimSpace(parts[0])
		ldapVal := strings.TrimSpace(parts[1])

		if vCardKey == "" || ldapVal == "" {
			log.Printf("Warning: Skipping mapping pair with empty key or value '%s'", pair)
			continue
		}

		parsed[vCardKey] = ldapVal

		// Special handling for the structured Name (N) field
		if strings.HasPrefix(strings.ToUpper(vCardKey), vCardNameField) {
			// Expecting ldapVal like "sn;gn" or "surnameAttr;givenNameAttr;..."
			nameComponents := strings.Split(ldapVal, ";")
			if len(nameComponents) >= 1 && nameComponents[0] != "" {
				nameAttrMap["sn"] = nameComponents[0] // Surname
				ldapAttrSet[nameComponents[0]] = struct{}{}
			}
			if len(nameComponents) >= 2 && nameComponents[1] != "" {
				nameAttrMap["gn"] = nameComponents[1] // Given Name
				ldapAttrSet[nameComponents[1]] = struct{}{}
			}
			// Add more components (Middle, Prefix, Suffix) if needed
		} else {
			// For regular fields, add the LDAP attribute to the set
			ldapAttrSet[ldapVal] = struct{}{}
		}
	}

	if len(parsed) == 0 {
		return nil, nil, fmt.Errorf("no valid mappings found in LDAP_ATTRIBUTE_MAPPING")
	}

	// Convert the set to a slice
	allLdapAttrs := make([]string, 0, len(ldapAttrSet))
	for attr := range ldapAttrSet {
		allLdapAttrs = append(allLdapAttrs, attr)
	}

	ldapInfo := &ldapAttributes{
		All:       allLdapAttrs,
		NameAttrs: nameAttrMap,
	}

	return parsed, ldapInfo, nil
}

// parseVCardFieldKey breaks down a vCard field key like "TEL;TYPE=work;TYPE=voice"
// into its name ("TEL") and parameters (map[string][]string).
// For simplicity here, we only handle one value per param like "TYPE=work".
func parseVCardFieldKey(key string) vCardField {
	parts := strings.Split(key, ";")
	field := vCardField{
		Name:       strings.ToUpper(parts[0]),
		Parameters: make(map[string]string),
	}
	for i := 1; i < len(parts); i++ {
		paramParts := strings.SplitN(parts[i], "=", 2)
		if len(paramParts) == 2 {
			paramName := strings.ToUpper(strings.TrimSpace(paramParts[0]))
			paramValue := strings.TrimSpace(paramParts[1])
			// Simple approach: last parameter wins if duplicated
			field.Parameters[paramName] = paramValue
		} else {
			// Handle valueless parameters if needed (e.g., ;PREF)
			paramName := strings.ToUpper(strings.TrimSpace(paramParts[0]))
			field.Parameters[paramName] = "" // Or handle as boolean flag
		}
	}
	return field
}

// runConversion connects to LDAP, searches, and generates the VCF file.
func runConversion(cfg *Config, mapping map[string]string, ldapAttrs *ldapAttributes) error {
	l, err := connectLDAP(cfg)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer l.Close()

	// Bind (authenticate)
	if cfg.LdapBindDN != "" {
		err = l.Bind(cfg.LdapBindDN, cfg.LdapBindPassword)
		if err != nil {
			// Mask password in log if present
			maskedErr := strings.Replace(err.Error(), cfg.LdapBindPassword, "[REDACTED]", -1)
			return fmt.Errorf("LDAP bind failed for DN %s: %s", cfg.LdapBindDN, maskedErr)
		}
		log.Printf("LDAP bind successful for DN: %s", cfg.LdapBindDN)
	} else {
		log.Println("Attempting anonymous LDAP bind.")
		// Depending on server config, anonymous bind might require an explicit Bind() call
		// or might work implicitly with the search. Test with your server.
		// err = l.UnauthenticatedBind("") // Example if explicit call needed
		// if err != nil {
		//     return fmt.Errorf("LDAP anonymous bind failed: %w", err)
		// }
	}

	// Ensure all necessary attributes (including name components) are requested
	attributesToFetch := ldapAttrs.All
	log.Printf("Requesting LDAP attributes: %v", attributesToFetch)
	if len(attributesToFetch) == 0 {
		log.Println("Warning: No LDAP attributes derived from mapping. Fetching all attributes (*).")
		attributesToFetch = []string{"*"} // Or consider fetching a minimal default set
	}

	searchRequest := ldap.NewSearchRequest(
		cfg.LdapBaseDN,
		ldap.ScopeWholeSubtree, // Or ldap.ScopeSingleLevel, ldap.ScopeBaseObject
		ldap.NeverDerefAliases, // Or ldap.DerefAlways, ldap.DerefFinding, ldap.DerefSearching
		0,                      // Size limit (0 = server default)
		0,                      // Time limit (0 = server default)
		false,                  // Types only (false = fetch values)
		cfg.LdapSearchFilter,   // The filter string
		attributesToFetch,      // Attributes to retrieve
		nil,                    // Controls (e.g., for paging)
	)

	log.Printf("Performing LDAP search with BaseDN='%s', Filter='%s'", cfg.LdapBaseDN, cfg.LdapSearchFilter)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}

	log.Printf("LDAP search completed. Found %d entries.", len(sr.Entries))

	// --- VCF File Generation ---
	file, err := os.Create(cfg.VcfOutputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", cfg.VcfOutputFile, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush() // Ensure buffer is written at the end

	for _, entry := range sr.Entries {
		vcfEntry := generateVCardEntry(entry, mapping, ldapAttrs)
		if vcfEntry != "" {
			_, err = writer.WriteString(vcfEntry)
			if err != nil {
				log.Printf("Warning: Failed to write VCF entry for DN %s: %v", entry.DN, err)
				// Decide whether to continue or return error
			}
		} else {
			log.Printf("Skipping VCF entry generation for DN %s (likely missing essential mapped fields)", entry.DN)
		}
	}

	return nil // Success
}

// connectLDAP establishes a connection to the LDAP server.
func connectLDAP(cfg *Config) (*ldap.Conn, error) {
	// Parse URL to check scheme
	u, err := url.Parse(cfg.LdapURL)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP_URL: %w", err)
	}

	isTLS := false
	if strings.ToLower(u.Scheme) == "ldaps" {
		isTLS = true
	}

	var l *ldap.Conn
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.LdapSkipTLSVerify}

	if isTLS {
		log.Printf("Connecting to LDAP server %s using LDAPS (TLS)...", u.Host)
		l, err = ldap.DialURL(cfg.LdapURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		log.Printf("Connecting to LDAP server %s using LDAP...", u.Host)
		l, err = ldap.DialURL(cfg.LdapURL)
	}

	if err != nil {
		return nil, fmt.Errorf("cannot dial LDAP server: %w", err)
	}

	// Handle StartTLS if configured and not already using LDAPS
	if !isTLS && cfg.LdapUseTLS {
		log.Println("Attempting StartTLS...")
		err = l.StartTLS(tlsConfig)
		if err != nil {
			l.Close() // Close connection if StartTLS fails
			return nil, fmt.Errorf("StartTLS failed: %w", err)
		}
		log.Println("StartTLS successful.")
	}

	return l, nil
}

// generateVCardEntry creates a single VCF entry string from an LDAP entry.
func generateVCardEntry(entry *ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) string {
	var sb strings.Builder
	hasEssentialData := false // Track if we added at least one useful field

	sb.WriteString("BEGIN:VCARD\n")
	sb.WriteString("VERSION:3.0\n")
	// Add UID based on DN or another unique attribute if desired
	// sb.WriteString(fmt.Sprintf("UID:%s\n", entry.DN)) // Example

	// Process mapped fields
	for vCardKey, ldapAttr := range mapping {
		field := parseVCardFieldKey(vCardKey)

		// Special handling for N (Name)
		if field.Name == vCardNameField {
			sn := entry.GetAttributeValue(ldapAttrs.NameAttrs["sn"])
			gn := entry.GetAttributeValue(ldapAttrs.NameAttrs["gn"])
			// Add more components (middle, prefix, suffix) if mapped

			// Only write N field if at least surname or given name exists
			if sn != "" || gn != "" {
				// Format: N:Family;Given;Middle;Prefix;Suffix (leave empty components blank)
				sb.WriteString(fmt.Sprintf("%s:%s;%s;;;\n", field.Name, escapeVCardValue(sn), escapeVCardValue(gn)))
				hasEssentialData = true
			}
			continue // Skip generic processing for N field
		}

		// Generic handling for other fields
		values := entry.GetAttributeValues(ldapAttr)
		if len(values) > 0 {
			hasEssentialData = true // Mark that we have data for this entry
			for _, value := range values {
				if value != "" {
					sb.WriteString(field.Name)
					// Add parameters
					for paramName, paramValue := range field.Parameters {
						sb.WriteString(";")
						sb.WriteString(paramName)
						if paramValue != "" {
							sb.WriteString("=")
							// Parameter values might need escaping too, but often simple types
							sb.WriteString(paramValue)
						}
					}
					sb.WriteString(":")
					sb.WriteString(escapeVCardValue(value))
					sb.WriteString("\n")
				}
			}
		}
	}

	// Add FN (Formatted Name) - often required. Try to construct it.
	// Attempt to get CN first, otherwise combine GN and SN.
	fn := entry.GetAttributeValue("cn") // Common Name is often used for FN
	if fn == "" {
		gn := entry.GetAttributeValue(ldapAttrs.NameAttrs["gn"])
		sn := entry.GetAttributeValue(ldapAttrs.NameAttrs["sn"])
		fn = strings.TrimSpace(gn + " " + sn)
	}

	if fn != "" {
		sb.WriteString(fmt.Sprintf("FN:%s\n", escapeVCardValue(fn)))
		hasEssentialData = true
	} else if !hasEssentialData {
		// If we still have no FN and no other essential data, this entry is likely useless
		return "" // Return empty string to indicate skipping this entry
	}

	sb.WriteString("END:VCARD\n")

	return sb.String()
}

// escapeVCardValue handles basic escaping for VCF field values.
// VCF 3.0 requires escaping backslash (\), comma (,), semicolon (;), and newline (\n).
func escapeVCardValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, ",", "\\,")
	value = strings.ReplaceAll(value, ";", "\\;")
	// Newlines should be encoded as literal \n
	value = strings.ReplaceAll(value, "\n", "\\n")
	return value
}
