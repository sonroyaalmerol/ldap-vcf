package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// OutputMode defines how VCF files are generated
type OutputMode string

const (
	OutputModeSingle   OutputMode = "single"
	OutputModeMultiple OutputMode = "multiple"
)

// Config holds all configuration parameters loaded from environment variables.
type Config struct {
	LdapURL           string
	LdapBindDN        string
	LdapBindPassword  string
	LdapBaseDN        string
	LdapSearchFilter  string
	LdapUseTLS        bool
	LdapSkipTLSVerify bool
	AttributeMapping  map[string]string // vCard Field -> LDAP Attribute(s)
	VcfOutputFile     string            // File path for single mode, Dir path for multiple
	VcfOutputMode     OutputMode
	VcfFileMode       string // Octal string like "0644"
	VcfFileOwner      string // User name or UID string
	VcfFileGroup      string // Group name or GID string
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
			log.Printf("Conversion successful.")
			if cfg.VcfOutputMode == OutputModeSingle {
				log.Printf("VCF file written to %s", cfg.VcfOutputFile)
			} else {
				log.Printf("VCF files written to directory %s", cfg.VcfOutputFile)
			}
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

	c.Start()
	log.Println("Cron scheduler started. Waiting for jobs...")

	// Keep the application running
	select {} // Block forever
}

// loadConfig reads configuration from environment variables.
func loadConfig() (*Config, error) {
	cfg := &Config{
		LdapURL:           getEnv("LDAP_URL", ""),
		LdapBindDN:        getEnv("LDAP_BIND_DN", ""),
		LdapBindPassword:  getEnv("LDAP_BIND_PASSWORD", ""),
		LdapBaseDN:        getEnv("LDAP_BASE_DN", ""),
		LdapSearchFilter:  getEnv("LDAP_SEARCH_FILTER", "(objectClass=*)"),
		VcfOutputFile:     getEnv("VCF_OUTPUT_FILE", "contacts.vcf"), // Default name/dir
		CronSchedule:      getEnv("CRON_SCHEDULE", ""),
		AttributeMapping:  make(map[string]string),
		LdapUseTLS:        getEnvAsBool("LDAP_USE_TLS", false),
		LdapSkipTLSVerify: getEnvAsBool("LDAP_SKIP_TLS_VERIFY", false),
		VcfFileMode:       getEnv("VCF_FILE_MODE", ""),  // Default: OS default
		VcfFileOwner:      getEnv("VCF_FILE_OWNER", ""), // Default: current user
		VcfFileGroup:      getEnv("VCF_FILE_GROUP", ""), // Default: current group
		VcfOutputMode:     OutputMode(strings.ToLower(getEnv("VCF_OUTPUT_MODE", string(OutputModeSingle)))),
	}

	// Basic validation
	if cfg.LdapURL == "" {
		return nil, fmt.Errorf("LDAP_URL environment variable is required")
	}
	if cfg.LdapBaseDN == "" {
		return nil, fmt.Errorf("LDAP_BASE_DN environment variable is required")
	}
	if cfg.VcfOutputMode != OutputModeSingle && cfg.VcfOutputMode != OutputModeMultiple {
		return nil, fmt.Errorf("invalid VCF_OUTPUT_MODE: must be 'single' or 'multiple'")
	}
	if cfg.VcfOutputFile == "" {
		return nil, fmt.Errorf("VCF_OUTPUT_FILE environment variable cannot be empty")
	}

	// Validate file mode if set
	if cfg.VcfFileMode != "" {
		if _, err := parseFileMode(cfg.VcfFileMode); err != nil {
			return nil, fmt.Errorf("invalid VCF_FILE_MODE: %w", err)
		}
	}

	// Load the raw mapping string
	mappingStr := getEnv("LDAP_ATTRIBUTE_MAPPING", "")
	if mappingStr == "" {
		return nil, fmt.Errorf("LDAP_ATTRIBUTE_MAPPING environment variable is required")
	}
	cfg.AttributeMapping["_raw_"] = mappingStr

	return cfg, nil
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	// Only log fallback usage if fallback is not empty, to avoid noise for optional vars
	if fallback != "" {
		log.Printf("Environment variable %s not set, using default: %s", key, fallback)
	} else {
		log.Printf("Environment variable %s not set, using no default.", key)
	}
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

// parseMapping (same as before)
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
			nameComponents := strings.Split(ldapVal, ";")
			if len(nameComponents) >= 1 && nameComponents[0] != "" {
				nameAttrMap["sn"] = nameComponents[0] // Surname
				ldapAttrSet[nameComponents[0]] = struct{}{}
			}
			if len(nameComponents) >= 2 && nameComponents[1] != "" {
				nameAttrMap["gn"] = nameComponents[1] // Given Name
				ldapAttrSet[nameComponents[1]] = struct{}{}
			}
		} else {
			ldapAttrSet[ldapVal] = struct{}{}
		}
	}

	if len(parsed) == 0 {
		return nil, nil, fmt.Errorf("no valid mappings found in LDAP_ATTRIBUTE_MAPPING")
	}

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

// parseVCardFieldKey (same as before)
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
			field.Parameters[paramName] = paramValue
		} else {
			paramName := strings.ToUpper(strings.TrimSpace(paramParts[0]))
			field.Parameters[paramName] = ""
		}
	}
	return field
}

// runConversion connects to LDAP, searches, and generates VCF based on output mode.
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
			maskedErr := strings.Replace(err.Error(), cfg.LdapBindPassword, "[REDACTED]", -1)
			return fmt.Errorf("LDAP bind failed for DN %s: %s", cfg.LdapBindDN, maskedErr)
		}
		log.Printf("LDAP bind successful for DN: %s", cfg.LdapBindDN)
	} else {
		log.Println("Attempting anonymous LDAP bind.")
	}

	// Ensure all necessary attributes are requested
	attributesToFetch := ldapAttrs.All
	log.Printf("Requesting LDAP attributes: %v", attributesToFetch)
	if len(attributesToFetch) == 0 {
		log.Println("Warning: No LDAP attributes derived from mapping. Fetching all attributes (*).")
		attributesToFetch = []string{"*"}
	}

	searchRequest := ldap.NewSearchRequest(
		cfg.LdapBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		cfg.LdapSearchFilter,
		attributesToFetch,
		nil,
	)

	log.Printf("Performing LDAP search with BaseDN='%s', Filter='%s'", cfg.LdapBaseDN, cfg.LdapSearchFilter)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}

	log.Printf("LDAP search completed. Found %d entries.", len(sr.Entries))

	// --- VCF File Generation ---
	if cfg.VcfOutputMode == OutputModeSingle {
		return generateSingleVCF(cfg, sr.Entries, mapping, ldapAttrs)
	} else {
		return generateMultipleVCFs(cfg, sr.Entries, mapping, ldapAttrs)
	}
}

// generateSingleVCF creates one VCF file containing all entries.
func generateSingleVCF(cfg *Config, entries []*ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) error {
	filePath := cfg.VcfOutputFile
	log.Printf("Generating single VCF file: %s", filePath)

	// Ensure parent directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil { // Use a reasonable default mode for dir
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", filePath, err)
	}
	defer file.Close() // Close before applying permissions

	writer := bufio.NewWriter(file)
	entriesWritten := 0
	for _, entry := range entries {
		vcfEntry := generateVCardEntry(entry, mapping, ldapAttrs)
		if vcfEntry != "" {
			_, err = writer.WriteString(vcfEntry)
			if err != nil {
				log.Printf("Warning: Failed to write VCF entry for DN %s to %s: %v", entry.DN, filePath, err)
				// Continue writing other entries
			} else {
				entriesWritten++
			}
		} else {
			log.Printf("Skipping VCF entry generation for DN %s (missing essential mapped fields)", entry.DN)
		}
	}

	if err := writer.Flush(); err != nil {
		log.Printf("Warning: Failed to flush writer for %s: %v", filePath, err)
		// File might be incomplete, but proceed to permission setting
	}
	file.Close() // Explicit close before chmod/chown

	log.Printf("Wrote %d entries to %s", entriesWritten, filePath)

	// Apply permissions to the single file
	if err := applyPermissions(filePath, cfg); err != nil {
		// Log as warning, file is already created
		log.Printf("Warning: Failed to apply permissions to %s: %v", filePath, err)
	}

	return nil
}

// generateMultipleVCFs creates one VCF file per entry in a directory.
func generateMultipleVCFs(cfg *Config, entries []*ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) error {
	outputDir := cfg.VcfOutputFile
	log.Printf("Generating multiple VCF files in directory: %s", outputDir)

	// Ensure the output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil { // Use a reasonable default mode for dir
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}
	// Note: Permissions for the directory itself are not set by VCF_FILE_*,
	// manage directory permissions separately if needed.

	filesWritten := 0
	for _, entry := range entries {
		vcfEntry := generateVCardEntry(entry, mapping, ldapAttrs)
		if vcfEntry != "" {
			// Generate unique filename
			fileName := uuid.New().String() + ".vcf"
			filePath := filepath.Join(outputDir, fileName)

			// Write file content (using WriteFile for simplicity)
			// Default permissions are used initially, then adjusted by applyPermissions
			err := os.WriteFile(filePath, []byte(vcfEntry), 0666) // Temporary permissive mode
			if err != nil {
				log.Printf("Warning: Failed to write VCF file %s for DN %s: %v", filePath, entry.DN, err)
				continue // Skip this entry, try the next one
			}

			// Apply permissions to the individual file
			if err := applyPermissions(filePath, cfg); err != nil {
				// Log as warning, file is already created
				log.Printf("Warning: Failed to apply permissions to %s: %v", filePath, err)
			}
			filesWritten++

		} else {
			log.Printf("Skipping VCF file generation for DN %s (missing essential mapped fields)", entry.DN)
		}
	}

	log.Printf("Wrote %d individual VCF files to %s", filesWritten, outputDir)
	return nil
}

// connectLDAP (same as before)
func connectLDAP(cfg *Config) (*ldap.Conn, error) {
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

	if !isTLS && cfg.LdapUseTLS {
		log.Println("Attempting StartTLS...")
		err = l.StartTLS(tlsConfig)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("StartTLS failed: %w", err)
		}
		log.Println("StartTLS successful.")
	}

	return l, nil
}

// generateVCardEntry (same as before)
func generateVCardEntry(entry *ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) string {
	var sb strings.Builder
	hasEssentialData := false

	sb.WriteString("BEGIN:VCARD\n")
	sb.WriteString("VERSION:3.0\n")
	// Consider adding UID based on a stable LDAP attribute if available
	// uidAttr := entry.GetAttributeValue("entryUUID") // Example
	// if uidAttr != "" {
	// 	sb.WriteString(fmt.Sprintf("UID:%s\n", uidAttr))
	// }

	// Process mapped fields
	for vCardKey, ldapAttr := range mapping {
		field := parseVCardFieldKey(vCardKey)

		if field.Name == vCardNameField {
			sn := entry.GetAttributeValue(ldapAttrs.NameAttrs["sn"])
			gn := entry.GetAttributeValue(ldapAttrs.NameAttrs["gn"])
			if sn != "" || gn != "" {
				sb.WriteString(fmt.Sprintf("%s:%s;%s;;;\n", field.Name, escapeVCardValue(sn), escapeVCardValue(gn)))
				hasEssentialData = true
			}
			continue
		}

		values := entry.GetAttributeValues(ldapAttr)
		if len(values) > 0 {
			hasEssentialData = true
			for _, value := range values {
				if value != "" {
					sb.WriteString(field.Name)
					for paramName, paramValue := range field.Parameters {
						sb.WriteString(";")
						sb.WriteString(paramName)
						if paramValue != "" {
							sb.WriteString("=")
							sb.WriteString(paramValue) // Basic param value handling
						}
					}
					sb.WriteString(":")
					sb.WriteString(escapeVCardValue(value))
					sb.WriteString("\n")
				}
			}
		}
	}

	// Add FN (Formatted Name)
	fn := entry.GetAttributeValue("cn")
	if fn == "" {
		gn := entry.GetAttributeValue(ldapAttrs.NameAttrs["gn"])
		sn := entry.GetAttributeValue(ldapAttrs.NameAttrs["sn"])
		fn = strings.TrimSpace(gn + " " + sn)
	}

	if fn != "" {
		sb.WriteString(fmt.Sprintf("FN:%s\n", escapeVCardValue(fn)))
		hasEssentialData = true
	} else if !hasEssentialData {
		return "" // Skip entry if no FN and no other mapped data found
	}

	// Add REV (Revision timestamp) - useful for tracking changes
	sb.WriteString(fmt.Sprintf("REV:%s\n", time.Now().UTC().Format("20060102T150405Z")))

	sb.WriteString("END:VCARD\n")

	return sb.String()
}

// escapeVCardValue (same as before)
func escapeVCardValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, ",", "\\,")
	value = strings.ReplaceAll(value, ";", "\\;")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return value
}

// parseFileMode converts an octal string like "0644" to os.FileMode.
func parseFileMode(modeStr string) (os.FileMode, error) {
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode string '%s': %w", modeStr, err)
	}
	return os.FileMode(mode), nil
}

// applyPermissions sets the mode and ownership of the specified file/directory.
func applyPermissions(path string, cfg *Config) error {
	var appliedMode bool
	var appliedOwner bool

	// 1. Set File Mode (chmod)
	if cfg.VcfFileMode != "" {
		mode, err := parseFileMode(cfg.VcfFileMode)
		if err != nil {
			// Should have been caught during config load, but double-check
			return fmt.Errorf("internal error parsing file mode: %w", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			// Log error but continue to chown if possible
			log.Printf("Warning: Failed to chmod %s to %s: %v (Permissions issue?)", path, cfg.VcfFileMode, err)
		} else {
			log.Printf("Applied mode %s to %s", cfg.VcfFileMode, path)
			appliedMode = true
		}
	}

	// 2. Set File Ownership (chown)
	if cfg.VcfFileOwner != "" || cfg.VcfFileGroup != "" {
		uid := -1 // -1 means don't change UID
		gid := -1 // -1 means don't change GID
		var err error

		// Lookup UID
		if cfg.VcfFileOwner != "" {
			u, lookupErr := user.Lookup(cfg.VcfFileOwner)
			if lookupErr == nil {
				uid, err = strconv.Atoi(u.Uid)
				if err != nil {
					log.Printf("Warning: Could not convert looked up UID '%s' for user '%s' to int: %v", u.Uid, cfg.VcfFileOwner, err)
					uid = -1 // Reset on error
				}
			} else {
				// Try parsing as numeric UID directly
				uid, err = strconv.Atoi(cfg.VcfFileOwner)
				if err != nil {
					log.Printf("Warning: Could not find user '%s' and it's not a numeric UID: %v", cfg.VcfFileOwner, lookupErr)
					uid = -1 // Reset on error
				}
			}
		}

		// Lookup GID
		if cfg.VcfFileGroup != "" {
			g, lookupErr := user.LookupGroup(cfg.VcfFileGroup)
			if lookupErr == nil {
				gid, err = strconv.Atoi(g.Gid)
				if err != nil {
					log.Printf("Warning: Could not convert looked up GID '%s' for group '%s' to int: %v", g.Gid, cfg.VcfFileGroup, err)
					gid = -1 // Reset on error
				}
			} else {
				// Try parsing as numeric GID directly
				gid, err = strconv.Atoi(cfg.VcfFileGroup)
				if err != nil {
					log.Printf("Warning: Could not find group '%s' and it's not a numeric GID: %v", cfg.VcfFileGroup, lookupErr)
					gid = -1 // Reset on error
				}
			}
		}

		// Apply Chown if UID or GID was successfully determined
		if uid != -1 || gid != -1 {
			log.Printf("Attempting to chown %s to UID=%d, GID=%d", path, uid, gid)
			if err := os.Chown(path, uid, gid); err != nil {
				// Check for specific permission error (EPERM)
				if perr, ok := err.(*os.PathError); ok && perr.Err == syscall.EPERM {
					log.Printf("Warning: Permission denied to chown %s. Ensure the process runs with sufficient privileges (e.g., as root or with capabilities).", path)
				} else {
					log.Printf("Warning: Failed to chown %s: %v", path, err)
				}
			} else {
				log.Printf("Applied ownership UID=%d, GID=%d to %s", uid, gid, path)
				appliedOwner = true
			}
		}
	}

	if !appliedMode && !appliedOwner {
		// No permissions were configured or applied
		return nil
	}

	return nil // Return nil even if warnings occurred, as file ops succeeded
}
