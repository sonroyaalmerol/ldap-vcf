package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
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

type OutputMode string

const (
	OutputModeSingle   OutputMode = "single"
	OutputModeMultiple OutputMode = "multiple"
)

type Config struct {
	LdapURL           string
	LdapBindDN        string
	LdapBindPassword  string
	LdapBaseDN        string
	LdapSearchFilter  string
	LdapUseTLS        bool
	LdapSkipTLSVerify bool
	GenerateDirs      string
	AttributeMapping  map[string]string
	VcfOutputFile     string
	VcfOutputMode     OutputMode
	VcfFileMode       string
	VcfFileOwner      string
	VcfFileGroup      string
	CronSchedule      string
}

type vCardField struct {
	Name       string
	Parameters map[string]string
}

type ldapAttributes struct {
	All       []string
	NameAttrs map[string]string
}

const (
	vCardNameField = "N"
	ldapEntryUUID  = "entryUUID" // Standard LDAP operational attribute for UUID
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	parsedMapping, ldapAttrsToFetch, err := parseMapping(cfg.AttributeMapping)
	if err != nil {
		log.Fatalf("Error parsing attribute mapping: %v", err)
	}

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

	if cfg.CronSchedule == "" {
		log.Println("No CRON_SCHEDULE defined. Running conversion once.")
		conversionFunc()
		log.Println("Exiting after single run.")
		return
	}

	log.Printf("CRON_SCHEDULE '%s' defined. Running in scheduled mode.", cfg.CronSchedule)
	c := cron.New(cron.WithChain(
		cron.SkipIfStillRunning(cron.DefaultLogger),
	))

	_, err = c.AddFunc(cfg.CronSchedule, conversionFunc)
	if err != nil {
		log.Fatalf("Error adding cron job (schedule '%s'): %v", cfg.CronSchedule, err)
	}

	c.Start()
	log.Println("Cron scheduler started. Waiting for jobs...")

	select {}
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		LdapURL:           getEnv("LDAP_URL", ""),
		LdapBindDN:        getEnv("LDAP_BIND_DN", ""),
		LdapBindPassword:  getEnv("LDAP_BIND_PASSWORD", ""),
		LdapBaseDN:        getEnv("LDAP_BASE_DN", ""),
		LdapSearchFilter:  getEnv("LDAP_SEARCH_FILTER", "(objectClass=*)"),
		VcfOutputFile:     getEnv("VCF_OUTPUT_FILE", "contacts.vcf"),
		CronSchedule:      getEnv("CRON_SCHEDULE", ""),
		AttributeMapping:  make(map[string]string),
		LdapUseTLS:        getEnvAsBool("LDAP_USE_TLS", false),
		LdapSkipTLSVerify: getEnvAsBool("LDAP_SKIP_TLS_VERIFY", false),
		VcfFileMode:       getEnv("VCF_FILE_MODE", ""),
		VcfFileOwner:      getEnv("VCF_FILE_OWNER", ""),
		VcfFileGroup:      getEnv("VCF_FILE_GROUP", ""),
		VcfOutputMode:     OutputMode(strings.ToLower(getEnv("VCF_OUTPUT_MODE", string(OutputModeSingle)))),
		GenerateDirs:      getEnv("GENERATE_DIRS", ""),
	}

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

	if cfg.VcfFileMode != "" {
		if _, err := parseFileMode(cfg.VcfFileMode); err != nil {
			return nil, fmt.Errorf("invalid VCF_FILE_MODE: %w", err)
		}
	}

	mappingStr := getEnv("LDAP_ATTRIBUTE_MAPPING", "")
	if mappingStr == "" {
		return nil, fmt.Errorf("LDAP_ATTRIBUTE_MAPPING environment variable is required")
	}
	cfg.AttributeMapping["_raw_"] = mappingStr

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	if fallback != "" {
		log.Printf("Environment variable %s not set, using default: %s", key, fallback)
	} else {
		log.Printf("Environment variable %s not set, using no default.", key)
	}
	return fallback
}

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

func parseMapping(rawMapping map[string]string) (map[string]string, *ldapAttributes, error) {
	mappingStr := rawMapping["_raw_"]
	if mappingStr == "" {
		return nil, nil, fmt.Errorf("attribute mapping string is empty")
	}

	parsed := make(map[string]string)
	ldapAttrSet := make(map[string]struct{})
	nameAttrMap := make(map[string]string)

	ldapAttrSet[ldapEntryUUID] = struct{}{}

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

		if strings.HasPrefix(strings.ToUpper(vCardKey), vCardNameField) {
			nameComponents := strings.Split(ldapVal, ";")
			if len(nameComponents) >= 1 && nameComponents[0] != "" {
				nameAttrMap["sn"] = nameComponents[0]
				ldapAttrSet[nameComponents[0]] = struct{}{}
			}
			if len(nameComponents) >= 2 && nameComponents[1] != "" {
				nameAttrMap["gn"] = nameComponents[1]
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

func runConversion(cfg *Config, mapping map[string]string, ldapAttrs *ldapAttributes) error {
	l, err := connectLDAP(cfg)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer l.Close()

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

	if cfg.VcfOutputMode == OutputModeSingle {
		return generateSingleVCF(cfg, sr.Entries, mapping, ldapAttrs)
	} else {
		return generateMultipleVCFs(cfg, sr.Entries, mapping, ldapAttrs)
	}
}

func generateSingleVCF(cfg *Config, entries []*ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) error {
	filePath := cfg.VcfOutputFile
	log.Printf("Generating single VCF file: %s", filePath)

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", filePath, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	entriesWritten := 0
	for _, entry := range entries {
		vcfEntry := generateVCardEntry(entry, mapping, ldapAttrs)
		if vcfEntry != "" {
			_, err = writer.WriteString(vcfEntry)
			if err != nil {
				log.Printf("Warning: Failed to write VCF entry for DN %s to %s: %v", entry.DN, filePath, err)
			} else {
				entriesWritten++
			}
		} else {
			log.Printf("Skipping VCF entry generation for DN %s (missing essential mapped fields)", entry.DN)
		}
	}

	if err := writer.Flush(); err != nil {
		log.Printf("Warning: Failed to flush writer for %s: %v", filePath, err)
	}
	file.Close()

	log.Printf("Wrote %d entries to %s", entriesWritten, filePath)

	if err := applyPermissions(filePath, cfg); err != nil {
		log.Printf("Warning: Failed to apply permissions to %s: %v", filePath, err)
	}

	return nil
}

func getCNFromDN(dnString string) (string, error) {
	dn, err := ldap.ParseDN(dnString)
	if err != nil {
		return "", fmt.Errorf("failed to parse DN '%s': %w", dnString, err)
	}

	for _, rdn := range dn.RDNs {
		for _, ava := range rdn.Attributes {
			if strings.EqualFold(ava.Type, "CN") {
				return ava.Value, nil
			}
		}
	}

	return "", fmt.Errorf("CN not found in DN: %s", dnString)
}

func generateMultipleVCFs(cfg *Config, entries []*ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) error {
	outputDir := cfg.VcfOutputFile
	log.Printf("Generating multiple VCF files in directory: %s", outputDir)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	filesWritten := 0
	for _, entry := range entries {
		vcfEntry := generateVCardEntry(entry, mapping, ldapAttrs)
		if vcfEntry != "" {
			var fileNameBase string
			if entry.DN != "" {
				fileNameBase = base64.URLEncoding.EncodeToString([]byte(entry.DN))
			} else {
				log.Printf("Warning: Entry found with empty DN. Using UUID for filename.")
				fileNameBase = uuid.New().String()
			}
			fileName := fileNameBase + ".vcf"
			filePath := filepath.Join(outputDir, fileName)

			err := os.WriteFile(filePath, []byte(vcfEntry), 0666)
			if err != nil {
				log.Printf("Warning: Failed to write VCF file %s for DN %s: %v", filePath, entry.DN, err)
				continue
			}

			if err := applyPermissions(filePath, cfg); err != nil {
				log.Printf("Warning: Failed to apply permissions to %s: %v", filePath, err)
			}

			if cfg.GenerateDirs != "" {
				if entryCN, err := getCNFromDN(entry.DN); err == nil {
					newDir := filepath.Join(cfg.GenerateDirs, entryCN)
					if err = os.MkdirAll(newDir, 0755); err == nil {
						if err := applyPermissions(newDir, cfg); err != nil {
							log.Printf("Warning: Failed to apply permissions to %s: %v", filePath, err)
						}
					}
				}
			}

			filesWritten++

		} else {
			log.Printf("Skipping VCF file generation for DN %s (missing essential mapped fields)", entry.DN)
		}
	}

	log.Printf("Wrote %d individual VCF files to %s", filesWritten, outputDir)
	return nil
}

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

func generateVCardEntry(entry *ldap.Entry, mapping map[string]string, ldapAttrs *ldapAttributes) string {
	var sb strings.Builder
	hasEssentialData := false

	sb.WriteString("BEGIN:VCARD\n")
	sb.WriteString("VERSION:3.0\n")

	uidValue := entry.GetAttributeValue(ldapEntryUUID)
	if uidValue == "" {
		uidValue = base64.URLEncoding.EncodeToString([]byte(entry.DN))
	}
	if uidValue != "" {
		sb.WriteString(fmt.Sprintf("UID:%s\n", uidValue))
	} else {
		log.Printf("Warning: Could not determine UID for entry (DN: %s). Skipping UID field.", entry.DN)
	}

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
		return ""
	}

	sb.WriteString(fmt.Sprintf("REV:%s\n", time.Now().UTC().Format("20060102T150405Z")))
	sb.WriteString("END:VCARD\n")

	return sb.String()
}

func escapeVCardValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, ",", "\\,")
	value = strings.ReplaceAll(value, ";", "\\;")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return value
}

func parseFileMode(modeStr string) (os.FileMode, error) {
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode string '%s': %w", modeStr, err)
	}
	return os.FileMode(mode), nil
}

func applyPermissions(path string, cfg *Config) error {
	var appliedMode bool
	var appliedOwner bool

	if cfg.VcfFileMode != "" {
		mode, err := parseFileMode(cfg.VcfFileMode)
		if err != nil {
			return fmt.Errorf("internal error parsing file mode: %w", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			log.Printf("Warning: Failed to chmod %s to %s: %v (Permissions issue?)", path, cfg.VcfFileMode, err)
		} else {
			log.Printf("Applied mode %s to %s", cfg.VcfFileMode, path)
			appliedMode = true
		}
	}

	if cfg.VcfFileOwner != "" || cfg.VcfFileGroup != "" {
		uid := -1
		gid := -1
		var err error

		if cfg.VcfFileOwner != "" {
			u, lookupErr := user.Lookup(cfg.VcfFileOwner)
			if lookupErr == nil {
				uid, err = strconv.Atoi(u.Uid)
				if err != nil {
					log.Printf("Warning: Could not convert looked up UID '%s' for user '%s' to int: %v", u.Uid, cfg.VcfFileOwner, err)
					uid = -1
				}
			} else {
				uid, err = strconv.Atoi(cfg.VcfFileOwner)
				if err != nil {
					log.Printf("Warning: Could not find user '%s' and it's not a numeric UID: %v", cfg.VcfFileOwner, lookupErr)
					uid = -1
				}
			}
		}

		if cfg.VcfFileGroup != "" {
			g, lookupErr := user.LookupGroup(cfg.VcfFileGroup)
			if lookupErr == nil {
				gid, err = strconv.Atoi(g.Gid)
				if err != nil {
					log.Printf("Warning: Could not convert looked up GID '%s' for group '%s' to int: %v", g.Gid, cfg.VcfFileGroup, err)
					gid = -1
				}
			} else {
				gid, err = strconv.Atoi(cfg.VcfFileGroup)
				if err != nil {
					log.Printf("Warning: Could not find group '%s' and it's not a numeric GID: %v", cfg.VcfFileGroup, lookupErr)
					gid = -1
				}
			}
		}

		if uid != -1 || gid != -1 {
			log.Printf("Attempting to chown %s to UID=%d, GID=%d", path, uid, gid)
			if err := os.Chown(path, uid, gid); err != nil {
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
		return nil
	}

	return nil
}
