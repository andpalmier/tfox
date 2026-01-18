package api

import (
	"fmt"
	"regexp"
)

// sha256Regex matches valid SHA256 hashes (64 hexadecimal characters)
var sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// md5Regex matches valid MD5 hashes (32 hexadecimal characters)
var md5Regex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// tagRegex matches valid tags (alphanumeric, dots, dashes, underscores)
var tagRegex = regexp.MustCompile(`^[A-Za-z0-9.\-_ ]+$`)

// ValidateSHA256 checks if the input is a valid SHA256 hash
func ValidateSHA256(hash string) error {
	if !sha256Regex.MatchString(hash) {
		return fmt.Errorf("invalid SHA256 hash: must be 64 hexadecimal characters")
	}
	return nil
}

// ValidateMD5 checks if the input is a valid MD5 hash
func ValidateMD5(hash string) error {
	if !md5Regex.MatchString(hash) {
		return fmt.Errorf("invalid MD5 hash: must be 32 hexadecimal characters")
	}
	return nil
}

// ValidateHash checks if the input is either a valid SHA256 or MD5 hash
func ValidateHash(hash string) error {
	if sha256Regex.MatchString(hash) || md5Regex.MatchString(hash) {
		return nil
	}
	return fmt.Errorf("invalid hash: must be SHA256 (64 hex) or MD5 (32 hex)")
}

// ValidateTag checks if the input is a valid tag
func ValidateTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	if len(tag) > 100 {
		return fmt.Errorf("tag too long: maximum 100 characters")
	}
	if !tagRegex.MatchString(tag) {
		return fmt.Errorf("invalid tag: only alphanumeric characters, dots, dashes, underscores, and spaces allowed")
	}
	return nil
}

// ValidateMalware checks if the malware name is not empty
func ValidateMalware(malware string) error {
	if malware == "" {
		return fmt.Errorf("malware name cannot be empty")
	}
	if len(malware) > 100 {
		return fmt.Errorf("malware name too long: maximum 100 characters")
	}
	return nil
}

// ValidateIOCID checks if the IOC ID is valid
func ValidateIOCID(id int) error {
	if id <= 0 {
		return fmt.Errorf("IOC ID must be a positive integer")
	}
	return nil
}

// ValidateSearchTerm checks if the search term is not empty
func ValidateSearchTerm(term string) error {
	if term == "" {
		return fmt.Errorf("search term cannot be empty")
	}
	if len(term) > 500 {
		return fmt.Errorf("search term too long: maximum 500 characters")
	}
	return nil
}

// ValidateDays checks if days is within acceptable range (1-7)
func ValidateDays(days int) error {
	if days < 1 {
		return fmt.Errorf("days must be at least 1")
	}
	if days > 7 {
		return fmt.Errorf("days cannot exceed 7")
	}
	return nil
}

// ValidateLimit checks if the limit is within acceptable range
func ValidateLimit(limit int) error {
	if limit < 0 {
		return fmt.Errorf("limit cannot be negative")
	}
	if limit > 1000 {
		return fmt.Errorf("limit too large: maximum 1000")
	}
	return nil
}

// ValidateConfidenceLevel checks confidence level (0-100)
func ValidateConfidenceLevel(level int) error {
	if level < 0 || level > 100 {
		return fmt.Errorf("confidence level must be between 0 and 100")
	}
	return nil
}
