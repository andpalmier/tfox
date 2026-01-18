package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andpalmier/tfox/api"
)

// Global flags
var verbose bool

// printRootHelp displays the help message for the root command
func printRootHelp() {
	fmt.Println("tfox - ThreatFox CLI Client")
	fmt.Println("  A command-line tool for interacting with the ThreatFox API")
	fmt.Println("  Built by @andpalmier")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  tfox [command] [flags]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  recent             Query recent IOCs from ThreatFox")
	fmt.Println("  query              Query ThreatFox by IOC ID, tag, or malware family")
	fmt.Println("  search             Search for IOCs by term or file hash")
	fmt.Println("  list               List malware families, types, or tags")
	fmt.Println("  version            Show version information")
	fmt.Println()
	fmt.Println("Global Flags:")
	fmt.Println("  -v, --verbose      Enable verbose output")
	fmt.Println("  -V, --version      Show version information")
	fmt.Println("  -h, --help         Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Query recent IOCs (last 3 days)")
	fmt.Println("  tfox recent -days 3")
	fmt.Println()
	fmt.Println("  # Query by malware family")
	fmt.Println("  tfox query -malware \"Cobalt Strike\" -limit 10")
	fmt.Println()
	fmt.Println("  # Query by tag")
	fmt.Println("  tfox query -tag Emotet -limit 10")
	fmt.Println()
	fmt.Println("  # Search for an IOC")
	fmt.Println("  tfox search -ioc 94.103.84.81")
	fmt.Println()
	fmt.Println("  # Search by file hash")
	fmt.Println("  tfox search -hash 2151c4b970eff0071948dbbc19066aa4")
	fmt.Println()
	fmt.Println("  # List malware families")
	fmt.Println("  tfox list -malware")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  ABUSECH_API_KEY    Your abuse.ch API key (required)")
	fmt.Println("                     Get one at https://auth.abuse.ch/")
	fmt.Println()
	fmt.Println("For more information about a command:")
	fmt.Println("  tfox [command] --help")
}

// getAPIClient creates and returns an API client with the API key from environment
// Returns an error if the API key is not set
func getAPIClient() (*api.Client, error) {
	apiKey := os.Getenv("ABUSECH_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ABUSECH_API_KEY environment variable is required. Get one at https://auth.abuse.ch/")
	}

	if verbose {
		printVerbose("Creating API client")
	}

	return api.NewClient(apiKey), nil
}

// getContext returns a context with timeout and its cancel function
func getContext() (context.Context, context.CancelFunc) {
	timeout := 30 * time.Second

	if verbose {
		printVerbose(fmt.Sprintf("Setting request timeout to %v", timeout))
	}

	return context.WithTimeout(context.Background(), timeout)
}

// printUsageHeader prints a standard usage header for commands
func printUsageHeader(command, description string) {
	fmt.Printf("Usage:\n  tfox %s [flags]\n", command)
	fmt.Println(description)
}

// printError prints an error message
func printError(message string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", message)
}

// printDetailedError prints a detailed error message with context
func printDetailedError(err error, context string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	if context != "" {
		fmt.Fprintf(os.Stderr, "Context: %s\n", context)
	}

	errStr := err.Error()
	suggestions := map[string]string{
		"Unauthorized":       "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here",
		"API key":            "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here",
		"timeout":            "The request timed out. Try again or check your network connection",
		"deadline exceeded":  "The request timed out. Try again or check your network connection",
		"connection refused": "Cannot reach API. Check your internet connection",
	}

	for keyword, solution := range suggestions {
		if contains(errStr, keyword) {
			fmt.Fprintf(os.Stderr, "Solution: %s\n", solution)
			break
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Full error: %+v\n", err)
	}
}

// printVerbose prints a verbose message
func printVerbose(message string) {
	fmt.Printf("[VERBOSE] %s\n", message)
}

// printSuccess prints a success message
func printSuccess(message string) {
	fmt.Println(message)
}

// printJSON prints data as indented JSON
func printJSON(data interface{}) {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Printf("%+v\n", data)
		return
	}
	fmt.Println(string(b))
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// SetVerbose sets the verbose flag
func SetVerbose(v bool) {
	verbose = v
	InitLogger(v)
}

// IsVerbose returns the verbose flag value
func IsVerbose() bool {
	return verbose
}
