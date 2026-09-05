package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/andpalmier/tfox/api"
)

// repeatableFlag collects a flag that may be given more than once.
type repeatableFlag []string

func (r *repeatableFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatableFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*r = append(*r, v)
	return nil
}

// executeSubmit handles the 'submit' subcommand
func executeSubmit(args []string) error {
	submitCmd := flag.NewFlagSet("submit", flag.ExitOnError)
	threatType := submitCmd.String("threat_type", "", "Threat type, e.g. botnet_cc (see: tfox list -types)")
	iocType := submitCmd.String("ioc_type", "", "IOC type, e.g. domain (see: tfox list -types)")
	malware := submitCmd.String("malware", "", "Malpedia malware name, e.g. win.zloader (see: tfox list -malware)")
	confidence := submitCmd.Int("confidence", 0, "Confidence level 0-100 (the API defaults to 50)")
	reference := submitCmd.String("reference", "", "Reference URL for this submission")
	comment := submitCmd.String("comment", "", "Your comment on these IOCs")
	tags := submitCmd.String("tags", "", "Comma separated list of tags")
	compromised := submitCmd.Bool("compromised", false, "The asset is compromised rather than attacker owned")
	anonymous := submitCmd.Bool("anonymous", false, "Submit anonymously (no user association)")
	var iocs repeatableFlag
	submitCmd.Var(&iocs, "ioc", "An IOC to submit. Repeatable.")

	submitCmd.Usage = func() {
		printUsageHeader("submit", "Shares indicators of compromise with ThreatFox.")
		fmt.Println("\nFlags:")
		fmt.Println("  -threat_type <type>    Threat type (required)")
		fmt.Println("  -ioc_type <type>       IOC type (required)")
		fmt.Println("  -malware <name>        Malpedia malware name (required)")
		fmt.Println("  -ioc <value>           An IOC to submit (required, repeatable)")
		fmt.Println("  -confidence <0-100>    Confidence level (the API defaults to 50)")
		fmt.Println("  -reference <url>       Reference URL")
		fmt.Println("  -comment <text>        Your comment on these IOCs")
		fmt.Println("  -tags <tag1,tag2>      Comma separated tags")
		fmt.Println("  -compromised           The asset is compromised, not attacker owned")
		fmt.Println("  -anonymous             Submit without attribution")
		fmt.Println("\nExample:")
		fmt.Println("  tfox submit -threat_type botnet_cc -ioc_type domain \\")
		fmt.Println("    -malware win.zloader -ioc evil.example -confidence 75 \\")
		fmt.Println("    -reference https://example.org/report -tags TA505")
		fmt.Println("\nOnly submit confirmed, vetted IOCs. Repeated policy violations can")
		fmt.Println("get your account banned from contributing.")
	}

	if err := submitCmd.Parse(args); err != nil {
		return err
	}

	var tagList []string
	if *tags != "" {
		tagList = strings.Split(*tags, ",")
	}

	opts := api.SubmitOptions{
		ThreatType:      *threatType,
		IOCType:         *iocType,
		Malware:         *malware,
		IOCs:            iocs,
		ConfidenceLevel: *confidence,
		IsCompromised:   *compromised,
		Reference:       *reference,
		Tags:            tagList,
		Comment:         *comment,
		Anonymous:       *anonymous,
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	result, err := client.SubmitIOC(ctx, opts)
	if err != nil {
		printDetailedError(err, "Failed to submit IOCs")
		submitCmd.Usage()
		return err
	}

	fmt.Printf("Submitted %d IOC(s) - Status: %s\n", len(iocs), result.QueryStatus)
	if len(result.Data) > 0 {
		printJSON(result.Data)
	}
	return nil
}
