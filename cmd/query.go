package cmd

import (
	"flag"
	"fmt"
)

// executeRecent handles the 'recent' subcommand
func executeRecent(args []string) error {
	recentCmd := flag.NewFlagSet("recent", flag.ExitOnError)
	days := recentCmd.Int("days", 3, "Number of days to query (1-7)")

	recentCmd.Usage = func() {
		printUsageHeader("recent", "Query recent IOCs from ThreatFox.")
		fmt.Println("\nFlags:")
		fmt.Println("  -days <number>     Number of days to query (1-7, default: 3)")
		fmt.Println("\nExamples:")
		fmt.Println("  tfox recent -days 1")
		fmt.Println("  tfox recent -days 7")
	}

	if err := recentCmd.Parse(args); err != nil {
		return err
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	results, err := client.GetRecentIOCs(ctx, *days)
	if err != nil {
		printDetailedError(err, "Failed to query recent IOCs")
		return err
	}

	printJSON(results)
	return nil
}

// executeQuery handles the 'query' subcommand
func executeQuery(args []string) error {
	queryCmd := flag.NewFlagSet("query", flag.ExitOnError)
	id := queryCmd.Int("id", 0, "Query IOC by ThreatFox ID")
	tag := queryCmd.String("tag", "", "Query IOCs by tag")
	malware := queryCmd.String("malware", "", "Query IOCs by malware family")
	label := queryCmd.String("label", "", "Identify malware label/name")
	platform := queryCmd.String("platform", "", "Platform for label lookup (win, osx, apk, jar, elf)")
	limit := queryCmd.Int("limit", 100, "Limit the number of results (max 1000)")

	queryCmd.Usage = func() {
		printUsageHeader("query", "Query ThreatFox by IOC ID, tag, or malware family.")
		fmt.Println("\nFlags:")
		fmt.Println("  -id <number>       Query IOC by ThreatFox ID")
		fmt.Println("  -tag <tag>         Query IOCs associated with a tag")
		fmt.Println("  -malware <name>    Query IOCs associated with a malware family")
		fmt.Println("  -label <name>      Identify the correct malware label/name")
		fmt.Println("  -platform <name>   Platform for label lookup (win, osx, apk, jar, elf)")
		fmt.Println("  -limit <number>    Limit results (default: 100, max: 1000)")
		fmt.Println("\nExamples:")
		fmt.Println("  tfox query -id 41")
		fmt.Println("  tfox query -tag Emotet -limit 10")
		fmt.Println("  tfox query -malware \"Cobalt Strike\" -limit 10")
		fmt.Println("  tfox query -label warzone -platform win")
	}

	if len(args) < 1 {
		printError("expected query arguments")
		queryCmd.Usage()
		return fmt.Errorf("expected query arguments")
	}

	if err := queryCmd.Parse(args); err != nil {
		return err
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	// Determine which query to run
	if *id > 0 {
		result, err := client.GetIOCByID(ctx, *id)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query IOC ID %d", *id))
			return err
		}
		printJSON(result)
		return nil
	}

	if *tag != "" {
		results, err := client.QueryTag(ctx, *tag, *limit)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query tag: %s", *tag))
			return err
		}
		printJSON(results)
		return nil
	}

	if *malware != "" {
		results, err := client.QueryMalware(ctx, *malware, *limit)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query malware: %s", *malware))
			return err
		}
		printJSON(results)
		return nil
	}

	if *label != "" {
		results, err := client.GetLabel(ctx, *label, *platform)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to get label: %s", *label))
			return err
		}
		printJSON(results)
		return nil
	}

	printError("please provide a query parameter (e.g., -id, -tag, -malware)")
	queryCmd.Usage()
	fmt.Println()
	return fmt.Errorf("please provide a query parameter")
}

// executeSearch handles the 'search' subcommand
func executeSearch(args []string) error {
	searchCmd := flag.NewFlagSet("search", flag.ExitOnError)
	ioc := searchCmd.String("ioc", "", "Search for an IOC (IP, domain, URL)")
	hash := searchCmd.String("hash", "", "Search IOCs by file hash (MD5 or SHA256)")
	exactMatch := searchCmd.Bool("exact", false, "Use exact match for IOC search (default: wildcard)")

	searchCmd.Usage = func() {
		printUsageHeader("search", "Search for IOCs by term or file hash.")
		fmt.Println("\nFlags:")
		fmt.Println("  -ioc <term>        Search for an IOC (IP, domain, URL)")
		fmt.Println("  -hash <hash>       Search IOCs associated with a file hash (MD5/SHA256)")
		fmt.Println("  -exact             Use exact match instead of wildcard search")
		fmt.Println("\nExamples:")
		fmt.Println("  tfox search -ioc 94.103.84.81")
		fmt.Println("  tfox search -ioc evil.com -exact")
		fmt.Println("  tfox search -hash 2151c4b970eff0071948dbbc19066aa4")
	}

	if len(args) < 1 {
		printError("expected search arguments")
		searchCmd.Usage()
		return fmt.Errorf("expected search arguments")
	}

	if err := searchCmd.Parse(args); err != nil {
		return err
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	if *ioc != "" {
		results, err := client.SearchIOC(ctx, *ioc, *exactMatch)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to search IOC: %s", *ioc))
			return err
		}
		printJSON(results)
		return nil
	}

	if *hash != "" {
		results, err := client.SearchByHash(ctx, *hash)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to search hash: %s", *hash))
			return err
		}
		printJSON(results)
		return nil
	}

	printError("please provide -ioc or -hash parameter")
	searchCmd.Usage()
	fmt.Println()
	return fmt.Errorf("please provide -ioc or -hash parameter")
}

// executeList handles the 'list' subcommand
func executeList(args []string) error {
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	malwareList := listCmd.Bool("malware", false, "List supported malware families")
	typesList := listCmd.Bool("types", false, "List IOC/threat types")
	tagList := listCmd.Bool("tags", false, "List known tags")

	listCmd.Usage = func() {
		printUsageHeader("list", "List malware families, IOC types, or tags.")
		fmt.Println("\nFlags:")
		fmt.Println("  -malware           List supported malware families")
		fmt.Println("  -types             List IOC/threat types")
		fmt.Println("  -tags              List known tags")
		fmt.Println("\nExamples:")
		fmt.Println("  tfox list -malware")
		fmt.Println("  tfox list -types")
		fmt.Println("  tfox list -tags")
	}

	if len(args) < 1 {
		printError("expected list flag (-malware, -types, or -tags)")
		listCmd.Usage()
		return fmt.Errorf("expected list flag")
	}

	if err := listCmd.Parse(args); err != nil {
		return err
	}

	if !*malwareList && !*typesList && !*tagList {
		printError("please specify -malware, -types, or -tags")
		listCmd.Usage()
		fmt.Println()
		return fmt.Errorf("please specify a list type")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	if *malwareList {
		results, err := client.GetMalwareList(ctx)
		if err != nil {
			printDetailedError(err, "Failed to get malware list")
			return err
		}
		printJSON(results)
		return nil
	}

	if *typesList {
		results, err := client.GetTypes(ctx)
		if err != nil {
			printDetailedError(err, "Failed to get types")
			return err
		}
		printJSON(results)
		return nil
	}

	if *tagList {
		results, err := client.GetTagList(ctx)
		if err != nil {
			printDetailedError(err, "Failed to get tag list")
			return err
		}
		printJSON(results)
		return nil
	}

	return nil
}
