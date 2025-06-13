package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
)

var (
	bucket   string
	prefix   string
	profile  string
	threads  int
	identity string
	outfile  string
)

func main() {
	root := &cobra.Command{
		Use:   "cloudtrail2iam",
		Short: "Analyze CloudTrail logs for successful actions by identity",
		Run:   run,
	}

	root.Flags().StringVar(&bucket, "bucket", "", "S3 bucket name (e.g. AWSLogs/<acc-id>/CloudTrail/)")
	root.Flags().StringVar(&prefix, "prefix", "", "S3 prefix for CloudTrail logs")
	root.Flags().StringVar(&profile, "profile", "", "AWS CLI profile to use")
	root.Flags().IntVar(&threads, "threads", 10, "Number of workers for processing logs and listing shards")
	root.Flags().StringVar(&identity, "identity", "", "Filter by identity ARN (default: caller identity)")
	root.Flags().StringVar(&outfile, "output", "", "Write results to this file (optional)")
	root.MarkFlagRequired("bucket")
	root.MarkFlagRequired("prefix")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	// Banner
	fmt.Println(`▓█████  ███▄    █ ▄▄▄█████▓ ██▀███   ▄▄▄       ██▓ ██▓      ██████ 
▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▓██▒▓██▒    ▒██    ▒ 
▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒██▒▒██░    ░ ▓██▄   
▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ░██░▒██░      ▒   ██▒
░▒████▒▒██░   ▓██░  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒░██░░██████▒▒██████▒▒
░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░▓  ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
 ░ ░  ░░ ░░   ░ ▒░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░ ▒ ░░ ░ ▒  ░░ ░▒  ░ ░
   ░      ░   ░ ░   ░        ░░   ░   ░   ▒    ▒ ░  ░ ░   ░  ░  ░  
   ░  ░         ░             ░           ░  ░ ░      ░  ░      ░  
                                                                  `)
	ctx := context.Background()
	fmt.Println("Loading AWS config...")
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		fail(err)
	}

	if identity == "" {
		fmt.Println("Retrieving caller identity...")
		stscli := sts.NewFromConfig(cfg)
		res, err := stscli.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			fail(err)
		}
		identity = *res.Arn
		fmt.Printf("Using identity: %s\n", identity)
	}

	// instantiate S3 client
	s3cli := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	})

	// Parallel listing by shard prefixes
	fmt.Println("Discovering shards under prefix...")
	keys := listKeysParallel(ctx, s3cli, bucket, prefix, threads)
	total := int64(len(keys))
	fmt.Printf("Found %d log files across shards\n", total)

	// Process logs with worker pool
	var processed int64
	actions := make(map[string]string)
	var mu sync.Mutex
	secrets := make(map[string]struct{})

	fmt.Printf("Starting %d workers for log processing...\n", threads)
	jobs := make(chan types.Object, len(keys))
	for _, obj := range keys {
		jobs <- obj
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for obj := range jobs {
				process(ctx, s3cli, bucket, *obj.Key, identity, actions, &mu, secrets)
				cur := atomic.AddInt64(&processed, 1)
				if cur%100 == 0 || cur == total {
					fmt.Printf("\rProcessed %d/%d logs", cur, total)
				}
			}
		}(i)
	}
	wg.Wait()
	fmt.Println()

	// Output results
	keysAct := sortedKeys(actions)
	fmt.Printf("\nActions by %s:\n", identity)
	for _, a := range keysAct {
		fmt.Printf("- %s (%s)\n", a, actions[a])
	}
	if len(secrets) > 0 {
		fmt.Println("\nPotential Secrets Manager secrets:")
		for _, s := range secretsList(secrets) {
			fmt.Printf("- %s\n", s)
		}
	}

	if outfile != "" {
		writeOutput(outfile, identity, keysAct, actions, secrets)
	}
}

// listKeysParallel shards listing across common prefixes under prefix
func listKeysParallel(ctx context.Context, cli *s3.Client, bucket, prefix string, shards int) []types.Object {
	// first list common prefixes at one delimiter level
	input := &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix, Delimiter: aws.String("/")}
	resp, err := cli.ListObjectsV2(ctx, input)
	if err != nil {
		fail(err)
	}
	var prefixes []string
	for _, cp := range resp.CommonPrefixes {
		prefixes = append(prefixes, *cp.Prefix)
	}
	if len(prefixes) == 0 {
		// fallback to regular listing
		return listKeys(ctx, cli, bucket, prefix)
	}
	fmt.Printf("Found %d shard prefixes, listing in parallel...\n", len(prefixes))

	// worker pool for shards
	jobs := make(chan string, len(prefixes))
	for _, p := range prefixes {
		jobs <- p
	}
	close(jobs)

	var mu sync.Mutex
	var all []types.Object
	var wg sync.WaitGroup
	for i := 0; i < shards; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shard := range jobs {
				p := s3.NewListObjectsV2Paginator(cli, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &shard})
				for p.HasMorePages() {
					page, err := p.NextPage(ctx)
					if err != nil {
						fmt.Fprintln(os.Stderr, "shard list error:", err)
						return
					}
					mu.Lock()
					all = append(all, page.Contents...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return all
}

// sortedKeys returns sorted action names
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// listKeys is fallback single-threaded
func listKeys(ctx context.Context, cli *s3.Client, bucket, prefix string) []types.Object {
	var all []types.Object
	p := s3.NewListObjectsV2Paginator(cli, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			fail(err)
		}
		all = append(all, page.Contents...)
	}
	return all
}

func process(ctx context.Context, cli *s3.Client, bucket, key, identity string,
	actions map[string]string, mu *sync.Mutex, secrets map[string]struct{}) {
	resp, err := cli.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return
	}
	defer gz.Close()

	var wrapper struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.NewDecoder(gz).Decode(&wrapper); err != nil {
		return
	}

	for _, raw := range wrapper.Records {
		var r struct {
			EventTime    string  `json:"eventTime"`
			EventSource  string  `json:"eventSource"`
			EventName    string  `json:"eventName"`
			ErrorCode    *string `json:"errorCode"`
			UserIdentity struct {
				Arn string `json:"arn"`
			} `json:"userIdentity"`
			RequestParameters map[string]interface{} `json:"requestParameters"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		arn := strings.Replace(strings.Replace(r.UserIdentity.Arn, "arn:aws:sts::", "arn:aws:iam::", 1), "/assumed-role", "/role", 1)
		arn = strings.SplitN(arn, "/", 2)[0]
		if arn != identity || r.ErrorCode != nil {
			continue
		}
		action := strings.Split(r.EventSource, ".")[0] + ":" + r.EventName
		mu.Lock()
		if prev, ok := actions[action]; !ok || r.EventTime > prev {
			actions[action] = r.EventTime
		}
		mu.Unlock()

		if strings.Contains(r.EventSource, "secretsmanager") && r.EventName == "GetSecretValue" {
			if id, ok := r.RequestParameters["secretId"].(string); ok {
				mu.Lock()
				secrets[id] = struct{}{}
				mu.Unlock()
			}
		}
	}
}

func secretsList(m map[string]struct{}) []string {
	list := make([]string, 0, len(m))
	for s := range m {
		list = append(list, s)
	}
	sort.Strings(list)
	return list
}

func writeOutput(file, identity string, keys []string, actions map[string]string, secrets map[string]struct{}) {
	f, err := os.Create(file)
	if err != nil {
		fail(err)
	}
	defer f.Close()

	fmt.Fprintf(f, "Actions by %s:\n", identity)
	for _, a := range keys {
		fmt.Fprintf(f, "- %s (%s)\n", a, actions[a])
	}
	if len(secrets) > 0 {
		fmt.Fprintln(f, "\nPotential Secrets Manager secrets:")
		for _, s := range secretsList(secrets) {
			fmt.Fprintf(f, "- %s\n", s)
		}
	}
	fmt.Println("Finished writing output.")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
