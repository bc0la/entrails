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

// convert sts ARNs to iam ARNs and strips session suffixes
func normalizeArn(raw string) string {
	arn := strings.Replace(raw, "arn:aws:sts::", "arn:aws:iam::", 1)
	// handle assumed-role vs role
	arn = strings.Replace(arn, ":assumed-role/", ":role/", 1)
	// strip any session or path after first /
	if idx := strings.Index(arn, "/"); idx != -1 {
		arn = arn[:idx]
	}
	return arn
}

func main() {
	root := &cobra.Command{
		Use:   "cloudtrail2iam",
		Short: "Analyze CloudTrail logs for successful actions by identity",
		Run:   run,
	}

	root.Flags().StringVar(&bucket, "bucket", "", "S3 bucket name (e.g. AWSLogs/<acc-id>/CloudTrail/)")
	root.Flags().StringVar(&prefix, "prefix", "", "S3 prefix for CloudTrail logs")
	root.Flags().StringVar(&profile, "profile", "", "AWS CLI profile to use")
	root.Flags().IntVar(&threads, "threads", 10, "Number of workers for listing shards and processing logs")
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
		identity = normalizeArn(*res.Arn)
		fmt.Printf("Using identity: %s\n", identity)
	}

	// instantiate S3 client
	s3cli := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	})

	// discover shard prefixes
	fmt.Println("Discovering shard prefixes...")
	prefixes := getShardPrefixes(ctx, s3cli, bucket, prefix, 4)
	nShards := len(prefixes)
	if nShards > 1 {
		fmt.Printf("Found %d shard prefixes.\n", nShards)
	} else {
		fmt.Println("Single shard detected or no deeper prefixes.")
		prefixes = []string{prefix}
		nShards = 1
	}

	// parallel listing
	var shardCount int64
	var allKeys []types.Object
	var lm sync.Mutex
	var lwg sync.WaitGroup
	fmt.Printf("Listing shards: 0/%d completed...\n", nShards)
	for _, p := range prefixes {
		lwg.Add(1)
		go func(pref string) {
			defer lwg.Done()
			paginator := s3.NewListObjectsV2Paginator(s3cli, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(pref)})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					fmt.Fprintln(os.Stderr, "list error:", err)
					return
				}
				lm.Lock()
				allKeys = append(allKeys, page.Contents...)
				lm.Unlock()
			}
			cur := atomic.AddInt64(&shardCount, 1)
			fmt.Printf("\rListing shards: %d/%d completed", cur, nShards)
		}(p)
	}
	lwg.Wait()
	fmt.Println()

	total := int64(len(allKeys))
	fmt.Printf("Total log files: %d\n", total)

	// process logs
	var processed int64
	actions := make(map[string]string)
	var mu sync.Mutex
	secrets := make(map[string]struct{})

	fmt.Printf("Starting %d workers for log processing...\n", threads)
	jobs := make(chan types.Object, total)
	for _, obj := range allKeys {
		jobs <- obj
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range jobs {
				process(ctx, s3cli, bucket, *obj.Key, identity, actions, &mu, secrets)
				cur := atomic.AddInt64(&processed, 1)
				if cur%100 == 0 || cur == total {
					fmt.Printf("\rProcessed %d/%d logs", cur, total)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Println()

	// output
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

// getShardPrefixes lists common prefixes up to 'levels' deep
func getShardPrefixes(ctx context.Context, cli *s3.Client, bucket, base string, levels int) []string {
	prefixes := []string{base}
	for lvl := 0; lvl < levels; lvl++ {
		var next []string
		for _, p := range prefixes {
			resp, err := cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(p), Delimiter: aws.String("/")})
			if err != nil {
				fail(err)
			}
			for _, cp := range resp.CommonPrefixes {
				next = append(next, *cp.Prefix)
			}
		}
		if len(next) == 0 {
			break
		}
		prefixes = next
	}
	return prefixes
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func process(ctx context.Context, cli *s3.Client, bucket, key, identity string, actions map[string]string, mu *sync.Mutex, secrets map[string]struct{}) {
	r, err := cli.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return
	}
	defer r.Body.Close()

	gz, err := gzip.NewReader(r.Body)
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
		var ev struct {
			EventTime    string  `json:"eventTime"`
			EventSource  string  `json:"eventSource"`
			EventName    string  `json:"eventName"`
			ErrorCode    *string `json:"errorCode"`
			UserIdentity struct {
				Arn string `json:"arn"`
			} `json:"userIdentity"`
			RequestParameters map[string]interface{} `json:"requestParameters"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			continue
		}
		norm := normalizeArn(ev.UserIdentity.Arn)
		if norm != identity || ev.ErrorCode != nil {
			continue
		}
		action := strings.Split(ev.EventSource, ".")[0] + ":" + ev.EventName
		mu.Lock()
		if prev, ok := actions[action]; !ok || ev.EventTime > prev {
			actions[action] = ev.EventTime
		}
		mu.Unlock()

		if strings.Contains(ev.EventSource, "secretsmanager") && ev.EventName == "GetSecretValue" {
			if sid, ok := ev.RequestParameters["secretId"].(string); ok {
				mu.Lock()
				secrets[sid] = struct{}{}
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
