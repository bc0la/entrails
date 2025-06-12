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
	root.Flags().IntVar(&threads, "threads", 10, "Number of workers")
	root.Flags().StringVar(&identity, "identity", "", "Filter by identity ARN (default: caller identity)")
	root.MarkFlagRequired("bucket")
	root.MarkFlagRequired("prefix")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		fail(err)
	}

	if identity == "" {
		stscli := sts.NewFromConfig(cfg)
		res, err := stscli.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			fail(err)
		}
		identity = *res.Arn
	}

	s3cli := s3.NewFromConfig(cfg)

	// list objects
	keys := listKeys(ctx, s3cli, bucket, prefix)
	total := int64(len(keys))
	var processed int64

	// results
	actions := make(map[string]string)
	var mu sync.Mutex
	secrets := make(map[string]struct{})

	// worker pool
	jobs := make(chan types.Object, len(keys))
	for _, obj := range keys {
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
				fmt.Printf("\rProcessed %d/%d logs", cur, total)
			}
		}()
	}
	wg.Wait()
	fmt.Println()

	// print actions
	keysAct := make([]string, 0, len(actions))
	for a := range actions {
		keysAct = append(keysAct, a)
	}
	sort.Strings(keysAct)
	fmt.Printf("\nActions by %s:\n", identity)
	for _, a := range keysAct {
		fmt.Printf("- %s (%s)\n", a, actions[a])
	}

	// print potential secrets
	if len(secrets) > 0 {
		fmt.Println("\nPotential Secrets Manager secrets:")
		list := make([]string, 0, len(secrets))
		for s := range secrets {
			list = append(list, s)
		}
		sort.Strings(list)
		for _, s := range list {
			fmt.Printf("- %s\n", s)
		}
	}
}

func listKeys(ctx context.Context, cli *s3.Client, bucket, prefix string) []types.Object {
	var all []types.Object
	p := s3.NewListObjectsV2Paginator(cli, &s3.ListObjectsV2Input{
		Bucket: &bucket,
		Prefix: &prefix,
	})
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
		if arn != identity {
			continue
		}
		if r.ErrorCode != nil {
			continue
		}
		action := strings.Split(r.EventSource, ".")[0] + ":" + r.EventName
		mu.Lock()
		if prev, ok := actions[action]; !ok || r.EventTime > prev {
			actions[action] = r.EventTime
		}
		mu.Unlock()

		// detect secrets manager usage
		if strings.Contains(r.EventSource, "secretsmanager") && r.EventName == "GetSecretValue" {
			if id, ok := r.RequestParameters["secretId"].(string); ok {
				mu.Lock()
				secrets[id] = struct{}{}
				mu.Unlock()
			}
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
