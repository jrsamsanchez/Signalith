package agents

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The AWS CloudTrail option: an OpenTelemetry Collector that reads the
// files CloudTrail writes to an S3 bucket and sends their records to
// Signalith. S3 tells an SQS queue about each new file; the Collector's
// aws_s3 receiver reads the queue, fetches the file and decodes it with
// the aws_logs_encoding extension. The Collector runs anywhere it can
// reach AWS and Signalith, with AWS credentials from the usual places (an
// EC2 instance's role, or keys in its environment).

// Placeholders written into the config until the page has the bucket and
// queue.
const (
	cloudTrailBucketExample = "my-cloudtrail-bucket"
	cloudTrailQueueExample  = "https://sqs.us-east-1.amazonaws.com/123456789012/signalith-cloudtrail"
)

var (
	s3BucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	// An SQS queue's URL names its region, account and name.
	sqsQueueURL = regexp.MustCompile(`^https://sqs\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?/(\d{12})/([A-Za-z0-9_-]{1,80})$`)
)

// cloudTrailSource is the bucket and queue a CloudTrail Collector reads,
// with the queue's region, account and name.
type cloudTrailSource struct {
	bucket, queue           string
	region, account, name   string
	partition, placeholders string
}

// cloudTrailOptions checks the bucket and queue, or puts examples in
// their place when they are not given yet (placeholders names them).
func cloudTrailOptions(o Options) (cloudTrailSource, error) {
	s := cloudTrailSource{bucket: strings.TrimSpace(o.AWSBucket), queue: strings.TrimSpace(o.AWSQueueURL)}
	var missing []string
	if s.bucket == "" {
		s.bucket = cloudTrailBucketExample
		missing = append(missing, "bucket")
	} else if !s3BucketName.MatchString(s.bucket) || strings.Contains(s.bucket, "..") {
		return s, &FieldError{Field: "aws_bucket", Err: errors.New("that is not an S3 bucket name: 3 to 63 lower-case letters, digits, dots and hyphens, such as my-cloudtrail-logs")}
	}
	if s.queue == "" {
		s.queue = cloudTrailQueueExample
		missing = append(missing, "queue URL")
	}
	m := sqsQueueURL.FindStringSubmatch(s.queue)
	if m == nil {
		return s, &FieldError{Field: "aws_queue", Err: errors.New("that is not an SQS queue URL; copy it from the queue's page in the AWS console, such as " + cloudTrailQueueExample)}
	}
	s.region, s.account, s.name = m[1], m[3], m[4]
	s.partition = "aws"
	if m[2] != "" {
		s.partition = "aws-cn"
	}
	s.placeholders = strings.Join(missing, " and ")
	return s, nil
}

// receiver is the aws_s3 receiver of the Collector's config.
func (s cloudTrailSource) receiver() string {
	return "  aws_s3/cloudtrail:\n" +
		"    s3downloader:\n" +
		"      region: " + s.region + "\n" +
		"      s3_bucket: " + s.bucket + "\n" +
		"    sqs:\n" +
		"      queue_url: " + s.queue + "\n" +
		"      region: " + s.region + "\n" +
		"    encodings:\n" +
		"      - extension: aws_logs_encoding/cloudtrail\n" +
		"        suffix: .json\n"
}

// policy is the IAM policy the Collector's AWS identity needs: read the
// bucket's files and take the queue's messages.
func (s cloudTrailSource) policy() string {
	return fmt.Sprintf(`{"Version": "2012-10-17", "Statement": [`+
		`{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:%s:s3:::%s/*"}, `+
		`{"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": "arn:%s:sqs:%s:%s:%s"}]}`,
		s.partition, s.bucket, s.partition, s.region, s.account, s.name)
}

// queuePolicy is the SQS queue's access policy: the bucket may send it
// messages.
func (s cloudTrailSource) queuePolicy() string {
	return fmt.Sprintf(`{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, `+
		`"Action": "sqs:SendMessage", "Resource": "arn:%s:sqs:%s:%s:%s", "Condition": {"ArnLike": {"aws:SourceArn": "arn:%s:s3:::%s"}}}]}`,
		s.partition, s.region, s.account, s.name, s.partition, s.bucket)
}

// steps are the AWS side of the setup, before the Collector's own.
func (s cloudTrailSource) steps() []string {
	var out []string
	if s.placeholders != "" {
		out = append(out, "Enter your CloudTrail bucket and queue URL above. Until you do, the configuration below has examples in their place ("+s.placeholders+").")
	}
	return append(out,
		"In AWS, have a CloudTrail trail write to an S3 bucket (CloudTrail > Trails > Create trail, with management events). An organization trail works too, with one bucket for every account.",
		"Create a standard SQS queue named "+s.name+" in "+s.region+", the bucket's region, with this access policy, so the bucket can tell it about each new file: "+s.queuePolicy(),
		"In the bucket's Properties, add an event notification for all object create events, with the prefix AWSLogs/ and the queue as its destination.",
		"Give the Collector an AWS identity that may read the bucket's files and take the queue's messages. On an EC2 instance, attach this IAM policy to the instance's role; elsewhere, attach it to an IAM user, whose access key the Collector gets in a later step: "+s.policy())
}
