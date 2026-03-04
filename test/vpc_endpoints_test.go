package integration_tests

import (
	"fmt"
	"html/template"
	"net"
	"strings"
	"time"

	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/ministryofjustice/cloud-platform-integration-tests/test/helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GIVEN VPC endpoints are configured", func() {
	var (
		namespace string
		options   *k8s.KubectlOptions
		oldLogger *logger.Logger
	)

	awsServices := []struct {
		name     string
		endpoint string
	}{
		{"API Gateway", "apigateway.eu-west-2.amazonaws.com"},
		{"Athena", "athena.eu-west-2.amazonaws.com"},
		{"AWS Backup", "backup.eu-west-2.amazonaws.com"},
		{"CloudTrail", "cloudtrail.eu-west-2.amazonaws.com"},
		{"AWS Comprehend", "comprehend.eu-west-2.amazonaws.com"},
		{"AWS Config", "config.eu-west-2.amazonaws.com"},
		{"AWS Detective", "api.detective.eu-west-2.amazonaws.com"},
		{"DMS", "dms.eu-west-2.amazonaws.com"},
		{"EC2", "ec2.eu-west-2.amazonaws.com"},
		{"ECR API", "api.ecr.eu-west-2.amazonaws.com"},
		{"ECR Docker", "dkr.ecr.eu-west-2.amazonaws.com"},
		{"EKS", "eks.eu-west-2.amazonaws.com"},
		{"EKS Auth", "eks-auth.eu-west-2.api.aws"},
		{"ElastiCache", "elasticache.eu-west-2.amazonaws.com"},
		{"SES API", "email.eu-west-2.amazonaws.com"},
		// {"SES SMTP", "email-smtp.eu-west-2.amazonaws.com"},
		{"CloudWatch Events", "events.eu-west-2.amazonaws.com"},
		{"AWS Glue", "glue.eu-west-2.amazonaws.com"},
		{"GuardDuty", "guardduty-data.eu-west-2.amazonaws.com"},
		{"Inspector", "inspector2.eu-west-2.amazonaws.com"},
		{"Kinesis Firehose", "firehose.eu-west-2.amazonaws.com"},
		{"KMS", "kms.eu-west-2.amazonaws.com"},
		{"Lambda", "lambda.eu-west-2.amazonaws.com"},
		{"CloudWatch Logs", "logs.eu-west-2.amazonaws.com"},
		{"AWS Macie", "macie2.eu-west-2.amazonaws.com"},
		{"RDS", "rds.eu-west-2.amazonaws.com"},
		{"RDS Data", "rds-data.eu-west-2.amazonaws.com"},
		{"Secrets Manager", "secretsmanager.eu-west-2.amazonaws.com"},
		{"Security Hub", "securityhub.eu-west-2.amazonaws.com"},
		{"SNS", "sns.eu-west-2.amazonaws.com"},
		{"SQS", "sqs.eu-west-2.amazonaws.com"},
		{"Systems Manager", "ssm.eu-west-2.amazonaws.com"},
		{"STS", "sts.eu-west-2.amazonaws.com"},
		{"AWS Transcribe", "transcribe.eu-west-2.amazonaws.com"},
		{"AWS Translate", "translate.eu-west-2.amazonaws.com"},
		{"WAF", "wafv2.eu-west-2.amazonaws.com"},
	}

	BeforeEach(func() {
		namespace = fmt.Sprintf("%s-vpc-endpoint-test-%s", c.Prefix, strings.ToLower(random.UniqueId()))
		options = k8s.NewKubectlOptions("", "", namespace)
		oldLogger = options.Logger
		options.Logger = logger.Discard

		tpl, err := helpers.TemplateFile("./fixtures/namespace.yaml.tmpl", "namespace.yaml.tmpl", template.FuncMap{
			"namespace": namespace,
			"psaMode":   "enforce",
		})
		Expect(err).NotTo(HaveOccurred())

		err = k8s.KubectlApplyFromStringE(GinkgoT(), options, tpl)
		Expect(err).NotTo(HaveOccurred())

		podTpl, err := helpers.TemplateFile("./fixtures/vpc-endpoint-test-pod.yaml.tmpl", "vpc-endpoint-test-pod.yaml.tmpl", template.FuncMap{
			"namespace": namespace,
		})
		Expect(err).NotTo(HaveOccurred())

		err = k8s.KubectlApplyFromStringE(GinkgoT(), options, podTpl)
		Expect(err).NotTo(HaveOccurred())

		k8s.WaitUntilPodAvailable(GinkgoT(), options, "vpc-endpoint-test", 10, 10*time.Second)
	})

	AfterEach(func() {
		err := k8s.DeleteNamespaceE(GinkgoT(), options, namespace)
		Expect(err).NotTo(HaveOccurred())

		defer func() {
			options.Logger = oldLogger
		}()
	})

	It("THEN ALLOW connectivity to all AWS services via VPC endpoints", func() {
		for _, service := range awsServices {
			output, err := k8s.RunKubectlAndGetOutputE(
				GinkgoT(),
				options,
				"exec",
				"vpc-endpoint-test",
				"--",
				"nc",
				"-vz",
				"-w",
				"5",
				service.endpoint,
				"443",
			)

			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to connect to %s: %v\nOutput: %s", service.endpoint, err, output))
			Expect(strings.Contains(output, "succeeded") || strings.Contains(output, "open")).To(BeTrue(),
				fmt.Sprintf("Expected successful connection to %s, got: %s", service.endpoint, output))
		}
	})

	It("THEN all AWS services resolve to internal VPC addresses", func() {
		for _, service := range awsServices {
			output, err := k8s.RunKubectlAndGetOutputE(
				GinkgoT(),
				options,
				"exec",
				"vpc-endpoint-test",
				"--",
				"nslookup",
				service.endpoint,
			)

			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to resolve %s: %v", service.endpoint, err))

			lines := strings.Split(output, "\n")
			var resolvedIP string
			inNonAuthSection := false

			for _, line := range lines {
				if strings.Contains(line, "Non-authoritative answer:") {
					inNonAuthSection = true
					continue
				}

				if inNonAuthSection && strings.Contains(line, "Address:") && !strings.Contains(line, "#53") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						resolvedIP = parts[1]
						break
					}
				}
			}

			Expect(resolvedIP).NotTo(BeEmpty(), fmt.Sprintf("Could not extract IP address from nslookup output for %s: %s", service.name, output))

			ip := net.ParseIP(resolvedIP)
			Expect(ip).NotTo(BeNil(), fmt.Sprintf("Invalid IP address for %s: %s", service.name, resolvedIP))

			isPrivate := ip.IsPrivate()
			Expect(isPrivate).To(BeTrue(),
				fmt.Sprintf("%s resolved to public IP %s instead of private VPC endpoint IP", service.endpoint, resolvedIP))
		}
	})
})
