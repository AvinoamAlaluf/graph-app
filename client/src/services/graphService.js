import axios from "axios";

const getVulnerabilities = () => {
  return axios
    .get("http://localhost:3000/api/vulnerabilities")
    .then(function (response) {
      // handle success
      console.log(response);
      return response;
    })
    .catch(function (error) {
      // handle error
      console.log(error);
    })
    .finally(function () {
      // always executed
    });
};

const mock = {
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-normalizer-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-normalizer-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-normalizer-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-normalizer-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-normalizer-queue-worker",
        ResourceTags: {
          Version: "3.8.591",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-normalizer-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-normalizer-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-normalizer-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-normalizer-queue-worker",
        ResourceTags: {
          Version: "3.8.591",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-deps-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-deps-vuln-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.590",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-deps-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-deps-vuln-enricher-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.590",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-governor-stats-aggregator":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-governor-stats-aggregator",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-governor-stats-aggregator is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-governor-stats-aggregator",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-governor-stats-aggregator",
        ResourceTags: {
          Version: "dev-3.7.798",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-session-term-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-session-term-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-session-term-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-session-term-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-session-term-queue-worker",
        ResourceTags: {
          Version: "2.12.625",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-vexes": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-sbom-vexes",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-sbom-vexes is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-sbom-vexes",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-vexes",
      ResourceTags: {
        Version: "dev-3.7.893",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-sbom-vexes",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-sbom-vexes variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-sbom-vexes",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-vexes",
      ResourceTags: {
        Version: "dev-3.7.893",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-android": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-os-android",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-os-android is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-os-android",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-android",
      ResourceTags: {
        Version: "2.9.61",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-resource-groups": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-resource-groups",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-resource-groups is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-resource-groups",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-resource-groups",
      ResourceTags: {
        Version: "3.7.1773",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-resource-groups",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-resource-groups variables -> Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-resource-groups",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-resource-groups",
      ResourceTags: {
        Version: "3.7.1773",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-ops-vendor": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-ops-vendor",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-sbom-ops-vendor is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-sbom-ops-vendor",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-ops-vendor",
      ResourceTags: {
        Version: "dev-3.7.37",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-global-data-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-global-data-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-global-data-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-global-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-global-data-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-global-data-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-global-data-enricher-queue-worker variables -> GitHub Token in variable GITHUB_ACCESS_TOKENS",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-global-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-global-data-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-cyclonedx-tools-wrapper":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-cyclonedx-tools-wrapper",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-cyclonedx-tools-wrapper is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-cyclonedx-tools-wrapper",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-cyclonedx-tools-wrapper",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-data-importer-github-advisory":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-data-importer-github-advisory",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-data-importer-github-advisory is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-data-importer-github-advisory",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-data-importer-github-advisory",
        ResourceTags: {
          Version: "3.8.54",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-cve":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-crowler-CVE",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-vulns-crowler-CVE is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-vulns-crowler-CVE",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-CVE",
        ResourceTags: {
          Version: "3.7.148",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-trigger-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-deps-vuln-trigger-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-deps-vuln-trigger-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-deps-vuln-trigger-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-trigger-sync",
        ResourceTags: {
          Version: "dev-3.7.768",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-windows": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-os-windows",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-os-windows is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-os-windows",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-windows",
      ResourceTags: {
        Version: "dev-2.9.9",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-custom-licenses":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-sbom-custom-licenses",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-admin-sbom-custom-licenses is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-admin-sbom-custom-licenses",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-custom-licenses",
        ResourceTags: {
          Version: "3.7.1773",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-sbom-custom-licenses",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-admin-sbom-custom-licenses variables -> Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-admin-sbom-custom-licenses",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-custom-licenses",
        ResourceTags: {
          Version: "3.7.1773",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-cre":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-crowler-CRE",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-vulns-crowler-CRE is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-vulns-crowler-CRE",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-CRE",
        ResourceTags: {
          Version: "3.7.148",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-lifecycle-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-lifecycle-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-lifecycle-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-lifecycle-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-lifecycle-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-lifecycle-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-lifecycle-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-lifecycle-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-lifecycle-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-status-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-customer-data-enrichment-status-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-customer-data-enrichment-status-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enrichment-status-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-status-sync",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-customer-data-enrichment-status-sync",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-customer-data-enrichment-status-sync variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enrichment-status-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-status-sync",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-global-data-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-global-data-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-global-data-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-global-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-global-data-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.810",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-global-data-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-global-data-enricher-queue-worker variables -> GitHub Token in variable GITHUB_ACCESS_TOKENS",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-global-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-global-data-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.810",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-integrations": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-integrations",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-integrations is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-integrations",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-integrations",
      ResourceTags: {
        Version: "3.7.1773",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-integrations",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-integrations variables -> Base64 High Entropy String in variable TI_PAN_CLIENT_SECRET, Secret Keyword in variable TI_PAN_CLIENT_SECRET, Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-integrations",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-integrations",
      ResourceTags: {
        Version: "3.7.1773",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-cisa": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-crowler-CISA",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-crowler-CISA is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-crowler-CISA",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-CISA",
      ResourceTags: {
        Version: "dev-3.7.15",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-spdx-tools-wrapper":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-spdx-tools-wrapper",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-spdx-tools-wrapper is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-spdx-tools-wrapper",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-spdx-tools-wrapper",
        ResourceTags: {
          Version: "dev-3.8.817",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-data-importer-spdx-licenses":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-data-importer-spdx-licenses",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-data-importer-spdx-licenses is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-data-importer-spdx-licenses",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-data-importer-spdx-licenses",
        ResourceTags: {
          Version: "dev-2.11.9",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-threat-intelligence-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-threat-intelligence-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-threat-intelligence-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-threat-intelligence-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-threat-intelligence-queue-worker",
        ResourceTags: {
          Version: "2.12.625",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-ops-vendor": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-ops-vendor",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-sbom-ops-vendor is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-sbom-ops-vendor",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-ops-vendor",
      ResourceTags: {
        Version: "3.7.50",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-normalizer-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-normalizer-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-normalizer-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-normalizer-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-normalizer-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.821",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-normalizer-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-normalizer-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-normalizer-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-normalizer-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.821",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-rtos": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-os-rtos",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-os-rtos is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-os-rtos",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-rtos",
      ResourceTags: {
        Version: "dev-2.9.9",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-slacknotifyservererror": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-slackNotifyServerError",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-slackNotifyServerError is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-slackNotifyServerError",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-slackNotifyServerError",
      ResourceTags: {},
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-epss": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-crowler-EPSS",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-crowler-EPSS is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-crowler-EPSS",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-EPSS",
      ResourceTags: {
        Version: "dev-3.7.15",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-threat-intelligence-gateway":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-threat-intelligence-gateway",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-threat-intelligence-gateway is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-threat-intelligence-gateway",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-threat-intelligence-gateway",
        ResourceTags: {
          Version: "2.10.103",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-threat-intelligence-gateway",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-threat-intelligence-gateway variables -> Base64 High Entropy String in variable PRIVATE_API_KEY, Secret Keyword in variable PRIVATE_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-threat-intelligence-gateway",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-threat-intelligence-gateway",
        ResourceTags: {
          Version: "2.10.103",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-users": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-users",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-users is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-users",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-users",
      ResourceTags: {
        Version: "dev-3.8.907",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-users",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-users variables -> Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-users",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-users",
      ResourceTags: {
        Version: "dev-3.8.907",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-session-term-sync": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-session-term-sync",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-session-term-sync is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-session-term-sync",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-session-term-sync",
      ResourceTags: {
        Version: "2.12.625",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-windows": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-os-windows",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-os-windows is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-os-windows",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-windows",
      ResourceTags: {
        Version: "2.9.61",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-processor": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-processor",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-vulns-processor is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-vulns-processor",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-processor",
      ResourceTags: {
        Version: "2.9.147",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-dispatcher":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-customer-data-enrichment-dispatcher",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-customer-data-enrichment-dispatcher is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-customer-data-enrichment-dispatcher",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-customer-data-enrichment-dispatcher variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-data-services-elastic-search":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-data-services-elastic-search",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-data-services-elastic-search is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-data-services-elastic-search",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-data-services-elastic-search",
        ResourceTags: {
          Version: "dev-3.8.68",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-data-services-elastic-search",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-data-services-elastic-search variables -> Base64 High Entropy String in variable API_KEY, Secret Keyword in variable API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-data-services-elastic-search",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-data-services-elastic-search",
        ResourceTags: {
          Version: "dev-3.8.68",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-dispatcher":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-customer-data-enrichment-dispatcher",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-customer-data-enrichment-dispatcher is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-customer-data-enrichment-dispatcher",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-customer-data-enrichment-dispatcher variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-dispatcher",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-cpe": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-crowler-CPE",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-crowler-CPE is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-crowler-CPE",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-CPE",
      ResourceTags: {
        Version: "dev-3.7.15",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-threat-intelligence-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-threat-intelligence-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-threat-intelligence-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-threat-intelligence-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-threat-intelligence-sync",
        ResourceTags: {
          Version: "2.12.625",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-threat-intelligence-sync",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-threat-intelligence-sync variables -> Base64 High Entropy String in variable TI_GATEWAY_PRIVATE_API_KEY, Secret Keyword in variable TI_GATEWAY_PRIVATE_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-threat-intelligence-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-threat-intelligence-sync",
        ResourceTags: {
          Version: "2.12.625",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-session-term-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-session-term-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-session-term-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-session-term-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-session-term-sync",
        ResourceTags: {
          Version: "2.12.625",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-trigger-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-deps-vuln-trigger-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-deps-vuln-trigger-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-deps-vuln-trigger-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-trigger-sync",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-trigger-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-deps-vuln-trigger-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-deps-vuln-trigger-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-deps-vuln-trigger-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-deps-vuln-trigger-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-customer-data-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-customer-data-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.812",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-customer-data-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-customer-data-enricher-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.812",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-data-importer-github-advisory":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-data-importer-github-advisory",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-data-importer-github-advisory is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-data-importer-github-advisory",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-data-importer-github-advisory",
        ResourceTags: {
          Version: "dev-3.8.37",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-users": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-users",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-users is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-users",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-users",
      ResourceTags: {
        Version: "3.8.1785",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-users",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-users variables -> Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-users",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-users",
      ResourceTags: {
        Version: "3.8.1785",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-rtos": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-os-rtos",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-os-rtos is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-os-rtos",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-rtos",
      ResourceTags: {
        Version: "2.9.61",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-downloader": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-downloader",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-downloader is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-downloader",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-downloader",
      ResourceTags: {
        Version: "dev-2.11.10",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-vuln-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-vuln-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-vuln-enricher-queue-worker variables -> GitHub Token in variable GITHUB_ACCESS_TOKENS",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-cre": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-crowler-CRE",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-crowler-CRE is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-crowler-CRE",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-CRE",
      ResourceTags: {
        Version: "dev-3.7.15",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-vexes": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-sbom-vexes",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-sbom-vexes is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-sbom-vexes",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-vexes",
      ResourceTags: {
        Version: "3.7.1779",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-sbom-vexes",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-sbom-vexes variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-sbom-vexes",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-vexes",
      ResourceTags: {
        Version: "3.7.1779",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-epss":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-crowler-EPSS",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-vulns-crowler-EPSS is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-vulns-crowler-EPSS",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-EPSS",
        ResourceTags: {
          Version: "3.7.148",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sboms": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-sboms",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-sboms is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-sboms",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sboms",
      ResourceTags: {
        Version: "3.8.1791",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-sboms",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-sboms variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-sboms",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sboms",
      ResourceTags: {
        Version: "3.8.1791",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-trigger-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-deps-vuln-trigger-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-deps-vuln-trigger-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-deps-vuln-trigger-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-trigger-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-threat-intelligence":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-threat-intelligence",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-admin-threat-intelligence is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-admin-threat-intelligence",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-threat-intelligence",
        ResourceTags: {
          Version: "dev-3.8.919",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-threat-intelligence",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-admin-threat-intelligence variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Secret Keyword in variable JWT_SECRET_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-admin-threat-intelligence",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-threat-intelligence",
        ResourceTags: {
          Version: "dev-3.8.919",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-data-importer-spdx-licenses":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-data-importer-spdx-licenses",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-data-importer-spdx-licenses is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-data-importer-spdx-licenses",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-data-importer-spdx-licenses",
        ResourceTags: {
          Version: "2.8.43",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-governors": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-governors",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-governors is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-governors",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-governors",
      ResourceTags: {
        Version: "3.8.1789",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-governors",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-governors variables -> Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-governors",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-governors",
      ResourceTags: {
        Version: "3.8.1789",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-cisa":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-crowler-CISA",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-vulns-crowler-CISA is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-vulns-crowler-CISA",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-CISA",
        ResourceTags: {
          Version: "3.7.148",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-spdx-tools-wrapper":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-spdx-tools-wrapper",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-spdx-tools-wrapper is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-spdx-tools-wrapper",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-spdx-tools-wrapper",
        ResourceTags: {
          Version: "3.8.590",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-import-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-import-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-import-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-import-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-import-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.772",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-integrations": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-integrations",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-integrations is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-integrations",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-integrations",
      ResourceTags: {
        Version: "dev-3.7.883",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-integrations",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-integrations variables -> Base64 High Entropy String in variable TI_PAN_CLIENT_SECRET, Secret Keyword in variable TI_PAN_CLIENT_SECRET, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-integrations",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-integrations",
      ResourceTags: {
        Version: "dev-3.7.883",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-policies": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-sbom-policies",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-sbom-policies is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-sbom-policies",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-policies",
      ResourceTags: {
        Version: "dev-3.8.921",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-sbom-policies",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-sbom-policies variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-sbom-policies",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-policies",
      ResourceTags: {
        Version: "dev-3.8.921",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-ops-data-lake": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-ops-data-lake",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-sbom-ops-data-lake is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-sbom-ops-data-lake",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-ops-data-lake",
      ResourceTags: {
        Version: "dev-3.8.41",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-android": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-os-android",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-os-android is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-os-android",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-android",
      ResourceTags: {
        Version: "dev-2.9.9",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-ops-data-lake":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-ops-data-lake",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-ops-data-lake is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-ops-data-lake",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-ops-data-lake",
        ResourceTags: {
          Version: "3.8.54",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-threat-intelligence-gateway":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-threat-intelligence-gateway",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-threat-intelligence-gateway is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-threat-intelligence-gateway",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-threat-intelligence-gateway",
        ResourceTags: {},
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-threat-intelligence-gateway",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-threat-intelligence-gateway variables -> Base64 High Entropy String in variable PRIVATE_API_KEY, Secret Keyword in variable PRIVATE_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-threat-intelligence-gateway",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-threat-intelligence-gateway",
        ResourceTags: {},
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-downloader": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-downloader",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-vulns-downloader is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-vulns-downloader",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-downloader",
      ResourceTags: {
        Version: "2.8.145",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-custom-licenses":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-sbom-custom-licenses",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-admin-sbom-custom-licenses is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-admin-sbom-custom-licenses",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-custom-licenses",
        ResourceTags: {
          Version: "dev-3.7.883",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-sbom-custom-licenses",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-admin-sbom-custom-licenses variables -> Secret Keyword in variable JWT_SECRET_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-admin-sbom-custom-licenses",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sbom-custom-licenses",
        ResourceTags: {
          Version: "dev-3.7.883",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-cve": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-crowler-CVE",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-crowler-CVE is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-crowler-CVE",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-crowler-CVE",
      ResourceTags: {
        Version: "dev-3.7.15",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-entity-deletion-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-entity-deletion-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-entity-deletion-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-entity-deletion-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-entity-deletion-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-processor": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-vulns-processor",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-vulns-processor is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-vulns-processor",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-vulns-processor",
      ResourceTags: {
        Version: "dev-2.11.10",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-governors": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-governors",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-governors is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-governors",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-governors",
      ResourceTags: {
        Version: "dev-3.8.917",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-governors",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-governors variables -> Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-governors",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-governors",
      ResourceTags: {
        Version: "dev-3.8.917",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-data-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-customer-data-enrichment-data-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-customer-data-enrichment-data-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enrichment-data-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-data-sync",
        ResourceTags: {
          Version: "dev-3.7.802",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-customer-data-enrichment-data-sync",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-customer-data-enrichment-data-sync variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enrichment-data-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-data-sync",
        ResourceTags: {
          Version: "dev-3.7.802",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-vuln-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-vuln-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-vuln-enricher-queue-worker variables -> GitHub Token in variable GITHUB_ACCESS_TOKENS",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-entity-deletion-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-entity-deletion-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-entity-deletion-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-entity-deletion-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-entity-deletion-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-governor-stats-aggregator":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-governor-stats-aggregator",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-governor-stats-aggregator is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-governor-stats-aggregator",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-governor-stats-aggregator",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-threat-intelligence":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-threat-intelligence",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-admin-threat-intelligence is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-admin-threat-intelligence",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-threat-intelligence",
        ResourceTags: {
          Version: "3.8.1788",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-threat-intelligence",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-admin-threat-intelligence variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-admin-threat-intelligence",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-threat-intelligence",
        ResourceTags: {
          Version: "3.8.1788",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-linux": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-os-linux",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-batch-os-linux is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-batch-os-linux",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-os-linux",
      ResourceTags: {
        Version: "2.9.61",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-import-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-import-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-import-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-import-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-import-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-linux": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-os-linux",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-batch-os-linux is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-batch-os-linux",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-os-linux",
      ResourceTags: {
        Version: "dev-2.9.9",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-lifecycle-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-lifecycle-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-lifecycle-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-lifecycle-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-lifecycle-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-lifecycle-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-lifecycle-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-lifecycle-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-lifecycle-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-data-services-elastic-search":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-data-services-elastic-search",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-data-services-elastic-search is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-data-services-elastic-search",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-data-services-elastic-search",
        ResourceTags: {
          Version: "3.8.36",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-data-services-elastic-search",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-data-services-elastic-search variables -> Base64 High Entropy String in variable API_KEY, Secret Keyword in variable API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-data-services-elastic-search",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-data-services-elastic-search",
        ResourceTags: {
          Version: "3.8.36",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sboms": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-sboms",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-sboms is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-sboms",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sboms",
      ResourceTags: {
        Version: "dev-3.8.935",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-sboms",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-sboms variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-sboms",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-sboms",
      ResourceTags: {
        Version: "dev-3.8.935",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-resource-groups": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-admin-resource-groups",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-admin-resource-groups is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-resource-groups",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-resource-groups",
      ResourceTags: {
        Version: "dev-3.7.883",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-admin-resource-groups",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-admin-resource-groups variables -> Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-admin-resource-groups",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-admin-resource-groups",
      ResourceTags: {
        Version: "dev-3.7.883",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-policies": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-admin-sbom-policies",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-admin-sbom-policies is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-sbom-policies",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-policies",
      ResourceTags: {
        Version: "3.8.1789",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-admin-sbom-policies",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function integ-admin-sbom-policies variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY, Base64 High Entropy String in variable JWT_SECRET_KEY, Secret Keyword in variable JWT_SECRET_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-admin-sbom-policies",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-admin-sbom-policies",
      ResourceTags: {
        Version: "3.8.1789",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-data-services-data-lake": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-data-services-data-lake",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function dev-data-services-data-lake is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-data-services-data-lake",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-data-services-data-lake",
      ResourceTags: {
        Version: "dev-3.8.68",
      },
    },
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-data-services-data-lake",
      Provider: "aws",
      CheckID: "awslambda_function_no_secrets_in_variables",
      CheckTitle: "Find secrets in Lambda functions variables.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Potential secret found in Lambda function dev-data-services-data-lake variables -> Base64 High Entropy String in variable API_KEY, Secret Keyword in variable API_KEY",
      Severity: "critical",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description: "Find secrets in Lambda functions variables.",
      Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
      RelatedUrl:
        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
      Remediation: {
        Code: {
          NativeIaC:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
          Terraform:
            "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
          CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
          Other: "",
        },
        Recommendation: {
          Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
          Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        },
      },
      Compliance: {
        "MITRE-ATTACK": ["T1552"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
      },
      Categories: ["secrets"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "dev-data-services-data-lake",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:dev-data-services-data-lake",
      ResourceTags: {
        Version: "dev-3.8.68",
      },
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-customer-data-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-customer-data-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-customer-data-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-customer-data-enricher-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enricher-queue-worker",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-status-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-customer-data-enrichment-status-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-customer-data-enrichment-status-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enrichment-status-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-status-sync",
        ResourceTags: {
          Version: "dev-3.8.808",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-customer-data-enrichment-status-sync",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-customer-data-enrichment-status-sync variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-customer-data-enrichment-status-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-customer-data-enrichment-status-sync",
        ResourceTags: {
          Version: "dev-3.8.808",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-threat-intelligence-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-threat-intelligence-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-threat-intelligence-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-threat-intelligence-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-threat-intelligence-queue-worker",
        ResourceTags: {
          Version: "dev-3.7.12",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-slacknotifyservererror": [
    {
      AssessmentStartTime: "2023-08-14T12:29:46.045664",
      FindingUniqueId:
        "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-slackNotifyServerError",
      Provider: "aws",
      CheckID:
        "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
      CheckTitle:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      CheckType: [],
      ServiceName: "lambda",
      SubServiceName: "",
      Status: "FAIL",
      StatusExtended:
        "Lambda function integ-slackNotifyServerError is not recorded by CloudTrail",
      Severity: "low",
      ResourceType: "AwsLambdaFunction",
      ResourceDetails: "",
      Description:
        "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
      RelatedUrl:
        "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
      Remediation: {
        Code: {
          NativeIaC: "",
          Terraform: "",
          CLI: "",
          Other: "",
        },
        Recommendation: {
          Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
          Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        },
      },
      Compliance: {
        "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
        "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
      },
      Categories: ["forensics-ready"],
      DependsOn: [],
      RelatedTo: [],
      Notes: "",
      Profile: "ENV",
      AccountId: "1234567890",
      OrganizationsInfo: null,
      Region: "us-east-1",
      ResourceId: "integ-slackNotifyServerError",
      ResourceArn:
        "arn:aws:lambda:us-east-1:1234567890:function:integ-slackNotifyServerError",
      ResourceTags: {},
    },
  ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-data-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-sbom-customer-data-enrichment-data-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-sbom-customer-data-enrichment-data-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enrichment-data-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-data-sync",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-batch-sbom-customer-data-enrichment-data-sync",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-batch-sbom-customer-data-enrichment-data-sync variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-sbom-customer-data-enrichment-data-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-sbom-customer-data-enrichment-data-sync",
        ResourceTags: {
          Version: "3.8.588",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-enricher-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-deps-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-deps-vuln-enricher-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.817",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-sbom-deps-vuln-enricher-queue-worker",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-sbom-deps-vuln-enricher-queue-worker variables -> Base64 High Entropy String in variable DS_API_KEY, Secret Keyword in variable DS_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-deps-vuln-enricher-queue-worker",
        ResourceTags: {
          Version: "dev-3.8.817",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-session-term-queue-worker":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-session-term-queue-worker",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-session-term-queue-worker is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-session-term-queue-worker",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-session-term-queue-worker",
        ResourceTags: {
          Version: "2.12.625",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-threat-intelligence-sync":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-threat-intelligence-sync",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-threat-intelligence-sync is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-threat-intelligence-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-threat-intelligence-sync",
        ResourceTags: {
          Version: "dev-3.7.12",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-dev-batch-threat-intelligence-sync",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function dev-batch-threat-intelligence-sync variables -> Base64 High Entropy String in variable TI_GATEWAY_PRIVATE_API_KEY, Secret Keyword in variable TI_GATEWAY_PRIVATE_API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-threat-intelligence-sync",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-threat-intelligence-sync",
        ResourceTags: {
          Version: "dev-3.7.12",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-cpe":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-batch-vulns-crowler-CPE",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-batch-vulns-crowler-CPE is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-batch-vulns-crowler-CPE",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-batch-vulns-crowler-CPE",
        ResourceTags: {
          Version: "3.7.148",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-cyclonedx-tools-wrapper":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-dev-batch-sbom-cyclonedx-tools-wrapper",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function dev-batch-sbom-cyclonedx-tools-wrapper is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "dev-batch-sbom-cyclonedx-tools-wrapper",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:dev-batch-sbom-cyclonedx-tools-wrapper",
        ResourceTags: {
          Version: "dev-3.7.762",
        },
      },
    ],
  "arn:aws:lambda:us-east-1:1234567890:function:integ-data-services-data-lake":
    [
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_invoke_api_operations_cloudtrail_logging_enabled-1234567890-us-east-1-integ-data-services-data-lake",
        Provider: "aws",
        CheckID:
          "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        CheckTitle:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Lambda function integ-data-services-data-lake is not recorded by CloudTrail",
        Severity: "low",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description:
          "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
        Risk: "If logs are not enabled; monitoring of service use and threat analysis is not possible.",
        RelatedUrl:
          "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        Remediation: {
          Code: {
            NativeIaC: "",
            Terraform: "",
            CLI: "",
            Other: "",
          },
          Recommendation: {
            Text: "Make sure you are logging information about Lambda operations. Create a lifecycle and use cases for each trail.",
            Url: "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
          },
        },
        Compliance: {
          "AWS-Well-Architected-Framework-Reliability-Pillar": ["REL06-BP01"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC04-BP01"],
        },
        Categories: ["forensics-ready"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-data-services-data-lake",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-data-services-data-lake",
        ResourceTags: {
          Version: "3.8.36",
        },
      },
      {
        AssessmentStartTime: "2023-08-14T12:29:46.045664",
        FindingUniqueId:
          "prowler-aws-awslambda_function_no_secrets_in_variables-1234567890-us-east-1-integ-data-services-data-lake",
        Provider: "aws",
        CheckID: "awslambda_function_no_secrets_in_variables",
        CheckTitle: "Find secrets in Lambda functions variables.",
        CheckType: [],
        ServiceName: "lambda",
        SubServiceName: "",
        Status: "FAIL",
        StatusExtended:
          "Potential secret found in Lambda function integ-data-services-data-lake variables -> Base64 High Entropy String in variable API_KEY, Secret Keyword in variable API_KEY",
        Severity: "critical",
        ResourceType: "AwsLambdaFunction",
        ResourceDetails: "",
        Description: "Find secrets in Lambda functions variables.",
        Risk: "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used; it is possible that malicious users gain access through the account in question.",
        RelatedUrl:
          "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
        Remediation: {
          Code: {
            NativeIaC:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cloudformation",
            Terraform:
              "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#terraform",
            CLI: "https://docs.bridgecrew.io/docs/bc_aws_secrets_3#cli-command",
            Other: "",
          },
          Recommendation: {
            Text: "Use Secrets Manager to securely provide database credentials to Lambda functions and secure the databases as well as use the credentials to connect and query them without hardcoding the secrets in code or passing them through environmental variables.",
            Url: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html",
          },
        },
        Compliance: {
          "MITRE-ATTACK": ["T1552"],
          "AWS-Well-Architected-Framework-Security-Pillar": ["SEC02-BP03"],
        },
        Categories: ["secrets"],
        DependsOn: [],
        RelatedTo: [],
        Notes: "",
        Profile: "ENV",
        AccountId: "1234567890",
        OrganizationsInfo: null,
        Region: "us-east-1",
        ResourceId: "integ-data-services-data-lake",
        ResourceArn:
          "arn:aws:lambda:us-east-1:1234567890:function:integ-data-services-data-lake",
        ResourceTags: {
          Version: "3.8.36",
        },
      },
    ],
};
const getMock = async () => {
  return await mock;
};

export default {
  getVulnerabilities,
  getMock,
};
