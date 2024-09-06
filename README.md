# Humanitec setup wizard

`humanitec-setup-wizard` is a CLI wizard designed to help users easily connect their existing cloud infrastructure to [Humanitec](https://humanitec.com/). Written in Go, this tool is lightweight and does not require any additional dependencies, making it quick and easy to set up and use.

## Prerequisites

- Go 1.22.5 or later (for building from source)
- Cloud account (AWS, Azure, Google Cloud) with appropriate permissions and the local cloud CLI (`aws`, `az`, or `gcloud`) authenticated
- Kubernetes cluster in your target cloud with API server endpoint accessible from your shell
- Humanitec account
- Humanitec’s CLI, `humctl`: https://developer.humanitec.com/platform-orchestrator/cli/

    If you prefer not to use `humctl`, the wizard will prompt you to provide your Humanitec API token directly during the setup process. See our [Authentication documentation](https://developer.humanitec.com/platform-orchestrator/reference/api-references/#authentication) for specifics.

## Installation

### Install from pre-built binaries

1. View the latest Github Releases: https://github.com/humanitec-architecture/setup-wizard/releases.
2. Download the binary appropriate for your platform from the latest release.

### Install from source

1. Clone the repository:

    ```bash
    git clone https://github.com/humanitec-architecture/setup-wizard.git
    cd setup-wizard
    ```

2. Build the CLI tool:

    ```bash
    go build -o humanitec-setup-wizard
    ```

## Usage

Log in to Humanitec using `humctl`:

```bash
humctl login
```

To start the wizard, simply run:

```bash
./humanitec-setup-wizard connect
```

The wizard will guide you through the process of connecting your cloud infrastructure to Humanitec.

## AWS Authentication

The wizard requires AWS credentials to connect your AWS cloud infrastructure.

### Using Default AWS CLI Profile

If you have already configured the AWS CLI with a default profile, the wizard will automatically detect and use it.

### Using a Specific AWS Profile

You can specify a different AWS profile by setting the `AWS_PROFILE` environment variable:

```bash
export AWS_PROFILE=your_profile_name
```

### Using Environment Variables

You can also provide AWS credentials directly through environment variables:

```bash
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export AWS_REGION=your_region
```

### Minimum Required AWS Permissions

The following AWS permissions are required for humanitec-setup-wizard to successfully connect and manage your AWS infrastructure:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListAttachedRolePolicies",
                "iam:GetRole",
                "iam:GetPolicy",
                "iam:CreateRole",
                "iam:CreatePolicy",
                "iam:AttachRolePolicy",
                "iam:PassRole",
                "eks:ListClusters",
                "eks:ListAssociatedAccessPolicies",
                "eks:ListAccessEntries",
                "eks:DescribeCluster",
                "eks:DescribeAccessEntry",
                "eks:CreateAccessEntry",
                "eks:CreatePodIdentityAssociation",
                "eks:AssociateAccessPolicy",
                "eks:DescribePodIdentityAssociation",
                "eks:DescribePodIdentityAssociation",
                "sts:AssumeRole",
                "elasticloadbalancing:DescribeLoadBalancers"
            ],
            "Resource": "*"
        }
    ]
}
```

These permissions allow the wizard to perform necessary actions such as creating roles, managing policies, and interacting with EKS clusters.

In addition, to install the Humanitec operator and/or agent, you will need deploy permissions access to the cluster you want to connect to Humanitec.

## GCP Provider Documentation

### Authentication

The CLI wizard requires that the [Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc) have been set up.

### Minimum Required GCP Permissions

The [Service Account impersonated by the Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc#sa-impersonation) or the User associated to them, should have the following roles:

- roles/serviceusage.serviceUsageViewer
- roles/iam.workloadIdentityPoolAdmin
- roles/iam.serviceAccountAdmin
- roles/container.admin
- roles/iam.roleAdmin
- roles/resourcemanager.projectIamAdmin

### Cluster and Project pre-requisites

The CLI wizard assumes that:

- In the target cluster an [Ingress Controller](https://developer.humanitec.com/integration-and-extensions/networking/ingress-controllers/) is available
- The [Secret Manager API](https://cloud.google.com/secret-manager/docs/configuring-secret-manager) is enabled in the selected GCP Project
- The target cluster has [Workload Identity Enabled](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)

### Resources Created

During the execution of the CLI wizard, the following GCP / Kubernetes resources will be created:

- To perform [GCP Service account impersonation](https://developer.humanitec.com/platform-orchestrator/security/cloud-accounts/gcp/#gcp-service-account-impersonation), the CLI wizard creates:
  - A Workload Identity Pool and a Workload Identity Provider
  - An IAM Service Account which will be impersonated by Humanitec
  - A Policy binding between the IAM Service Account and the Workload Identity Federation
- To [connect a GKE Cluster](https://developer.humanitec.com/integration-and-extensions/containerization/kubernetes/#gke) via Kubernetes Cluster role + IAM cluster access custom role, the CLI wizard creates:
  - An IAM Custom Role that is assigned to the IAM Service Account impersonated by Humanitec
  - A Kubernetes Cluster Role on the target cluster, which is bound to the IAM Service Account impersonated by Humanitec
  - A [GKE Cluster Humanitec Resource Definition](https://developer.humanitec.com/integration-and-extensions/containerization/kubernetes/#3-create-a-gke-resource-definition)

The CLI wizard outputs the name of every GCP resources generated and stores them in the state session.

## Contact

For questions about this wizard, please reach out to our support team or via [GitHub Issues](https://github.com/humanitec-architecture/setup-wizard/issues).

### Known Issues

Patches for issues listed here will be available soon. 🙂

* During initial configuration of your cloud account, you may receive an error about role assumption (e.g.: error code `CRED-005`). To work around the issue, wait ~10 seconds and restart the wizard using state from the previous session.

## License & Copyright

(c) 2024– Humanitec (PlatCo GmbH)

Source code for this project is released under the Microsoft Reference Source License (MS-RSL).
