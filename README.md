# Humanitec setup wizard

`humanitec-setup-wizard` is a CLI wizard designed to help users easily connect their existing cloud infrastructure to [Humanitec](https://humanitec.com/). Written in Go, this tool is lightweight and does not require any additional dependencies, making it quick and easy to set up and use.

## Prerequisites

- Go 1.22.5 or later (for building from source)
- Cloud account with appropriate permissions
- Humanitec account

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/humanitec-architecture/setup-wizard.git
    cd setup-wizard
    ```

2. Build the CLI tool:

    ```bash
    go build -o humanitec-setup-wizard
    ```

3. Install Humanitec’s CLI, `humctl`: https://developer.humanitec.com/platform-orchestrator/cli/

   If you prefer not to use `humctl`, the wizard will prompt you to provide your Humanitec API token directly during the setup process. See our [Authentication documentation](https://developer.humanitec.com/platform-orchestrator/reference/api-references/#authentication) for specifics.

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
                "sts:AssumeRole",
                "elasticloadbalancing:DescribeLoadBalancers"
            ],
            "Resource": "*"
        }
    ]
}
```

These permissions allow the wizard to perform necessary actions such as creating roles, managing policies, and interacting with EKS clusters.

## Contact

For questions about this wizard, please reach out to our support team or via [GitHub Issues](https://github.com/humanitec-architecture/setup-wizard/issues).

### Known Issues

Patches for issues listed here will be available soon. 🙂

* During initial configuration of your cloud account, you may receive an error about role assumption (e.g.: error code `CRED-005`). To work around the issue, wait ~10 seconds and restart the wizard using state from the previous session.

## License & Copyright

(c) 2024– Humanitec (PlatCo GmbH)

Source code for this project is released under the Microsoft Reference Source License (MS-RSL).
