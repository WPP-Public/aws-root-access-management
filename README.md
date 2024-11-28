
# AWS: Root Access Management rollout

This script will enable root access management in your management account and itterate over all accounts removing root credentials.
The following will be removed from the root user:
- Login Profile - Removes the aws created password and disables the ability to reset a password on the account.
- Access keys - Removes all access keys assigned to the account
- Signing certifications - All signing certificates will be removed
- MFA - This will remove both virtial and hardware keys

## Warning
This script assumes you have completed the necessary due-dilligence to ensure that essential workloads will continue. There may be
legacy use cases of using signing certificates that will be broken when running this script. Skip flags are available.

## Usage

The following skip flags are available:
- `--skip-login-profile`: Skips login profile deletion.
- `--skip-access-key`s: Skips access key deletion.
- `--skip-signing-certificates`: Skips signing certificate deletion.
- `--skip-mfa-devices`: Skips MFA device deletion.

Dry run mode is also available using the param `--dry-run`


### AWS cloudshell
```bash
git clone https://github.com/WPP-Public/aws-root-access-management.git root-account-management
cd root-account-management
python3 ./main.py
```

### Local - aws-vault
```bash
git clone https://github.com/WPP-Public/aws-root-access-management.git root-account-management
cd root-account-management
aws-vault exec <insert-management-profile> -- python3 ./main.py
```

### Local - aws cli
```bash
git clone https://github.com/WPP-Public/aws-root-access-management.git root-account-management
cd root-account-management
python3 ./main.py
```

###
