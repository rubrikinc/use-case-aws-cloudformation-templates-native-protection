package servers_and_apps

import (
	iamdefinitions "rubrik/aws/iam/definitions"
)

func getPolicy1000(
	ec2RecoveryPassRolePath string,
) *iamdefinitions.PolicyDocument {
	return iamdefinitions.NewPolicyDocument(
		[]*iamdefinitions.Statement{
			iamdefinitions.NewStatement(
				"", // sid
				iamdefinitions.EffectAllow,
				nil, // principal,
				[]iamdefinitions.ActionWithUseCase{
					{
						Permission: "ec2:ModifyInstanceAttribute",
						UseCase: []string{
							"Changing security groups of an EC2 instance from the no connectivity security group to a user-specified security group for export EC2 instance in a powered off state.", // nolint: lll
						},
					},
					{
						Permission: "ec2:TerminateInstances",
						UseCase: []string{
							"Terminating EC2 instances created during failed exports.",
						},
					},
				},
				[]string{
					"arn:*:ec2:*:*:instance/*",
				},
				map[string]map[string]interface{}{
					"StringEquals": {
						"ec2:ResourceTag/rk_component": "Cloud Cluster",
					},
				},
			),
			iamdefinitions.NewStatement(
				"", // sid
				iamdefinitions.EffectAllow,
				nil, // principal
				[]iamdefinitions.ActionWithUseCase{
					{
						Permission: "ec2:DeleteSnapshot",
						// nolint: lll
						UseCase: []string{
							"Deleting EBS volume snapshots associated with expired backups.",
							"Deleting associated snapshots when deleting an Amazon Machine Image (AMI) while reverting the Create EC2 instance snapshot task or exporting the EC2 instance snapshot to a different region.",
							"Deleting snapshots when reverting the Create EBS volume snapshot task.",
							"Deleting snapshots when exporting the EBS volume snapshot to a different region.",
							"Deleting crash-consistent snapshots of excluded EBS volumes.",
							"Deleting snapshot when deleting an AWS account.",
							"Deleting snapshots after expiry.",
							"Deleting temporary snapshots created during replication and export.",
						},
					},
					{
						Permission: "ec2:DeleteVolume",
						UseCase: []string{
							"Deleting the EBS volumes launched from the backup if a restore or export EC2 instance task fails in the middle.", // nolint: lll
							"Deleting temporary EBS volume launched for file indexing and storage tiering.",                                   // nolint: lll
						},
					},
					{
						Permission: "ec2:TerminateInstances",
						UseCase: []string{
							"Terminating EC2 instances created during failed exports.",
						},
					},
					// Needed to remove default outbound rule from security
					// groups for exporting AWS VMs in powered off state.
					{
						Permission: "ec2:RevokeSecurityGroupEgress",
						UseCase: []string{
							"Removing the default egress rule from no connectivity security group for export EC2 instance in a powered off state.", // nolint: lll
						},
					},
				},
				[]string{"*"},
				map[string]map[string]interface{}{
					"StringEquals": {
						"ec2:ResourceTag/rk_component": "Cloud Native Protection",
					},
				},
			),
			iamdefinitions.NewStatement(
				"", // sid
				iamdefinitions.EffectAllow,
				nil, // principal
				[]iamdefinitions.ActionWithUseCase{
					{
						Permission: "ebs:ListSnapshotBlocks",
						UseCase: []string{
							"Getting the indices of blocks with data or the changed block indices that are used for optimal archival.", // nolint: lll
						},
					},
					{
						Permission: "ebs:ListChangedBlocks",
						UseCase: []string{
							"Getting the indices of blocks with data or the changed block indices that are used for optimal archival.", // nolint: lll
						},
					},
					// This allows us to fetch the data in block of a snapshot. Used
					// for direct read based archival and indexing.
					{
						Permission: "ebs:GetSnapshotBlock",
						UseCase:    []string{},
					},
					// Allows to create & write to an AWS EBS snapshot.
					{
						Permission: "ebs:StartSnapshot",
						UseCase:    []string{},
					},
					{
						Permission: "ebs:PutSnapshotBlock",
						UseCase:    []string{},
					},
					{
						Permission: "ebs:CompleteSnapshot",
						UseCase:    []string{},
					},
				},
				[]string{
					"arn:*:ec2:*::snapshot/*",
				},
				map[string]map[string]interface{}{
					"StringEquals": {
						"aws:ResourceTag/rk_component": "Cloud Native Protection",
					},
				},
			),
			iamdefinitions.NewStatement(
				"", // sid
				iamdefinitions.EffectAllow,
				nil, // principal
				[]iamdefinitions.ActionWithUseCase{
					{
						// Needed to modify security groups back to the user
						// specified security groups for exporting AWS VMs in
						// powered off state. The tag requirement is only for the
						// instance.
						Permission: "ec2:ModifyInstanceAttribute",
						UseCase: []string{
							"Changing security groups of an EC2 instance from the no connectivity security group to a user-specified security group for export EC2 instance in a powered off state.", // nolint: lll
						},
					},
				},
				[]string{
					"arn:*:ec2:*:*:instance/*",
				},
				map[string]map[string]interface{}{
					"StringEquals": {
						"ec2:ResourceTag/rk_component": "Cloud Native Protection",
					},
				},
			),
			iamdefinitions.NewStatement(
				"",
				iamdefinitions.EffectAllow,
				nil,
				[]iamdefinitions.ActionWithUseCase{
					{
						// Needed to modify security groups back to the user
						// specified security groups for exporting AWS VMs in
						// powered off state. There is no tag requirement on the
						// customer's security groups which are being attached.
						Permission: "ec2:ModifyInstanceAttribute",
						UseCase: []string{
							"Changing security groups of an EC2 instance from the no connectivity security group to a user-specified security group for export EC2 instance in a powered off state.", // nolint: lll
						},
					},
				},
				[]string{
					"arn:*:ec2:*:*:security-group/*",
				},
				nil,
			),
			iamdefinitions.NewStatement(
				"",
				iamdefinitions.EffectAllow,
				nil,
				[]iamdefinitions.ActionWithUseCase{
					{
						Permission: "kms:CreateGrant",
						// nolint: lll
						UseCase: []string{
							"Enabling EC2 service to use the Customer Managed Key (CMK) on the behalf of the user.",
							"Example: If an EBS volume snapshot is copied from key K1 to key K2, the EC2 service decrypts the K1 encrypted snapshot so that it can be encrypted to K2. To enable this, the EC2 service must be allowed to create grants for K1 and K2.",
						},
					},
				},
				[]string{"*"},
				map[string]map[string]interface{}{
					"Bool": {
						"kms:GrantIsForAWSResource": true,
					},
					"StringLike": {
						"kms:ViaService": []string{"ec2.*.amazonaws.com"},
					},
				},
			),
			iamdefinitions.NewStatement(
				"",
				iamdefinitions.EffectAllow,
				nil,
				[]iamdefinitions.ActionWithUseCase{
					{
						// Used to pass iam role to ec2 instance for cloud cluster ES.
						Permission: "iam:PassRole",
						UseCase: []string{
							"Used to pass iam role to ec2 instance for cloud cluster ES.",
						},
					},
				},
				[]string{"arn:*:iam::*:role/rubrik-cces-*"},
				map[string]map[string]interface{}{
					"StringEquals": {
						"iam:PassedToService": "ec2.amazonaws.com",
					},
				},
			),
			iamdefinitions.NewStatement(
				"",
				iamdefinitions.EffectAllow,
				nil,
				[]iamdefinitions.ActionWithUseCase{
					// nolint: lll
					{
						// Used to pass iam role to ec2 instance for exported VM. An input is
						// taken during the export VM operation where the customer can provide
						// the node instance profile which is then passed to the exported VM.
						// This permission is required for that. Since the input can be
						// anything that the customer provides, the resource has to be kept '*'.
						Permission: "iam:PassRole",
						UseCase: []string{
							"Use to allow the passing of the worker node role to EC2 worker nodes and the master node role to the EKS cluster.", // nolint: lll
						},
					},
				},
				[]string{
					ec2RecoveryPassRolePath,
				},
				map[string]map[string]interface{}{
					"StringEquals": {
						"iam:PassedToService": "ec2.amazonaws.com",
					},
				},
			),
			iamdefinitions.NewStatement(
				"",
				iamdefinitions.EffectAllow,
				nil,
				[]iamdefinitions.ActionWithUseCase{
					{
						Permission: "ec2:AttachVolume",
						UseCase: []string{
							"Restoring EC2 instances and attaching exported EBS volumes.",
							"Exporting crash-consistent snapshot of an EC2 instance.",
							"Exporting EBS volume and replacing it wherever attached.",
							"Attaching the temporary EBS volume to Amazon Elastic Kubernetes Service (EKS) cluster for indexing and storage tiering.", // nolint: lll
						},
					},
					{
						Permission: "ec2:CopyImage",
						UseCase: []string{
							"Cross-region export of EC2 instances.",
							"Cross-region replication of EC2 instance snapshots.",
						},
					},
					{
						Permission: "ec2:CopySnapshot",
						UseCase: []string{
							"Cross-region export and replication of EBS volumes.",
							"Cross-region export and replication of crash-consistent snapshots of EC2 instances.", // nolint: lll
						},
					},
					{
						Permission: "ec2:CreateImage",
						UseCase: []string{
							"Creating an image of an EC2 instance for backup.",
						},
					},
					{
						Permission: "ec2:CreateSnapshot",
						UseCase: []string{
							"Creating a snapshot of an EBS volume for backup.",
						},
					},
					{
						Permission: "ec2:CreateSnapshots",
						UseCase: []string{
							"Creating a crash-consistent snapshots of an EC2 instance.",
						},
					},
					{
						Permission: "ec2:CreateTags",
						UseCase: []string{
							"Assigning metadata tags to the created resources such as EBS volumes, EC2 instances, images, and snapshots.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeTags",
						UseCase: []string{
							"Backing up the tags attached to an EC2 instance during backup.",
							"Avoiding the tag limit while assigning tags to new resources.",
						},
					},
					{
						Permission: "ec2:CreateVolume",
						UseCase: []string{
							"Exporting EBS volumes.",
							"Restoring EC2 instances.",
							"Exporting crash-consistent snapshot of an EC2 instance.",
							"Creating temporary EBS volume to perform indexing for file search and recovery and storage tiering.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DeleteTags",
						UseCase: []string{
							"Overwriting existing tags when restoring tags in the EC2 instance restore job.", // nolint: lll
							"Deleting Rubrik metadata tags when the tag limit is exceeded.",
							"Deleting Garbage Collection (GC) tags when the GC task is no longer required for the resource.", // nolint: lll
						},
					},
					{
						Permission: "ec2:RegisterImage",
						UseCase:    []string{},
					},
					{
						Permission: "ec2:DeregisterImage",
						UseCase: []string{
							"Deleting the AMI associated with an expired backup.",
							"Deleting image in undo of the EC2 instance snapshot task.",
							"Deleting image after copying it to a new region during the cross-region export.", // nolint: lll
							"Deleting AMIs after a snapshot expiry.",
							"Deleting any temporary AMI created during replication and export.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeAvailabilityZones",
						UseCase: []string{
							"Retrieving the list of availability zones while exporting EBS volume and EC2 instance snapshots.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeImages",
						UseCase: []string{
							"Tracking the image creation status in the EC2 backup task.",
							"Retrieving image details for the recovery tasks.",
							"Periodically ensuring that the AMI associated with RSC backups is still available and not deleted by an external actor.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeInstances",
						UseCase: []string{
							"Retrieving the list of EC2 instances during the refresh task.",
							"Retrieving instance details during snapshot and recovery tasks.",
						},
					},
					{
						Permission: "ec2:DescribeKeyPairs",
						UseCase: []string{
							"Retrieving the list of SSH key pairs during the virtual machine recovery.",   // nolint: lll
							"Tracking the associated key pairs for EC2 instances when a backup is taken.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeSecurityGroups",
						// nolint: lll
						UseCase: []string{
							"Retrieving the list of security groups during the account refresh task.",
							"Retrieving the list of security groups while exporting EC2 instance snapshots.",
						},
					},
					{
						Permission: "ec2:DescribeSnapshots",
						// nolint: lll
						UseCase: []string{
							"Tracking the snapshot creation status during the EBS volume snapshot task.",
							"Retrieving snapshot details for the recovery tasks.",
							"Periodically ensuring that the snapshot associated with RSC backups is still available and not deleted by an external actor, for example, an user-initiated script.",
						},
					},
					{
						Permission: "ec2:DescribeSubnets",
						UseCase: []string{
							"Retrieving the list of subnets during the account refresh task.",
							"Retrieving the list of subnets while exporting EC2 instance snapshots.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeVolumes",
						UseCase: []string{
							"Retrieving the list of EBS Volumes during the refresh task.",
							"Retrieving volume details in various snapshot and recovery tasks.", // nolint: lll
						},
					},
					{
						Permission: "ec2:DescribeVpcs",
						UseCase: []string{
							"Retrieving the list of all Virtual Private Clouds (VPC) while exporting EC2 instance snapshots.", // nolint: lll
							"Retrieving the list of VPCs during the account refresh task.",
						},
					},
					{
						Permission: "ec2:DetachVolume",
						// nolint: lll
						UseCase: []string{
							"Detaching the existing volumes to replace them with recovered copies during the restore EC2 instance.",
							"Detaching an existing EBS volume when the Replace where attached option is selected at the time of exporting an EBS volume.",
							"Detaching the EBS volume from the temporary EKS cluster when the file search is enabled for an EC2 instance or EBS volume.",
						},
					},
					{
						Permission: "ec2:ModifyImageAttribute",
						// nolint: lll
						UseCase: []string{
							"Modifying the description of EC2 instance snapshots created by RSC.",
							"The image description is used for identifying all GC leaked images.",
						},
					},
					{
						Permission: "ec2:RunInstances",
						UseCase: []string{
							"Launching a virtual machine from a backup.",
						},
					},
					{
						Permission: "ec2:StartInstances",
						UseCase: []string{
							"Starting a virtual machine that was restored with new disks.",
						},
					},
					{
						Permission: "ec2:StopInstances",
						UseCase: []string{
							"Stopping an EC2 instance. When restoring a virtual machine, disks can only be replaced when the EC2 instance is stopped.", // nolint: lll
						},
					},
					// Needed to carry out disk migration for AWS clusters.
					{
						Permission: "ec2:ModifyVolume",
						UseCase: []string{
							"Modify Volume.",
						},
					},
					{
						Permission: "ec2:DescribeVolumes",
						UseCase: []string{
							"Describe Volume",
						},
					},
					{
						Permission: "ec2:DescribeVolumesModifications",
						UseCase: []string{
							"Describe Volumnes Modifications",
						},
					},
					{
						Permission: "kms:Decrypt",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					{
						Permission: "kms:DescribeKey",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					{
						Permission: "kms:Encrypt",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					{
						Permission: "kms:GenerateDataKey",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					{
						Permission: "kms:GenerateDataKeyWithoutPlaintext",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					{
						Permission: "kms:ListKeys",
						UseCase: []string{
							"Displaying Key Management Service (KMS) keys for the AWS account in a region.", // nolint: lll
						},
					},
					{
						Permission: "kms:ListAliases",
						UseCase: []string{
							"Displaying KMS aliases for the AWS account in a region.",
						},
					},
					{
						Permission: "kms:ReEncryptFrom",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					{
						Permission: "kms:ReEncryptTo",
						UseCase: []string{
							"Performing the custom CMK flow while exporting EC2 instance or EBS volume.", // nolint: lll
						},
					},
					// ec2:DescribeVolumeAttribute is used to
					// marketplace information of volume to be used to skip indexing of
					// marketplace volumes.
					{
						Permission: "ec2:DescribeVolumeAttribute",
						UseCase: []string{
							"Allowing RSC to identify EBS volumes launched from the AWS marketplace. You cannot perform file recovery and storage tiering for marketplace EBS volumes.", // nolint: lll
						},
					},
					// Required to be able to check if a EBS snapshot has marketplace
					// codes assigned or not.
					{
						Permission: "ec2:DescribeSnapshotAttribute",
						UseCase: []string{
							"Performing a check to determine if an EBS volume snapshot is from the AWS marketplace or not.", // nolint: lll
						},
					},
					// Required to share EBS snapshot with another AWS account
					{
						Permission: "ec2:ModifySnapshotAttribute",
						UseCase: []string{
							"Sharing EBS snapshots with other AWS accounts for cross-account replication.", // nolint: lll
						},
					},
					// Need to list buckets
					{
						Permission: "s3:ListAllMyBuckets",
						UseCase: []string{
							"It is used when listing S3 bucket endpoints.",
						},
					},
					// Needed to list bucket and check if it exists or not
					{
						Permission: "s3:ListBucket",
						UseCase: []string{
							"Listing bucket objects and checking if the bucket exists. It is used in the download job.", // nolint: lll
						},
					},
					// Needed for multi part upload
					{
						Permission: "s3:AbortMultipartUpload",
						UseCase: []string{
							"Performing the multipart upload. It is used in the file recovery job.", // nolint: lll
						},
					},
					// Needed to create a new bucket
					{
						Permission: "s3:CreateBucket",
						UseCase: []string{
							"Creating a bucket. It is used in the file recovery job.",
						},
					},
					// Needed to upload object
					{
						Permission: "s3:PutObject",
						UseCase: []string{
							"Uploading objects. It is used in the file recovery job.",
						},
					},
					// Needed to add tags to s3 objects
					{
						Permission: "s3:PutObjectTagging",
						UseCase: []string{
							"Adding tags to s3 objects",
						},
					},
					// Needed to add tags to s3 buckets
					{
						Permission: "s3:PutBucketTagging",
						UseCase: []string{
							"Adding tags to S3 buckets. It is used in the file recovery job.",
						},
					},
					// These are needed for cc-provision
					{
						Permission: "s3:GetBucketVersioning",
						UseCase: []string{
							"Get bucket versioning. It is used in cc-provision.",
						},
					},
					{
						Permission: "s3:GetBucketObjectLockConfiguration",
						UseCase: []string{
							"Get bucket object lock configuration. It is used in the file recovery job.", // nolint: lll
						},
					},
					// Used to check if default EBS encryption is enabled in customer's
					// account and region.
					{
						Permission: "ec2:GetEbsEncryptionByDefault",
						UseCase: []string{
							"Checking if EBS encryption by default is enabled in the AWS customer account and region.", // nolint: lll
						},
					},
					// Needed to create no connectivity security group for
					// exporting AWS VMs in powered off state feature.
					{
						Permission: "ec2:CreateSecurityGroup",
						UseCase: []string{
							"Creating a security group, without connectivity, for exporting AWS virtual machines that are powered off.", // nolint: lll
						},
					},
					// Needed to list iam profiles to attach to instances
					// for s3 bucket access.
					{
						Permission: "iam:ListInstanceProfiles",
						UseCase: []string{
							"Listing the IAM instance profiles for associating them with EC2 instances for s3 bucket access.", // nolint: lll
						},
					},
					// Needed to attach/update the iam instance profiles
					// during ec2 instance export.
					{
						Permission: "ec2:AssociateIamInstanceProfile",
						UseCase: []string{
							"Associating an IAM instance profile with an EC2 instance during EC2 export.", // nolint: lll
						},
					},
					{
						Permission: "ec2:ReplaceIamInstanceProfileAssociation",
						UseCase: []string{
							"Replacing an IAM instance profile for the EC2 instance during EC2 export.", // nolint: lll
						},
					},
				},
				[]string{
					"*",
				},
				nil,
			),
		},
		"2012-10-17",
	)
}
