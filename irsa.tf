# Enable IAM Roles for EKS Service-Accounts (IRSA).

# The Root CA Thumbprint for an OpenID Connect Identity Provider is currently
# Being passed as a default value which is the same for all regions and
# Is valid until (Jun 28 17:39:16 2034 GMT).
# https://crt.sh/?q=9E99A48A9960B14926BB7F3B02E22DA2B0AB7280
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html
# https://github.com/terraform-providers/terraform-provider-aws/issues/10104

resource "aws_iam_openid_connect_provider" "oidc_provider" {
  count           = var.enable_irsa ? 1 : 0
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [var.eks_oidc_root_ca_thumbprint]
  url             = flatten(concat(aws_eks_cluster.this[*].identity[*].oidc.0.issuer, [""]))[0]
}

data "aws_iam_policy_document" "irsa_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.oidc_provider.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.oidc_provider.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "irsa_example" {
  assume_role_policy = data.aws_iam_policy_document.irsa_assume_role_policy.json
  name               = "irsa-example"
  path               = var.iam_path
}
