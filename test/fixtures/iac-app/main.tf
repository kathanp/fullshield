resource "aws_s3_bucket_acl" "b" {
  acl = "public-read"
}
resource "aws_security_group_rule" "db" {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 5432
  to_port     = 5432
}
resource "aws_ebs_volume" "data" {
  encrypted = false
}
