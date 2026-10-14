resource "aws_s3_bucket" "b" {
  bucket = "private-example"
}
resource "aws_security_group_rule" "db" {
  cidr_blocks = ["10.0.0.0/8"]
  from_port   = 5432
  to_port     = 5432
}
resource "aws_ebs_volume" "data" {
  encrypted = true
}
