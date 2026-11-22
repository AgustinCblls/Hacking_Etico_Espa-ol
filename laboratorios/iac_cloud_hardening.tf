# Plantilla educativa Terraform (IaC) para auditar configuraciones Cloud seguras (Tomo V: Cap. 5.1, 5.2, 5.5)
# Uso didáctico con herramientas estáticas como `trivy config` o `checkov` (sin necesidad de credenciales reales).

resource "aws_s3_bucket" "evidencia_forense_lab" {
  bucket = "lab-evidencia-ejemplo-001"
}

resource "aws_s3_bucket_public_access_block" "bloqueo_publico" {
  bucket                  = aws_s3_bucket.evidencia_forense_lab.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cifrado_sse" {
  bucket = aws_s3_bucket.evidencia_forense_lab.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Ejemplo de instancia EC2 exigiendo IMDSv2 (mitiga SSRF hacia credenciales de rol en 169.254.169.254)
resource "aws_instance" "nodo_lab_endurecido" {
  ami           = "ami-00000000000000000"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Exige token de sesión IMDSv2
    http_put_response_hop_limit = 1          # Evita salto desde contenedores
  }

  root_block_device {
    encrypted = true
  }
}
