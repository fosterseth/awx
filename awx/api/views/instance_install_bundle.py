# Copyright (c) 2018 Red Hat, Inc.
# All Rights Reserved.

import datetime
import io
import os
import tarfile
import tempfile

import asn1
from awx.api import serializers
from awx.api.generics import GenericAPIView, Response
from awx.api.permissions import IsSystemAdminOrAuditor
from awx.main import models
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import DNSName, IPAddress, ObjectIdentifier, OtherName
from cryptography.x509.oid import NameOID
from django.http import HttpResponse
from django.utils.translation import gettext_lazy as _
from rest_framework import status

# Red Hat has an OID namespace (RHANANA). Receptor has its own designation under that.
RECEPTOR_OID = "1.3.6.1.4.1.2312.19.1"

# generate install bundle for the instance
# install bundle directory structure
# ├── install_receptor.yml (playbook)
# ├── inventory.ini
# ├── receptor
# │   ├── vars.yml
# │   ├── tls
# │   │   ├── ca
# │   │   │   └── receptor-ca.crt
# │   │   ├── receptor.crt
# │   │   └── receptor.key
# │   └── work-public-key.pem
# └── requirements.yml
class InstanceInstallBundle(GenericAPIView):

    name = _('Install Bundle')
    model = models.Instance
    serializer_class = serializers.InstanceSerializer
    permission_classes = (IsSystemAdminOrAuditor,)

    def get(self, request, *args, **kwargs):
        instance_obj = self.get_object()

        # if the instance is not a hop or execution node than return 400
        if instance_obj.node_type not in ('execution', 'hop'):
            return Response(
                data=dict(msg=_('Install bundle can only be generated for execution or hop nodes.')),
                status=status.HTTP_400_BAD_REQUEST,
            )

        with tempfile.NamedTemporaryFile(suffix='.tar.gz') as tmpfile:
            with tarfile.open(tmpfile.name, 'w:gz') as tar:

                # copy /etc/receptor/tls/ca/receptor-ca.crt to receptor/tls/ca in the tar file
                tar.add(
                    os.path.realpath('/etc/receptor/tls/ca/receptor-ca.crt'), arcname=f"{instance_obj.hostname}_install_bundle/receptor/tls/ca/receptor-ca.crt"
                )

                # copy /etc/receptor/signing/work-public-key.pem to receptor/work-public-key.pem
                tar.add('/etc/receptor/signing/work-public-key.pem', arcname=f"{instance_obj.hostname}_install_bundle/receptor/work-public-key.pem")

                # generate and write the receptor key to receptor/tls/receptor.key in the tar file
                key, cert = self.generate_receptor_tls()

                key_tarinfo = tarfile.TarInfo(f"{instance_obj.hostname}_install_bundle/receptor/tls/receptor.key")
                key_tarinfo.size = len(key)
                tar.addfile(key_tarinfo, io.BytesIO(key))

                cert_tarinfo = tarfile.TarInfo(f"{instance_obj.hostname}_install_bundle/receptor/tls/receptor.crt")
                cert_tarinfo.size = len(cert)
                tar.addfile(cert_tarinfo, io.BytesIO(cert))

            # read the temporary file and send it to the client
            with open(tmpfile.name, 'rb') as f:
                response = HttpResponse(f.read(), status=status.HTTP_200_OK)
                response['Content-Disposition'] = f"attachment; filename={instance_obj.hostname}_install_bundle.tar.gz"
                return response

    def generate_receptor_tls(self):
        instance_obj = self.get_object()

        # generate private key for the receptor
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # encode receptor hostname to asn1
        hostname = instance_obj.hostname
        encoder = asn1.Encoder()
        encoder.start()
        encoder.write(hostname.encode(), nr=asn1.Numbers.UTF8String)
        hostname_asn1 = encoder.output()

        # generate certificate for the receptor
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName([DNSName(hostname), OtherName(ObjectIdentifier(RECEPTOR_OID), hostname_asn1)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # sign csr with the receptor ca key from /etc/receptor/ca/receptor-ca.key
        with open('/etc/receptor/tls/ca/receptor-ca.key', 'rb') as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        with open('/etc/receptor/tls/ca/receptor-ca.crt', 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.issuer)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
            .add_extension(
                x509.SubjectAlternativeName([DNSName(hostname), OtherName(ObjectIdentifier(RECEPTOR_OID), hostname_asn1)]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert = cert.public_bytes(
            encoding=serialization.Encoding.PEM,
        )

        return key, cert
