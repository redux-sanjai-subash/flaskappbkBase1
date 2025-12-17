import ssl
import socket
import OpenSSL
from datetime import datetime

def fetch_ssl_details(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert_bin = s.getpeercert(True)
            cert = ssl.DER_cert_to_PEM_cert(cert_bin)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            # Expiry date
            expiry_str = x509.get_notAfter().decode("ascii")
            expiry_date = datetime.strptime(expiry_str, "%Y%m%d%H%M%SZ")

            # Provider
            issuer = x509.get_issuer()
            provider = None
            for name, value in issuer.get_components():
                if name.decode("utf-8").lower() in ["o", "organizationname"]:
                    provider = value.decode("utf-8")
                    break

            return {"provider": provider, "expiry": expiry_date}
    except Exception as e:
        print(f"[SSL fetch failed] {domain}: {e}")
        return None

