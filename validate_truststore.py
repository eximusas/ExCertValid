'''
validate_truststore.py

Script para diagnosticar problemas de PKIX Path Building contra un servicio HTTPS:
 1. Localiza el `cacerts` del JDK usado por Tomcat.
 2. Lista los aliases presentes en el truststore (JKS o PKCS12).
 3. Verifica que estén los certificados esperados (por alias o subject).
 4. Permite comprobar si archivos de certificados externos (.cer/.pem) están importados.
 5. Extrae el truststore a PEM y prueba un handshake SSL contra el host remoto.

Requisitos:
  pip install pyjks cryptography

Uso:
  python validate_truststore.py \
    --jdk "C:\Install_BT\openlogic-openjdk-17.0.13+11-windows-x64" \
    --storepass changeit \
    --expected "nosis,sectigo,usertrust" \
    --certfiles "nosis.cer,sectigo.cer,usertrust.cer" \
    --host sac.nosis.com \
    --port 443
'''
import os
import sys
import ssl
import socket
import tempfile
import argparse
import hashlib

try:
    import jks
    from jks.util import DecryptionFailureException, BadKeystoreFormatException
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Faltan dependencias: pip install pyjks cryptography")
    sys.exit(1)


def find_cacerts(jdk_home):
    candidates = [
        os.path.join(jdk_home, 'lib', 'security', 'jssecacerts'),
        os.path.join(jdk_home, 'lib', 'security', 'cacerts'),
        os.path.join(jdk_home, 'jre', 'lib', 'security', 'jssecacerts'),
        os.path.join(jdk_home, 'jre', 'lib', 'security', 'cacerts'),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def load_keystore(cacerts_path, password):
    data = open(cacerts_path, 'rb').read()
    try:
        return jks.KeyStore.loads(data, password)
    except DecryptionFailureException:
        print(f"ERROR: Contraseña incorrecta para {cacerts_path}")
        sys.exit(1)
    except BadKeystoreFormatException:
        try:
            return jks.PKCS12KeyStore.loads(data, password)
        except Exception as ex:
            print(f"ERROR: No es un keystore JKS o PKCS12 válido: {ex}")
            sys.exit(1)


def list_aliases(ks):
    if hasattr(ks, 'certs'):
        return list(ks.certs.keys())
    # PKCS12KeyStore may use .entries
    return [e.alias for e in getattr(ks, 'entries', [])]


def extract_truststore_pem(ks, password):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
    if hasattr(ks, 'certs'):
        entries = ks.certs.values()
    else:
        entries = [e.cert for e in ks.certs.values()] if hasattr(ks, 'certs') else []
    for entry in entries:
        cert = x509.load_der_x509_certificate(entry.cert if hasattr(entry, 'cert') else entry, default_backend())
        tmp.write(cert.public_bytes(Encoding.PEM))
    tmp.close()
    return tmp.name


def compute_fingerprint(cert_path):
    data = open(cert_path, 'rb').read()
    # soporta DER (.cer) o PEM
    try:
        cert = x509.load_pem_x509_certificate(data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(data, default_backend())
    der = cert.public_bytes(Encoding.DER)
    sha256 = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(sha256[i:i+2] for i in range(0, len(sha256), 2)), cert.subject.rfc4514_string()


def test_ssl_connection(host, port, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        print(f"✅ SSL handshake OK contra {host}:{port}")
        return True
    except Exception as e:
        print(f"❌ ERROR SSL handshake: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Diagnóstico de PKIX con cacerts de Java.")
    parser.add_argument('--jdk',        required=True, help='Directorio JAVA_HOME')
    parser.add_argument('--storepass',  default='changeit', help='Password del cacerts')
    parser.add_argument('--expected',   help='Aliases esperados en cacerts (coma-separados)')
    parser.add_argument('--certfiles',  help='Archivos de certificados externos (.cer/.pem)')
    parser.add_argument('--host',       help='Host remoto a probar SSL')
    parser.add_argument('--port',       type=int, default=443, help='Puerto remoto SSL')
    args = parser.parse_args()

    # 1) Encontrar cacerts
    cacerts_path = find_cacerts(args.jdk)
    if not cacerts_path:
        print(f"ERROR: No se encontró cacerts/jssecacerts en {args.jdk}")
        sys.exit(1)
    print(f"Usando truststore: {cacerts_path}\n")

    # 2) Cargar keystore
    ks = load_keystore(cacerts_path, args.storepass)

    # 3) Listar aliases
    aliases = list_aliases(ks)
    print(f"Aliases en cacerts ({len(aliases)}):")
    for a in aliases:
        print(f"  - {a}")

    # 4) Verificar aliases esperados
    if args.expected:
        missing = [e for e in args.expected.split(',') if e not in aliases]
        if missing:
            print(f"\n⚠️  Faltan estos alias en cacerts: {', '.join(missing)}")
        else:
            print(f"\n✅ Todos los alias esperados están presentes.")

    # 5) Verificar archivos de certificados externos
    if args.certfiles:
        print("\nValidando archivos de certificados externos:")
        for path in args.certfiles.split(','):
            path = path.strip()
            if not os.path.isfile(path):
                print(f"ERROR: No existe el certificado {path}")
                continue
            fp, subj = compute_fingerprint(path)
            found = False
            for alias in aliases:
                # obtener huella de cada alias
                entry = ks.certs.get(alias) if hasattr(ks, 'certs') else None
                der = entry.cert if entry else None
                if der:
                    cert = x509.load_der_x509_certificate(der, default_backend())
                    der_fp = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest().upper()
                    der_fp_formatted = ':'.join(der_fp[i:i+2] for i in range(0, len(der_fp), 2))
                    if der_fp_formatted == fp:
                        found = True
                        break
            print(f"  {path}: {'✅ importado' if found else '❌ no encontrado'} (Subject: {subj})")

    # 6) Probar handshake SSL
    if args.host:
        pem = extract_truststore_pem(ks, args.storepass)
        try:
            test_ssl_connection(args.host, args.port, cafile=pem)
        finally:
            os.unlink(pem)

if __name__ == '__main__':
    main()
